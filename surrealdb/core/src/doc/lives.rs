use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use async_channel::Sender;
use chrono::Utc;
use futures::future::try_join_all;
use reblessive::TreeStack;
use reblessive::tree::Stk;

use super::IgnoreError;
use crate::catalog::{Permission, SubscriptionDefinition, SubscriptionFields};
use crate::ctx::{Context, FrozenContext};
use crate::dbs::{MessageBroker, Options, RoutedNotification};
use crate::doc::{Action, CursorDoc, Document};
use crate::err::Error;
use crate::expr::FlowResultExt as _;
use crate::expr::paths::{AC, ID, RD, TK};
use crate::kvs::Transaction;
use crate::types::{PublicAction, PublicNotification, PublicValue};
use crate::val::{Number, Value, convert_value_to_public_value};

impl Document {
	/// Processes any LIVE SELECT statements which
	/// have been defined for the table which this
	/// record belongs to. This functions loops
	/// through the live queries and processes them
	/// all within the currently running transaction.
	pub(super) async fn process_table_lives(
		&mut self,
		_stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		action: Action,
	) -> Result<()> {
		// Check import
		if opt.import {
			return Ok(());
		}

		// Check if we can send notifications
		if ctx.broker().is_none() {
			// no sender, so nothing to do.
			return Ok(());
		};

		// Check if changed
		if !self.changed() {
			return Ok(());
		}

		// Get all live queries for this table
		let live_subscriptions = self.lv(ctx, opt).await?;

		// If there are no live queries, we can skip the rest of the function
		if live_subscriptions.is_empty() {
			return Ok(());
		}

		// Get the event action
		let (met, is_delete): (Arc<Value>, _) = if matches!(action, Action::Delete) {
			(Value::from("DELETE").into(), true)
		} else if matches!(action, Action::Create) || self.is_new() {
			(Value::from("CREATE").into(), false)
		} else {
			(Value::from("UPDATE").into(), false)
		};

		// Get the current and initial docs
		// These are only used for EVENTS, so they should not be reduced
		let initial = self.initial.doc.as_arc();
		let current = self.current.doc.as_arc();

		// Move self to a shared reference
		let doc: &Self = &*self;

		let mut tasks = Vec::with_capacity(live_subscriptions.len());
		// Loop through all index statements
		for live_subscription in live_subscriptions.iter() {
			// We need to create a new options which we will
			// use for processing this LIVE query statement.
			// This ensures that we are using the auth data
			// of the user who created the LIVE query.
			let lqopt = opt.new_with_perms(true);
			let (met, current, initial) =
				(Arc::clone(&met), Arc::clone(&current), Arc::clone(&initial));
			tasks.push(async move {
				let mut stack = TreeStack::new();
				stack
					.enter(|stk| {
						doc.lq_compute(
							stk,
							ctx,
							live_subscription.clone(),
							lqopt,
							ctx.tx(),
							(met, initial, current),
							is_delete,
						)
					})
					.finish()
					.await
			});
		}
		// Run the tasks concurrently
		try_join_all(tasks).await?;
		// Carry on
		Ok(())
	}

	#[allow(clippy::too_many_arguments)]
	async fn lq_compute(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		live_subscription: SubscriptionDefinition,
		opt: Options,
		tx: Arc<Transaction>,
		(met, initial, current): (Arc<Value>, Arc<Value>, Arc<Value>),
		is_delete: bool,
	) -> Result<()> {
		// Ensure that a session exists on the LIVE query
		let sess = match live_subscription.session.as_ref() {
			Some(v) => v,
			None => return Ok(()),
		};
		// Skip notification if the session that created this LIVE query has expired.
		// session["exp"] is a unix timestamp (i64) set by DURATION FOR SESSION; absent means no
		// expiry. This mirrors the per-request check in Datastore::execute without requiring the
		// originating Session object to remain in memory beyond the RPC connection lifetime.
		if let Value::Object(ref session_obj) = *sess
			&& let Some(Value::Number(Number::Int(exp))) = session_obj.get("exp")
			&& Utc::now().timestamp() > *exp
		{
			return Ok(());
		}
		// Ensure that auth info exists on the LIVE query
		let auth = match live_subscription.auth.clone() {
			Some(v) => v,
			None => return Ok(()),
		};
		let opt = opt.with_auth(auth.into());

		let Some(sender) = ctx.broker() else {
			return Ok(());
		};

		// Get the record id of this document
		let rid = self
			.id
			.clone()
			.ok_or_else(|| {
				Error::unreachable("Processing live query for record without a Record ID")
			})
			.map_err(anyhow::Error::new)?;

		// We need to create a new context which we will
		// use for processing this LIVE query statement.
		// This ensures that we are using the session
		// of the user who created the LIVE query.
		let mut ctx = Context::background(ctx);
		// Set the current transaction on the new LIVE
		// query context to prevent unreachable behaviour
		// and ensure that queries can be executed.
		ctx.set_transaction(tx);
		// Captured user variables first; trusted LIVE / session params last so
		// a user-named `$value` / `$before` / `$after` / `$event` cannot shadow
		// the real document context that table permission expressions read.
		ctx.add_values(live_subscription.vars.clone());
		ctx.add_value("access", sess.pick(AC.as_ref()).into());
		ctx.add_value("auth", sess.pick(RD.as_ref()).into());
		ctx.add_value("token", sess.pick(TK.as_ref()).into());
		ctx.add_value("session", sess.clone().into());
		ctx.add_value("event", met);
		ctx.add_value("value", Arc::clone(&current));
		ctx.add_value("after", current);
		ctx.add_value("before", initial);
		// Freeze the context
		let ctx = ctx.freeze();

		// Extract the session ID now so it is available for both the normal notification
		// path and any early-return error notification path below.
		let session_id = match sess.pick(ID.as_ref()) {
			Value::Uuid(uuid) => Some(uuid.into()),
			Value::String(s) => s.parse::<crate::val::Uuid>().ok().map(|uuid| uuid.into()),
			_ => None,
		};

		// Get the document to check against and to return based on lq context
		// We need to clone the document as we will potentially modify it with computed fields
		// The outcome for every computed field can be different based on the context of the
		// user. Both compute_reduced_target and computed_fields_inner run under the LIVE
		// owner's auth, which may differ from the writer's; any evaluation error skips this
		// notification rather than aborting the triggering write transaction.
		//
		// Store the reduction flag so the DIFF arm can reuse it without a second call.
		let reduction_required = self.check_reduction_required(&ctx, &opt)?;
		let mut doc = if reduction_required {
			let target = if is_delete {
				&self.initial
			} else {
				&self.current
			};
			match self.compute_reduced_target(stk, &ctx, &opt, target).await {
				Ok(d) => d,
				Err(_) => return Ok(()),
			}
		} else if is_delete {
			self.initial.clone()
		} else {
			self.current.clone()
		};

		if let Ok(rid) = self.id() {
			let fields = match self.fd(&ctx, &opt).await {
				Ok(f) => f,
				Err(_) => return Ok(()),
			};
			if Document::computed_fields_inner(
				stk,
				&ctx,
				&opt,
				&rid,
				fields.as_ref(),
				&mut doc,
				None,
			)
			.await
			.is_err()
			{
				return Ok(());
			}
			// SECURITY: `compute_reduced_target` runs before computed
			// fields are populated, so it can't filter them; apply the
			// computed-field `FOR select` permissions now so a subscriber
			// without permission to read a computed field never receives
			// its value in the LIVE notification.
			if self
				.filter_computed_field_permissions(stk, &ctx, &opt, fields.as_ref(), &mut doc)
				.await
				.is_err()
			{
				return Ok(());
			}
		};

		// First of all, let's check to see if the WHERE
		// clause of the LIVE query is matched by this
		// document. If it is then we can continue.
		let lq_check_result = match self.lq_check(stk, &ctx, &opt, &live_subscription, &doc).await {
			Err(IgnoreError::Ignore) => return Ok(()),
			Err(IgnoreError::Error(e)) => Err(e),
			Ok(_) => Ok(()),
		};
		// Secondly, let's check to see if any PERMISSIONS
		// clause for this table allows this document to
		// be viewed by the user who created this LIVE
		// query. If it does, then we can continue.
		match self.lq_allow(stk, &ctx, &opt, is_delete).await {
			Err(IgnoreError::Ignore) => return Ok(()),
			Err(IgnoreError::Error(e)) => return Err(e),
			Ok(_) => (),
		}
		if !sender.should_emit(*ctx.node_id().as_bytes(), *live_subscription.node.as_bytes())? {
			return Ok(());
		}
		if let Err(e) = lq_check_result {
			// The WHERE clause raised an evaluation error (e.g. InvalidFunctionArguments,
			// THROW). Surface it to the subscriber as an Action::Error notification so
			// they can diagnose the broken query rather than silently receiving nothing.
			// We still return Ok(()) to avoid aborting the triggering write transaction.
			if let Ok(rid_public) =
				convert_value_to_public_value(Value::RecordId(rid.as_ref().clone()))
			{
				sender
					.send(RoutedNotification::new(
						live_subscription.node,
						PublicNotification::new(
							live_subscription.id.into(),
							session_id,
							PublicAction::Error,
							rid_public,
							PublicValue::String(e.to_string()),
						),
					))
					.await;
			}
			return Ok(());
		}
		// Let's check what type of statement
		// caused this LIVE query to run, and obtain
		// the relevant result.
		let (action, mut result) = match live_subscription.fields {
			SubscriptionFields::Diff => {
				// DIFF mode: return JSON patch operations instead of full document
				if is_delete {
					// For DELETE: compute diff from initial document to empty object
					let operations = self.initial.doc.as_ref().diff(&Value::None);
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Delete, result)
				} else if self.is_new() {
					// For CREATE: compute diff from empty object to current document
					let operations = Value::None.diff(doc.doc.as_ref());
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Create, result)
				} else {
					// For UPDATE: mirror the same preparation that was applied to `doc`
					// (the RHS). First reduce under the LIVE owner's auth so restricted
					// fields cancel out on both sides (no spurious Remove ops). Then run
					// computed_fields_inner so COMPUTED fields are populated on the LHS
					// too (no spurious Add/Replace ops for fields defined as COMPUTED).
					let mut reduced_initial = if reduction_required {
						match self.compute_reduced_target(stk, &ctx, &opt, &self.initial).await {
							Ok(d) => d,
							Err(_) => return Ok(()),
						}
					} else {
						self.initial.clone()
					};
					if let Ok(rid) = self.id() {
						let Ok(fields) = self.fd(&ctx, &opt).await else {
							return Ok(());
						};
						if Document::computed_fields_inner(
							stk,
							&ctx,
							&opt,
							&rid,
							fields.as_ref(),
							&mut reduced_initial,
							None,
						)
						.await
						.is_err()
						{
							return Ok(());
						}
						// SECURITY: filter computed-field permissions on the
						// LHS of the DIFF so the subscriber doesn't receive
						// patch ops revealing denied computed values.
						if self
							.filter_computed_field_permissions(
								stk,
								&ctx,
								&opt,
								fields.as_ref(),
								&mut reduced_initial,
							)
							.await
							.is_err()
						{
							return Ok(());
						}
					}
					let operations = reduced_initial.doc.as_ref().diff(doc.doc.as_ref());
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Update, result)
				}
			}
			SubscriptionFields::Select(x) => {
				// Evaluate the projection. Any error (type mismatch, THROW, BREAK, CONTINUE,
				// closure result, etc.) skips this notification without aborting the write.
				let Ok(result) = x.compute(stk, &ctx, &opt, Some(&doc)).await else {
					return Ok(());
				};
				if is_delete {
					(PublicAction::Delete, result)
				} else if self.is_new() {
					(PublicAction::Create, result)
				} else {
					(PublicAction::Update, result)
				}
			}
		};

		// Process any potential `FETCH` clause on the live statement.
		// Any evaluation error (invalid function arguments, unsupported expressions, etc.)
		// skips this notification rather than aborting the triggering write transaction.
		if let Some(fetchs) = live_subscription.fetch {
			let mut idioms = BTreeSet::new();
			for fetch in fetchs.iter() {
				if fetch.compute(stk, &ctx, &opt, &mut idioms).await.is_err() {
					return Ok(());
				}
			}
			for i in &idioms {
				if stk.run(|stk| result.fetch(stk, &ctx, &opt, i)).await.is_err() {
					return Ok(());
				}
			}
		}

		// Convert values to the public wire format. Any conversion error (e.g. a
		// closure-valued projection that cannot be serialised) skips this notification
		// rather than aborting the triggering write transaction.
		let (Ok(rid_public), Ok(result_public)) = (
			convert_value_to_public_value(Value::RecordId(rid.as_ref().clone())),
			convert_value_to_public_value(result),
		) else {
			return Ok(());
		};
		let notification = PublicNotification::new(
			live_subscription.id.into(),
			session_id,
			action,
			rid_public,
			result_public,
		);

		// Send the notification
		sender.send(RoutedNotification::new(live_subscription.node, notification)).await;

		Ok(())
	}

	/// Check the WHERE clause for a LIVE query.
	///
	/// Returns:
	/// - `Ok(())` — the WHERE clause matched (or there is no WHERE clause).
	/// - `Err(IgnoreError::Ignore)` — the WHERE clause evaluated to a non-truthy value; skip this
	///   notification silently.
	/// - `Err(IgnoreError::Error(e))` — the WHERE clause raised an evaluation error (e.g.
	///   `InvalidFunctionArguments`, `THROW`). The caller should send an `Action::Error`
	///   notification to the subscriber instead of silently discarding the event.
	async fn lq_check(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		live_subscription: &SubscriptionDefinition,
		doc: &CursorDoc,
	) -> Result<(), IgnoreError> {
		// Check where condition
		if let Some(cond) = live_subscription.cond.as_ref() {
			// Evaluate the WHERE expression. Control-flow signals (RETURN, BREAK,
			// CONTINUE) are normalised by `catch_return` into either a value or an
			// `InvalidControlFlow` error. All other errors are propagated so the
			// caller can surface them to the subscriber via an Action::Error
			// notification rather than silently dropping the event. Neither path
			// can abort the write transaction — the caller always returns Ok(()).
			match stk.run(|stk| cond.compute(stk, ctx, opt, Some(doc))).await.catch_return() {
				Ok(v) if !v.is_truthy() => return Err(IgnoreError::Ignore),
				Err(e) => return Err(IgnoreError::Error(e)),
				Ok(_) => {}
			}
		}
		// Carry on
		Ok(())
	}
	/// Check any PERRMISSIONS for a LIVE query
	async fn lq_allow(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		is_delete: bool,
	) -> Result<(), IgnoreError> {
		// Should we run permissions checks?
		// Live queries are always
		if ctx.check_perms(opt, crate::iam::Action::View)? {
			// Get the table
			let tb = self.tb().await?;
			// Process the table permissions
			match &tb.permissions.select {
				Permission::None => return Err(IgnoreError::Ignore),
				Permission::Full => return Ok(()),
				Permission::Specific(e) => {
					// Retrieve the document to check permissions against.
					// For DELETE events, we need self.initial as self.current has been cleared.
					let doc = if is_delete {
						&self.initial
					} else {
						&self.current
					};

					// Disable permissions
					let opt = &opt.new_with_perms(false);
					// Process the PERMISSION clause
					if !stk
						.run(|stk| e.compute(stk, ctx, opt, Some(doc)))
						.await
						.catch_return()
						.is_ok_and(|x| x.is_truthy())
					{
						return Err(IgnoreError::Ignore);
					}
				}
			}
		}
		// Carry on
		Ok(())
	}
}

#[derive(Clone, Debug)]
pub(crate) struct DefaultBroker {
	sender: Sender<RoutedNotification>,
	delivery: Arc<dyn MessageBroker>,
}

impl DefaultBroker {
	pub(crate) fn new(
		sender: Sender<RoutedNotification>,
		delivery: Arc<dyn MessageBroker>,
	) -> Arc<Self> {
		Arc::new(Self {
			sender,
			delivery,
		})
	}
}
impl MessageBroker for DefaultBroker {
	fn should_emit(&self, node_id: [u8; 16], target_node: [u8; 16]) -> Result<bool> {
		self.delivery.should_emit(node_id, target_node)
	}

	fn send(&self, item: RoutedNotification) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
		Box::pin(async move {
			// If there is an error, we can just ignore it,
			// as it means that the channel was closed.
			let _ = self.sender.send(item).await;
		})
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use anyhow::Result;
	use chrono::Utc;

	use crate::catalog::providers::CatalogProvider;
	use crate::channel::Receiver;
	use crate::dbs::{Capabilities, Session};
	use crate::kvs::Datastore;
	use crate::kvs::LockType::Optimistic;
	use crate::kvs::TransactionType::Write;
	use crate::types::{
		PublicAction, PublicNotification, PublicRecordId, PublicRecordIdKey, PublicValue,
	};

	async fn new_ds_with_broker() -> Result<(Receiver<PublicNotification>, Datastore)> {
		let (send, recv) = crate::channel::bounded(1000);
		let ds = Datastore::builder()
			.with_capabilities(Capabilities::all())
			.with_auth(false)
			.with_notify(send)
			.build_with_path("memory")
			.await?;
		Ok((recv, ds))
	}

	async fn setup_ns_db_table(ds: &Datastore, ns: &str, db: &str, tb: &str) {
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();
		let ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(&format!("DEFINE TABLE {tb}"), &ses, None).await.unwrap();
	}

	/// A LIVE query with a constant WHERE clause that always throws
	/// `InvalidFunctionArguments` (here: `string::len(NONE)`) must be rejected at
	/// registration time. The expression is document-independent (no field refs, no
	/// doc params), so we can evaluate it eagerly and surface the error immediately.
	#[tokio::test]
	async fn test_live_where_constant_error_rejected_at_registration() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);

		let mut res = ds
			.execute("LIVE SELECT * FROM person WHERE string::len(NONE)", &ses, None)
			.await
			.unwrap();
		let err = res.remove(0).result;
		assert!(
			err.is_err(),
			"LIVE query with a constant invalid WHERE clause should be rejected at registration"
		);
	}

	/// A LIVE query whose WHERE clause depends on a document field (`name`) and
	/// always throws `InvalidFunctionArguments` (when `name` is not a string) must
	/// not abort subsequent CREATE statements on the same table. The error is
	/// surfaced as an `Action::Error` notification instead.
	#[tokio::test]
	async fn test_live_where_doc_dependent_error_does_not_abort_create() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);

		// `string::len(name)` is document-dependent (references field `name`), so it
		// passes the constant-expression check. When `name` is NONE or a non-string
		// the function throws, which should surface as an error notification rather
		// than aborting the write.
		ds.execute("LIVE SELECT * FROM person WHERE string::len(name) > 3", &ses, None)
			.await
			.unwrap();

		// CREATE must succeed despite the erroring WHERE-clause subscription.
		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:1", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed, not be aborted by LIVE WHERE error");

		// Notifications are forwarded asynchronously; wait briefly for the error one.
		let notification =
			tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
				.await
				.expect("expected an error notification within timeout")
				.expect("channel should not be closed");
		assert_eq!(
			notification.action,
			crate::types::PublicAction::Error,
			"expected Action::Error, got {:?}",
			notification.action
		);
	}

	/// Defense-in-depth: a LIVE query whose SELECT projection always throws
	/// `InvalidFunctionArguments` must not abort subsequent writes on the table.
	#[tokio::test]
	async fn test_live_projection_type_error_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);

		// Register a LIVE query whose SELECT projection always errors.
		ds.execute("LIVE SELECT string::len(NONE) FROM person", &ses, None).await.unwrap();

		// CREATE must succeed despite the erroring projection.
		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:2", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0)
			.result
			.expect("CREATE should succeed, not be aborted by LIVE projection error");
	}

	/// Multiple LIVE queries with document-dependent erroring WHERE clauses on the
	/// same table must not prevent any of CREATE, UPDATE, or DELETE from succeeding.
	/// Each failing evaluation fires an Action::Error notification instead.
	#[tokio::test]
	async fn test_multiple_erroring_live_queries_do_not_abort_writes() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);

		// Register doc-dependent subscriptions that will error when evaluated against
		// a record without a matching string field.
		ds.execute("LIVE SELECT * FROM person WHERE string::len(name) > 3", &ses, None)
			.await
			.unwrap();
		ds.execute("LIVE SELECT * FROM person WHERE string::uppercase(name) = 'ALICE'", &ses, None)
			.await
			.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);

		let mut res =
			ds.execute("CREATE person:3", &ses_write, None).await.expect("execute should not Err");
		res.remove(0).result.expect("CREATE should succeed");

		let mut res = ds
			.execute("UPDATE person:3 SET name = 'Alice'", &ses_write, None)
			.await
			.expect("execute should not Err");
		res.remove(0).result.expect("UPDATE should succeed");

		let mut res =
			ds.execute("DELETE person:3", &ses_write, None).await.expect("execute should not Err");
		res.remove(0).result.expect("DELETE should succeed");
	}

	/// A LIVE query with a constant `THROW` WHERE clause must be rejected at
	/// registration (the expression is document-independent).
	#[tokio::test]
	async fn test_live_where_constant_throw_rejected_at_registration() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		let mut res = ds
			.execute(r#"LIVE SELECT * FROM person WHERE THROW "abort""#, &ses, None)
			.await
			.unwrap();
		assert!(
			res.remove(0).result.is_err(),
			"constant THROW in WHERE should be rejected at registration"
		);
	}

	/// A LIVE query whose document-dependent WHERE clause uses THROW must not abort
	/// subsequent writes. The error is surfaced as an Action::Error notification.
	/// `THROW` produces `Error::Thrown`, which is not in the old `is_ignorable()` allowlist.
	#[tokio::test]
	async fn test_live_where_doc_dependent_throw_does_not_abort_create() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		// `THROW name` is document-dependent (references field `name`), so it passes
		// the constant-expression check at registration.
		ds.execute(r#"LIVE SELECT * FROM person WHERE THROW name"#, &ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:10", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed despite THROW in LIVE WHERE");

		// Notifications are forwarded asynchronously; wait briefly for the error one.
		let notification =
			tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
				.await
				.expect("expected an error notification within timeout")
				.expect("channel should not be closed");
		assert_eq!(
			notification.action,
			crate::types::PublicAction::Error,
			"expected Action::Error for THROW in LIVE WHERE"
		);
	}

	/// A LIVE query whose SELECT projection uses THROW must not abort subsequent writes.
	#[tokio::test]
	async fn test_live_projection_throw_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute(r#"LIVE SELECT THROW "abort" FROM person"#, &ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:11", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed despite THROW in LIVE SELECT");
	}

	/// A user-named `$value` / `$before` / `$after` / `$event` captured at LIVE registration
	/// time must not override the real document context when the WHERE clause is evaluated
	/// at notification time. Without the reorder fix the captured `$value` would shadow the
	/// real document, letting a subscriber pass table permission expressions like
	/// `WHERE $value.ok = true` against an attacker-chosen document instead of the live one.
	#[tokio::test]
	async fn test_live_user_value_does_not_shadow_real_document() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		// Capture a user `$value` claiming `ok = true`, then register a LIVE query whose
		// WHERE references `$value.ok`. The capture pass picks `$value` up because it is
		// not in PROTECTED_PARAM_NAMES.
		ds.execute(
			"LET $value = { ok: true }; LIVE SELECT * FROM person WHERE $value.ok = true",
			&ses,
			None,
		)
		.await
		.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:42 SET ok = false", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed");

		// With the fix the system `$value` (the real document, ok=false) wins, so the
		// WHERE clause is false and no notification fires. Wait briefly to be sure.
		let result =
			tokio::time::timeout(tokio::time::Duration::from_millis(300), recv.recv()).await;
		assert!(
			result.is_err(),
			"no notification should fire when the real document does not match the WHERE"
		);
	}

	/// A LIVE query with a FETCH clause that always errors must not abort subsequent writes.
	/// `type::field(NONE)` triggers `InvalidFunctionArguments` in the FETCH path, which was
	/// previously unprotected (raw `?` propagation).
	#[tokio::test]
	async fn test_live_fetch_error_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute("LIVE SELECT * FROM person FETCH type::field(NONE)", &ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:12", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0).result.expect("CREATE should succeed despite invalid FETCH expression");
	}

	/// A LIVE query registered by a record-access session whose per-field SELECT permission
	/// expression always errors must not abort subsequent writes. `compute_reduced_target`
	/// runs under the LIVE owner's auth and can fail even when the writer's evaluation
	/// succeeds; the error must skip the notification rather than rolling back the
	/// triggering write transaction.
	///
	/// The LIVE subscriber must be a non-root session (here: a record-access user) so that
	/// `check_reduction_required` returns true and `compute_reduced_target` is actually
	/// called. A root/owner session bypasses per-field permission evaluation entirely.
	#[tokio::test]
	async fn test_live_field_permission_error_does_not_abort_create() {
		let (_, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		// Define a table with a field whose SELECT permission always errors.
		ds.execute(
			"DEFINE TABLE person; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD secret ON person PERMISSIONS FOR select WHERE string::len(NONE)",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		// Register the LIVE query as a record-access user. Record-level auth has
		// db_in_actor_level = false, so check_reduction_required returns true and
		// compute_reduced_target is invoked under the subscriber's restricted auth.
		let live_ses = Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String("alice".to_string()),
			}),
		)
		.with_rt(true);
		ds.execute("LIVE SELECT * FROM person", &live_ses, None).await.unwrap();

		let ses_write = Session::owner().with_ns(ns).with_db(db);
		let mut res = ds
			.execute("CREATE person:20 SET secret = 'shh'", &ses_write, None)
			.await
			.expect("execute should not return an Err");
		res.remove(0)
			.result
			.expect("CREATE should succeed despite erroring field SELECT permission");
	}

	/// `LIVE SELECT DIFF FROM t` with a non-Owner subscriber must not include `Remove`
	/// operations for fields the subscriber cannot `SELECT`.
	///
	/// Before the fix, `self.initial` (LHS of the diff for UPDATE notifications) was not reduced
	/// under the subscriber's auth, so any field present in the initial document but absent from
	/// the reduced RHS would appear as a spurious `Remove` op — leaking the field name and
	/// existence to a subscriber who has no SELECT permission on it.
	#[tokio::test]
	async fn test_live_diff_does_not_leak_restricted_field_name() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD name ON person TYPE string; \
			 DEFINE FIELD secret ON person TYPE string PERMISSIONS FOR select WHERE false",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		// Pre-create the record before the LIVE query so the subsequent UPDATE is
		// seen as a diff from a known initial state, not a CREATE notification.
		ds.execute("CREATE person:50 SET name = 'foo', secret = 'shh'", &owner_ses, None)
			.await
			.unwrap();

		// Register LIVE SELECT DIFF as a record-access (non-Owner) subscriber.
		let live_ses = Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String("alice".to_string()),
			}),
		)
		.with_rt(true);
		ds.execute("LIVE SELECT DIFF FROM person", &live_ses, None).await.unwrap();
		// Drain any stale notifications.
		while recv.try_recv().is_ok() {}

		// Trigger an UPDATE as owner — only the `name` field changes.
		ds.execute("UPDATE person:50 SET name = 'bar'", &owner_ses, None).await.unwrap();

		// Collect the UPDATE notification.
		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");

		// The result must be an array of JSON patch operations.
		let PublicValue::Array(ops) = notif.result else {
			panic!(
				"DIFF result should be a Value::Array of patch operations, got: {:?}",
				notif.result
			);
		};
		// No operation should be a Remove referencing /secret.
		for op in ops.iter() {
			let PublicValue::Object(obj) = op else {
				continue;
			};
			let is_remove = obj.get("op") == Some(&PublicValue::String("remove".to_string()));
			let targets_secret =
				obj.get("path") == Some(&PublicValue::String("/secret".to_string()));
			assert!(
				!(is_remove && targets_secret),
				"DIFF UPDATE must not leak a Remove op for the restricted /secret field; ops: {ops:?}"
			);
		}
	}

	/// `compute_reduced_target` reduces the document *before* `computed_fields_inner`
	/// populates COMPUTED fields, so a computed field marked
	/// `PERMISSIONS FOR select NONE` would never be touched by the table-side
	/// reduction. The CREATE notification delivered to a record subscriber must not
	/// contain the computed field's value.
	#[tokio::test]
	async fn test_live_create_does_not_leak_restricted_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD secret ON person TYPE string; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', secret) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		// Register the LIVE subscriber as a record user; `compute_reduced_target`
		// fires for non-owner sessions.
		let live_ses = Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String("alice".to_string()),
			}),
		)
		.with_rt(true);
		ds.execute("LIVE SELECT * FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		// CREATE as owner — `derived` is computed at write time, so it exists in
		// the stored record. The notification builder must strip it before
		// shipping to the record subscriber.
		ds.execute("CREATE person:1 SET secret = 'shh'", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");

		assert_eq!(notif.action, PublicAction::Create);
		let PublicValue::Object(obj) = notif.result else {
			panic!("CREATE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			!obj.contains_key("derived"),
			"CREATE notification must not include the restricted computed field; got: {obj:?}"
		);
	}

	/// `lq_compute` runs the helper on `&self.initial` for DELETE events too;
	/// without it, the DELETE notification would carry the unfiltered computed
	/// field from the pre-delete state.
	#[tokio::test]
	async fn test_live_delete_does_not_leak_restricted_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD secret ON person TYPE string; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', secret) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();
		ds.execute("CREATE person:1 SET secret = 'shh'", &owner_ses, None).await.unwrap();

		let live_ses = Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String("alice".to_string()),
			}),
		)
		.with_rt(true);
		ds.execute("LIVE SELECT * FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("DELETE person:1", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");

		assert_eq!(notif.action, PublicAction::Delete);
		let PublicValue::Object(obj) = notif.result else {
			panic!("DELETE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			!obj.contains_key("derived"),
			"DELETE notification must not include the restricted computed field; got: {obj:?}"
		);
	}

	/// LIVE DIFF on an UPDATE evaluates the diff between `reduced_initial` and the
	/// permission-reduced current document. The LHS must also have computed-field
	/// permissions applied; otherwise a Remove op exposes the restricted computed
	/// field name (and value, via the patch contents).
	#[tokio::test]
	async fn test_live_diff_does_not_leak_restricted_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE person PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD name ON person TYPE string; \
			 DEFINE FIELD derived ON person TYPE string \
			     COMPUTED string::concat('derived_', name) \
			     PERMISSIONS FOR select NONE",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		// Pre-create so the subsequent UPDATE produces an UPDATE notification
		// (not a CREATE) and exercises the `reduced_initial` filtering path.
		ds.execute("CREATE person:1 SET name = 'foo'", &owner_ses, None).await.unwrap();

		let live_ses = Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String("alice".to_string()),
			}),
		)
		.with_rt(true);
		ds.execute("LIVE SELECT DIFF FROM person", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		ds.execute("UPDATE person:1 SET name = 'bar'", &owner_ses, None).await.unwrap();

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");

		let PublicValue::Array(ops) = notif.result else {
			panic!(
				"DIFF result should be a Value::Array of patch operations, got: {:?}",
				notif.result
			);
		};
		for op in ops.iter() {
			let PublicValue::Object(obj) = op else {
				continue;
			};
			// `Remove /derived` on the LHS would leak the field's existence; a
			// `Replace /derived` would leak its old value via the patch payload.
			let path = obj.get("path");
			let targets_derived = path == Some(&PublicValue::String("/derived".to_string()));
			assert!(
				!targets_derived,
				"DIFF UPDATE must not reference the restricted computed field; ops: {ops:?}"
			);
		}
	}

	/// Conditional (`Specific`) field permissions on computed fields must also be
	/// enforced on LIVE delivery: a subscriber whose record does not satisfy the
	/// permission expression must not receive the computed value, while a
	/// subscriber whose record does satisfy it must.
	#[tokio::test]
	async fn test_live_conditional_permission_filters_computed_field() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db) = ("test", "test");
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.ensure_ns_db(None, ns, db).await.unwrap();
		tx.commit().await.unwrap();

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		ds.execute(
			"DEFINE TABLE doc PERMISSIONS FOR select FULL; \
			 DEFINE ACCESS user ON DATABASE TYPE RECORD; \
			 DEFINE FIELD owner ON doc TYPE record<user>; \
			 DEFINE FIELD name ON doc TYPE string; \
			 DEFINE FIELD mine ON doc TYPE string \
			     COMPUTED string::concat('hi_', name) \
			     PERMISSIONS FOR select WHERE owner = $auth",
			&owner_ses,
			None,
		)
		.await
		.unwrap();

		let live_ses = Session::for_record(
			ns,
			db,
			"user",
			PublicValue::RecordId(PublicRecordId {
				table: "user".to_string().into(),
				key: PublicRecordIdKey::String("alice".to_string()),
			}),
		)
		.with_rt(true);
		ds.execute("LIVE SELECT * FROM doc", &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		// First record is owned by the subscriber → `mine` is visible.
		ds.execute("CREATE doc:1 SET owner = user:alice, name = 'one'", &owner_ses, None)
			.await
			.unwrap();
		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		let PublicValue::Object(obj) = notif.result else {
			panic!("CREATE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			obj.contains_key("mine"),
			"CREATE notification for own record must include the conditional computed field; got: {obj:?}"
		);

		// Second record is owned by someone else → `mine` is hidden.
		ds.execute("CREATE doc:2 SET owner = user:bob, name = 'two'", &owner_ses, None)
			.await
			.unwrap();
		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification should arrive within timeout")
			.expect("channel should not be closed");
		let PublicValue::Object(obj) = notif.result else {
			panic!("CREATE result should be an object, got: {:?}", notif.result);
		};
		assert!(
			!obj.contains_key("mine"),
			"CREATE notification for someone else's record must NOT include the conditional computed field; got: {obj:?}"
		);
	}

	/// Sanity check: a LIVE query with a non-expiring session receives notifications normally.
	#[tokio::test]
	async fn test_live_active_session_sends_notification() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let live_ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute(&format!("LIVE SELECT * FROM {tb}"), &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		let res = ds.execute(&format!("CREATE {tb}"), &owner_ses, None).await.unwrap();
		assert!(res[0].result.is_ok());

		// Notifications are forwarded from the per-execution broker to the datastore
		// channel by a spawned task, so yield briefly to allow that task to run.
		let notification =
			tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv()).await;
		assert!(notification.is_ok(), "expected a notification from the active LIVE query");
	}

	/// A read-only bare statement in the same batch must not leave a stale broker on `ctx`;
	/// otherwise the next write's LIVE notifications are dropped into a closed channel (broker
	/// leak).
	#[tokio::test]
	async fn test_live_notification_survives_read_only_preceding_write_in_batch() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let live_ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute(&format!("LIVE SELECT * FROM {tb}"), &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		let res = ds.execute(&format!("RETURN 1; CREATE {tb}:1"), &owner_ses, None).await.unwrap();
		assert!(res[0].result.is_ok(), "RETURN should succeed");
		assert!(res[1].result.is_ok(), "CREATE should succeed");

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("CREATE notification must arrive after a preceding read in the same batch")
			.expect("notification channel should not be closed");
		assert_eq!(notif.action, PublicAction::Create);
	}

	/// A failing write must clear the per-statement broker so a later statement in the batch
	/// still installs a fresh channel for LIVE notifications.
	#[tokio::test]
	async fn test_live_notification_survives_failing_write_preceding_success_in_batch() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let live_ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		ds.execute(&format!("LIVE SELECT * FROM {tb}"), &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		let res = ds
			.execute(
				&format!(
					"CREATE {tb}:dup SET x = 1; CREATE {tb}:dup SET x = 2; CREATE {tb}:ok SET x = 3"
				),
				&owner_ses,
				None,
			)
			.await
			.unwrap();
		assert_eq!(res.len(), 3);
		assert!(res[0].result.is_ok(), "first CREATE should succeed");
		assert!(res[1].result.is_err(), "duplicate CREATE should fail");
		assert!(res[2].result.is_ok(), "third CREATE should succeed");

		let notif = tokio::time::timeout(tokio::time::Duration::from_millis(500), recv.recv())
			.await
			.expect("notification must arrive after a failing write in the same batch")
			.expect("notification channel should not be closed");
		assert_eq!(notif.action, PublicAction::Create);
	}

	/// A LIVE query whose originating session has expired via TTL must not receive
	/// notifications after the TTL passes. Data written after a session expires
	/// should not be streamed to the now-invalid subscriber.
	///
	/// We set `exp` to the current integer second so the session is still technically
	/// valid at query-creation time (`Utc::now().timestamp() > exp` is false), then
	/// sleep ≥1.1 s to guarantee the integer counter has advanced past `exp`.
	#[tokio::test]
	async fn test_live_expired_session_suppresses_notification() {
		let (recv, ds) = new_ds_with_broker().await.unwrap();
		let (ns, db, tb) = ("test", "test", "person");
		setup_ns_db_table(&ds, ns, db, tb).await;

		let mut live_ses = Session::owner().with_ns(ns).with_db(db).with_rt(true);
		live_ses.exp = Some(Utc::now().timestamp());
		ds.execute(&format!("LIVE SELECT * FROM {tb}"), &live_ses, None).await.unwrap();
		while recv.try_recv().is_ok() {}

		// Sleep long enough that the integer-second counter advances past `exp`.
		tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

		let owner_ses = Session::owner().with_ns(ns).with_db(db);
		let res = ds.execute(&format!("CREATE {tb}"), &owner_ses, None).await.unwrap();
		assert!(res[0].result.is_ok(), "CREATE must succeed regardless of LIVE query TTL");

		// Give the background forwarding task time to deliver any notification that might
		// have been queued, then verify the channel remains empty.
		let spurious =
			tokio::time::timeout(tokio::time::Duration::from_millis(200), recv.recv()).await;
		assert!(
			spurious.is_err(),
			"no notification must be sent after the LIVE query's session TTL has expired"
		);
	}
}
