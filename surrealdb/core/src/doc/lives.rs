use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use async_channel::Sender;
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
use crate::types::{PublicAction, PublicNotification};
use crate::val::{Value, convert_value_to_public_value};

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
		if !self.is_modified() {
			return Ok(());
		}

		// Get all live queries for this table
		let live_subscriptions = self.doc_ctx.lv()?;

		// If there are no live queries, we can skip the rest of the function
		if live_subscriptions.is_empty() {
			return Ok(());
		}

		// Get the event action
		let (met, is_delete): (Arc<Value>, _) = match action {
			Action::Delete => (Value::from("DELETE").into(), true),
			Action::Create => (Value::from("CREATE").into(), false),
			Action::Update => (Value::from("UPDATE").into(), false),
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

	#[allow(clippy::too_many_arguments, reason = "live-query dispatch shape")]
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
		// Add the session params to this LIVE query, so
		// that queries can use these within field
		// projections and WHERE clauses.
		ctx.add_value("access", sess.pick(AC.as_ref()).into());
		ctx.add_value("auth", sess.pick(RD.as_ref()).into());
		ctx.add_value("token", sess.pick(TK.as_ref()).into());
		ctx.add_value("session", sess.clone().into());
		// Add $before, $after, $value, and $event params
		// to this LIVE query so the user can use these
		// within field projections and WHERE clauses.
		ctx.add_value("event", met);
		ctx.add_value("value", Arc::clone(&current));
		ctx.add_value("after", current);
		ctx.add_value("before", initial);
		// Add the variables to the context
		ctx.add_values(live_subscription.vars.clone());
		// Freeze the context
		let ctx = ctx.freeze();

		// Get the document to check against and to return based on lq context.
		// We need an owned clone here because computed-field evaluation
		// mutates the doc, and the outcome can differ per subscription.
		// `reduce_to_owned` collapses the reduction-required / clone-only
		// branches into one call.
		let source = if is_delete {
			&self.initial
		} else {
			&self.current
		};
		let mut doc = self.reduce_to_owned(stk, &ctx, &opt, source).await?;

		if let Ok(rid) = self.id() {
			let fields = self.doc_ctx.fd()?;
			// Live-query notifications evaluate every computed field
			// for now. A future refinement can pass the closure of
			// fields the subscription's projection / WHERE actually
			// reads, mirroring what SELECT does, but the savings on
			// live tables are usually small and the bookkeeping less
			// obvious. Pass `None` to keep behaviour conservative.
			Document::computed_fields_inner(stk, &ctx, &opt, rid.as_ref(), fields, &mut doc, None)
				.await?;
		};

		// First of all, let's check to see if the WHERE
		// clause of the LIVE query is matched by this
		// document. If it is then we can continue.
		match self.lq_check(stk, &ctx, &opt, &live_subscription, &doc).await {
			Err(IgnoreError::Ignore) => return Ok(()),
			Err(IgnoreError::Error(e)) => return Err(e),
			Ok(_) => (),
		}
		// Secondly, let's check to see if any PERMISSIONS
		// clause for this table allows this document to
		// be viewed by the user who created this LIVE
		// query. If it does, then we can continue.
		match self.lq_allow(stk, &ctx, &opt).await {
			Err(IgnoreError::Ignore) => return Ok(()),
			Err(IgnoreError::Error(e)) => return Err(e),
			Ok(_) => (),
		}
		if !sender.should_emit(*ctx.node_id().as_bytes(), *live_subscription.node.as_bytes())? {
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
					// For UPDATE: compute diff from initial to current document
					let operations = self.initial.doc.as_ref().diff(doc.doc.as_ref());
					let result = Value::Array(
						operations.into_iter().map(|op| Value::Object(op.into_object())).collect(),
					);
					(PublicAction::Update, result)
				}
			}
			SubscriptionFields::Select(x) => {
				if is_delete {
					// Prepare a DELETE notification
					// An error ignore here is about livequery not the query which invoked the
					// livequery trigger. So we should catch the ignore and skip this entry in this
					// case.
					let result = match x
						.compute(stk, &ctx, &opt, Some(&doc))
						.await
						.map_err(IgnoreError::from)
					{
						Err(IgnoreError::Ignore) => return Ok(()),
						Err(IgnoreError::Error(e)) => return Err(e),
						Ok(x) => x,
					};
					(PublicAction::Delete, result)
				} else if self.is_new() {
					// Prepare a CREATE notification
					// An error ignore here is about livequery not the query which invoked the
					// livequery trigger. So we should catch the ignore and skip this entry in this
					// case.
					let result = match x
						.compute(stk, &ctx, &opt, Some(&doc))
						.await
						.map_err(IgnoreError::from)
					{
						Err(IgnoreError::Ignore) => return Ok(()),
						Err(IgnoreError::Error(e)) => return Err(e),
						Ok(x) => x,
					};
					(PublicAction::Create, result)
				} else {
					// Prepare a UPDATE notification
					// An error ignore here is about livequery not the query which invoked the
					// livequery trigger. So we should catch the ignore and skip this entry in this
					// case.
					let result = match x
						.compute(stk, &ctx, &opt, Some(&doc))
						.await
						.map_err(IgnoreError::from)
					{
						Err(IgnoreError::Ignore) => return Ok(()),
						Err(IgnoreError::Error(e)) => return Err(e),
						Ok(x) => x,
					};
					(PublicAction::Update, result)
				}
			}
		};

		// Process any potential `FETCH` clause on the live statement
		if let Some(fetchs) = live_subscription.fetch {
			let mut idioms: std::collections::BTreeSet<crate::expr::Idiom> =
				std::collections::BTreeSet::new();
			for fetch in fetchs.iter() {
				fetch.compute(stk, &ctx, &opt, &mut idioms).await?;
			}
			for i in &idioms {
				stk.run(|stk| result.fetch(stk, &ctx, &opt, &i.0)).await?;
			}
		}

		// Extract the session ID from the session value
		let session_id = match sess.pick(ID.as_ref()) {
			Value::Uuid(uuid) => Some(uuid.into()),
			Value::String(s) => s.parse::<crate::val::Uuid>().ok().map(|uuid| uuid.into()),
			_ => None,
		};

		let notification = PublicNotification::new(
			live_subscription.id.into(),
			session_id,
			action,
			convert_value_to_public_value(Value::RecordId(rid.as_ref().clone()))?,
			convert_value_to_public_value(result)?,
		);

		// Send the notification
		sender.send(RoutedNotification::new(live_subscription.node, notification)).await;

		Ok(())
	}

	/// Check the WHERE clause for a LIVE query
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
			// Check if the expression is truthy
			if !stk
				.run(|stk| cond.compute(stk, ctx, opt, Some(doc)))
				.await
				.catch_return()?
				.is_truthy()
			{
				// Ignore this document
				return Err(IgnoreError::Ignore);
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
	) -> Result<(), IgnoreError> {
		// Should we run permissions checks?
		// Live queries are always
		if ctx.check_perms(opt, crate::iam::Action::View)? {
			// Get the table
			let tb = self.doc_ctx.tb()?;
			// Process the table permissions
			match &tb.permissions.select {
				Permission::None => return Err(IgnoreError::Ignore),
				Permission::Full => return Ok(()),
				Permission::Specific(e) => {
					// Retrieve the document to check permissions against
					let doc = &self.current;

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
