use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::Result;
use chrono::Utc;
use reblessive::TreeStack;
use revision::revisioned;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use uuid::Uuid;
use web_time::Instant;

use super::builder::Building;
use super::{
	AppendingId, BUILD_CLOSING_SLEEP, BatchId, BuildGeneration, ExistingPrimaryAppending,
	IndexBuildPhase, IndexBuildReportStatus, LEGACY_BATCH_ID,
};
use crate::catalog::providers::NodeProvider;
use crate::catalog::{Index, Record};
use crate::ctx::FrozenContext;
use crate::doc::{CursorDoc, Document};
use crate::err::Error;
use crate::expr::FlowResultExt as _;
use crate::idx::ft::fulltext::FullTextIndex;
use crate::idx::index::IndexOperation;
use crate::key::index::ig::IndexAppending;
use crate::key::record;
use crate::key::table::bg::Bg;
use crate::key::table::bp::Bp;
use crate::key::table::br::Br;
use crate::kvs::{
	INDEXING_BATCH_SIZE, Key, Transaction, Val, impl_kv_value_revisioned,
	is_retryable_transaction_conflict,
};
use crate::val::{RecordId, RecordIdKey, Value};

#[revisioned(revision = 2)]
#[derive(Debug, PartialEq)]
pub(crate) struct Appending {
	/// Values to remove from the index when replaying the write.
	pub(super) old_values: Option<Vec<Value>>,
	/// Values to add to the index when replaying the write.
	pub(super) new_values: Option<Vec<Value>>,
	/// Record id key whose index entries are being replayed.
	pub(super) id: RecordIdKey,
	/// Cached COUNT condition match state `(old_matches, new_matches)`.
	///
	/// Re-evaluating a conditional COUNT predicate during replay can observe a
	/// different document state than the user write observed. Carrying both
	/// booleans makes replay deterministic.
	#[revision(start = 2)]
	pub(super) count_cond_match: Option<(bool, bool)>,
}

impl_kv_value_revisioned!(Appending);

impl Appending {
	#[cfg(test)]
	pub(crate) fn new(
		old_values: Option<Vec<Value>>,
		new_values: Option<Vec<Value>>,
		id: RecordIdKey,
	) -> Self {
		Self {
			old_values,
			new_values,
			id,
			count_cond_match: None,
		}
	}
}

#[revisioned(revision = 2)]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub(crate) struct PrimaryAppending(
	/// Appending id within the concurrent indexing queue.
	AppendingId,
	/// Batch id associated with this append.
	#[revision(start = 2)]
	BatchId,
);

impl_kv_value_revisioned!(PrimaryAppending);

impl PrimaryAppending {
	#[cfg(test)]
	pub(crate) fn new(appending_id: AppendingId, batch_id: BatchId) -> Self {
		Self(appending_id, batch_id)
	}
}

struct InitialIndexValue<'a> {
	rid: &'a RecordId,
	opt_values: Option<Vec<Value>>,
	count_cond_match: Option<(bool, bool)>,
}

struct CountPrimaryAppendingScan<'a> {
	lookup_tx: &'a Transaction,
	cursor: &'a mut Option<RecordIdKey>,
	through: Option<&'a RecordIdKey>,
	live_ids: &'a BTreeSet<RecordIdKey>,
	initial_count: usize,
}

impl Building {
	/// Drain both legacy and durable queued mutations until the visible queues are empty.
	///
	/// Legacy `!ig`/`!ip` appendings can exist from already committed work
	/// created by older paths. Durable `!bg` appendings are scoped to the
	/// current generation and must be replayed before the build can move online.
	pub(super) async fn index_appending_loop(
		&self,
		initial_count: usize,
		updates_count: &mut usize,
		last_prepare_remove_check: &mut Instant,
	) -> Result<()> {
		let rng = self.ikb.new_ig_range()?;
		let generation = self.build_generation.load(Ordering::Acquire);
		let durable_rng = if generation == 0 {
			None
		} else {
			Some(self.ikb.new_bg_range(generation)?)
		};
		loop {
			if self.is_aborted().await {
				return Ok(());
			}
			self.is_beyond_threshold(None)?;
			// Check the index still exists and has not been marked for removal
			self.check_prepare_remove(last_prepare_remove_check).await?;

			let (keys, durable_keys) = {
				let tx = self.new_read_tx().await?;
				let keys = catch!(tx, tx.keys(rng.clone(), INDEXING_BATCH_SIZE, 0, None).await);
				let durable_keys = if let Some(durable_rng) = &durable_rng {
					catch!(tx, tx.keys(durable_rng.clone(), INDEXING_BATCH_SIZE, 0, None).await)
				} else {
					Vec::new()
				};
				tx.cancel().await?;
				(keys, durable_keys)
			};
			let pending = keys.len() + durable_keys.len();
			if keys.is_empty() && durable_keys.is_empty() {
				self.mark_durable_report(
					generation,
					IndexBuildReportStatus::Indexing,
					Some(initial_count),
					Some(0),
					Some(*updates_count),
				)
				.await?;
				break;
			}
			self.mark_durable_report(
				generation,
				IndexBuildReportStatus::Indexing,
				Some(initial_count),
				Some(pending),
				Some(*updates_count),
			)
			.await?;
			if !keys.is_empty() {
				// We have committed appendings to index.
				// Create a new context with a write transaction.
				let ctx = self.new_write_tx_ctx().await?;
				let tx = ctx.tx();
				let saved_updates_count = *updates_count;
				let allowed = if generation == 0 {
					&[][..]
				} else {
					&[IndexBuildPhase::Building, IndexBuildPhase::Closing][..]
				};
				if generation != 0
					&& let Err(err) = self.maintain_build_ownership(&tx, generation, allowed).await
				{
					*updates_count = saved_updates_count;
					if self
						.cancel_and_retryable_conflict(
							&tx,
							&err,
							"transient conflict maintaining build ownership, retrying",
						)
						.await
					{
						continue;
					}
					return Err(err);
				}
				match self.index_appending_range(&ctx, &tx, keys, updates_count).await {
					Ok(()) => {}
					Err(err) => {
						*updates_count = saved_updates_count;
						if self
							.cancel_and_retryable_conflict(
								&tx,
								&err,
								"transient conflict in appending range, retrying",
							)
							.await
						{
							continue;
						}
						return Err(err);
					}
				};
				match tx.commit().await {
					Ok(()) => {
						self.mark_durable_report(
							generation,
							IndexBuildReportStatus::Indexing,
							Some(initial_count),
							Some(0),
							Some(*updates_count),
						)
						.await?;
					}
					Err(err) => {
						*updates_count = saved_updates_count;
						if self
							.cancel_and_retryable_conflict(
								&tx,
								&err,
								"transient conflict on commit, retrying",
							)
							.await
						{
							continue;
						}
						return Err(err);
					}
				}
			}
			if !durable_keys.is_empty() {
				let ctx = self.new_write_tx_ctx().await?;
				let tx = ctx.tx();
				let saved_updates_count = *updates_count;
				let allowed = &[IndexBuildPhase::Building, IndexBuildPhase::Closing];
				if let Err(err) = self.maintain_build_ownership(&tx, generation, allowed).await {
					*updates_count = saved_updates_count;
					if self
						.cancel_and_retryable_conflict(
							&tx,
							&err,
							"transient conflict maintaining build ownership, retrying",
						)
						.await
					{
						continue;
					}
					return Err(err);
				}
				match self
					.index_durable_appending_range(&ctx, &tx, durable_keys, updates_count)
					.await
				{
					Ok(()) => match tx.commit().await {
						Ok(()) => {
							self.mark_durable_report(
								generation,
								IndexBuildReportStatus::Indexing,
								Some(initial_count),
								Some(0),
								Some(*updates_count),
							)
							.await?;
						}
						Err(err) => {
							*updates_count = saved_updates_count;
							if self
								.cancel_and_retryable_conflict(
									&tx,
									&err,
									"transient conflict on durable appending commit, retrying",
								)
								.await
							{
								continue;
							}
							return Err(err);
						}
					},
					Err(err) => {
						*updates_count = saved_updates_count;
						if self
							.cancel_and_retryable_conflict(
								&tx,
								&err,
								"transient conflict in durable appending range, retrying",
							)
							.await
						{
							continue;
						}
						return Err(err);
					}
				}
			}
		}
		Ok(())
	}

	/// Wait until every admitted writer has either committed its appending or is
	/// safe to discard after writer-node death.
	///
	/// During `Closing`, new admissions are rejected. This loop closes the gap
	/// for writers that received a ticket before `Closing` but have not yet
	/// committed the user transaction that writes the durable appending.
	pub(super) async fn wait_for_durable_reservations(
		&self,
		generation: BuildGeneration,
		last_prepare_remove_check: &mut Instant,
	) -> Result<()> {
		let rng = self.ikb.new_br_range(generation)?;
		loop {
			if self.is_aborted().await {
				return Ok(());
			}
			self.check_prepare_remove(last_prepare_remove_check).await?;
			let keys = {
				let tx = self.new_read_tx().await?;
				let keys = catch!(tx, tx.keys(rng.clone(), INDEXING_BATCH_SIZE, 0, None).await);
				tx.cancel().await?;
				keys
			};
			if keys.is_empty() {
				return Ok(());
			}
			let now = Utc::now();
			let mut blocked = false;
			let ctx = self.new_write_tx_ctx().await?;
			let tx = ctx.tx();
			if let Err(err) =
				self.maintain_build_ownership(&tx, generation, &[IndexBuildPhase::Closing]).await
			{
				if self
					.cancel_and_retryable_conflict(
						&tx,
						&err,
						"transient conflict maintaining build ownership, retrying",
					)
					.await
				{
					continue;
				}
				return Err(err);
			}
			for key in keys {
				let br = Br::decode_key(&key)?;
				if let Some(reservation) = tx.get(&br, None).await? {
					let appending_committed =
						tx.exists(&self.ikb.new_bg_key(br.generation, br.ticket), None).await?;
					let writer_dead = reservation.expires_at <= now
						&& !self.reservation_node_is_live(&tx, reservation.node).await?;
					if appending_committed || writer_dead {
						tx.del(&br).await?;
					} else {
						blocked = true;
					}
				}
			}
			if let Err(err) = tx.commit().await {
				if self
					.cancel_and_retryable_conflict(
						&tx,
						&err,
						"transient conflict while cleaning build reservations, retrying",
					)
					.await
				{
					continue;
				}
				return Err(err);
			}
			if blocked {
				sleep(BUILD_CLOSING_SLEEP).await;
			}
		}
	}

	/// Check durable node membership before discarding an expired reservation.
	async fn reservation_node_is_live(&self, tx: &Transaction, node: Uuid) -> Result<bool> {
		match tx.get_node(node).await {
			Ok(node) => Ok(node.is_active()),
			Err(err) if matches!(err.downcast_ref::<Error>(), Some(Error::NdNotFound { .. })) => {
				Ok(false)
			}
			Err(err) => Err(err),
		}
	}

	/// Index one batch from the initial record scan.
	///
	/// If a queued mutation already exists for a record, the scan indexes the
	/// queued old state instead of the current record value. That avoids
	/// double-counting the same write when the appending is replayed later.
	pub(super) async fn index_initial_batch(
		&self,
		ctx: &FrozenContext,
		tx: &Transaction,
		values: &[(Key, Val)],
		initial_count: usize,
		v1_appending_sentinel: &mut bool,
		count_primary_cursor: &mut Option<Option<RecordIdKey>>,
	) -> Result<usize> {
		let mut rc = false;
		let mut count = 0;
		let mut live_ids = BTreeSet::new();
		let mut last_live_id = None;
		let mut stack = TreeStack::new();
		let fulltext_index =
			IndexOperation::create_fulltext_index(ctx, self.ix_key.ns, self.ix_key.db, &self.ix)
				.await?;
		let lookup_tx = self.new_read_tx().await?;
		let result = async {
			// Index the records.
			for (k, v) in values {
				if self.is_aborted().await {
					return Ok(count);
				}
				self.is_beyond_threshold(Some(initial_count + count))?;
				let key = record::RecordKey::decode_key(k)?;
				// Parse the value.
				let val: Record = revision::from_slice(v.as_slice())?;
				let rid: Arc<RecordId> = RecordId {
					table: key.tb.into_owned(),
					key: key.id,
				}
				.into();
				if count_primary_cursor.is_some() {
					live_ids.insert(rid.key.clone());
					last_live_id = Some(rid.key.clone());
				}

				// Is there already a queued update for this record?
				let (opt_values, count_cond_match) = if let Some(a) = self
					.check_existing_primary_appending(&lookup_tx, &rid.key, v1_appending_sentinel)
					.await?
				{
					(a.old_values, a.count_cond_match.map(|(old_matches, _)| (false, old_matches)))
				} else {
					// Otherwise, proceed with normal indexing.
					let doc = CursorDoc::new(Some(Arc::clone(&rid)), None, val);
					let opt_values = stack
						.enter(|stk| {
							Document::build_opt_values(stk, ctx, &self.opt, &self.ix, &doc)
						})
						.finish()
						.await?;
					// COUNT WHERE indexes have no indexed values, so the
					// initial scan carries the predicate result separately.
					let count_cond_match = if let Index::Count(Some(cond)) = &self.ix.index {
						let new_matches = stack
							.enter(|stk| cond.0.compute(stk, ctx, &self.opt, Some(&doc)))
							.finish()
							.await
							.catch_return()?
							.is_truthy();
						Some((false, new_matches))
					} else {
						None
					};
					(opt_values, count_cond_match)
				};
				self.index_initial_values(
					ctx,
					&mut stack,
					&fulltext_index,
					InitialIndexValue {
						rid: rid.as_ref(),
						opt_values,
						count_cond_match,
					},
					&mut rc,
				)
				.await?;

				// Increment the count.
				count += 1;
			}
			if let Some(cursor) = count_primary_cursor.as_mut()
				&& let Some(through) = last_live_id.as_ref()
			{
				count += self
					.index_missing_count_primary_appendings(
						ctx,
						CountPrimaryAppendingScan {
							lookup_tx: &lookup_tx,
							cursor,
							through: Some(through),
							live_ids: &live_ids,
							initial_count: initial_count + count,
						},
						&mut stack,
						&mut rc,
					)
					.await?;
			}
			// Trigger compaction if needed.
			self.check_index_compaction(tx, &mut rc).await?;
			// We're done.
			Ok(count)
		}
		.await;
		let cancel_result = lookup_tx.cancel().await;
		match result {
			Ok(count) => {
				cancel_result?;
				Ok(count)
			}
			Err(err) => {
				let _ = cancel_result;
				Err(err)
			}
		}
	}

	/// Index queued old states for COUNT records the live scan has already passed.
	pub(super) async fn index_remaining_count_primary_appendings(
		&self,
		ctx: &FrozenContext,
		tx: &Transaction,
		count_primary_cursor: &mut Option<Option<RecordIdKey>>,
		initial_count: usize,
	) -> Result<usize> {
		let Some(cursor) = count_primary_cursor.as_mut() else {
			return Ok(0);
		};
		let lookup_tx = self.new_read_tx().await?;
		let mut stack = TreeStack::new();
		let mut rc = false;
		let live_ids = BTreeSet::new();
		let result = self
			.index_missing_count_primary_appendings(
				ctx,
				CountPrimaryAppendingScan {
					lookup_tx: &lookup_tx,
					cursor,
					through: None,
					live_ids: &live_ids,
					initial_count,
				},
				&mut stack,
				&mut rc,
			)
			.await;
		let cancel_result = lookup_tx.cancel().await;
		match result {
			Ok(count) => {
				cancel_result?;
				self.check_index_compaction(tx, &mut rc).await?;
				Ok(count)
			}
			Err(err) => {
				let _ = cancel_result;
				Err(err)
			}
		}
	}

	/// Index one initial-scan value.
	async fn index_initial_values(
		&self,
		ctx: &FrozenContext,
		stack: &mut TreeStack,
		fulltext_index: &Option<FullTextIndex>,
		value: InitialIndexValue<'_>,
		rc: &mut bool,
	) -> Result<()> {
		let InitialIndexValue {
			rid,
			opt_values,
			count_cond_match,
		} = value;
		let mut io = IndexOperation::new(
			ctx,
			&self.opt,
			self.ix_key.ns,
			self.ix_key.db,
			self.tb,
			&self.ix,
			None,
			opt_values,
			rid,
		);
		if let Some((old_matches, new_matches)) = count_cond_match {
			io = io.with_count_cond_match(old_matches, new_matches);
		}
		if let Some(fulltext_index) = fulltext_index {
			stack
				.enter(|stk| io.compute_fulltext_with_index(stk, fulltext_index, rc))
				.finish()
				.await
		} else {
			stack.enter(|stk| io.compute(stk, rc)).finish().await
		}
	}

	/// Merge orphaned COUNT primary markers into the initial baseline.
	///
	/// Durable `!bp` markers record the first queued mutation for each record
	/// while the initial scan is running. A COUNT build must index the queued
	/// old state even when the live record scan no longer sees the record, so
	/// later replay deltas are applied against the same baseline.
	async fn index_missing_count_primary_appendings(
		&self,
		ctx: &FrozenContext,
		scan: CountPrimaryAppendingScan<'_>,
		stack: &mut TreeStack,
		rc: &mut bool,
	) -> Result<usize> {
		let Index::Count(_) = &self.ix.index else {
			return Ok(0);
		};
		let generation = self.build_generation.load(Ordering::Acquire);
		if generation == 0 {
			return Ok(0);
		}
		let range = self.ikb.new_bp_span_range(generation, scan.cursor.as_ref(), scan.through)?;
		if range.start >= range.end {
			if let Some(through) = scan.through {
				*scan.cursor = Some(through.clone());
			}
			return Ok(0);
		}
		let mut count = 0;
		let mut next = Some(range);
		while let Some(rng) = next {
			if self.is_aborted().await {
				return Ok(count);
			}
			let batch = scan.lookup_tx.batch_keys(rng, INDEXING_BATCH_SIZE, None).await?;
			next = batch.next;
			for key in batch.result {
				if self.is_aborted().await {
					return Ok(count);
				}
				self.is_beyond_threshold(Some(scan.initial_count + count))?;
				let bp = Bp::decode_key(&key)?;
				if scan.live_ids.contains(&bp.id) {
					continue;
				}
				let Some(ticket) = scan.lookup_tx.get(&bp, None).await? else {
					continue;
				};
				let bg = self.ikb.new_bg_key(bp.generation, ticket);
				let Some(appending) = scan.lookup_tx.get(&bg, None).await? else {
					return Err(Error::CorruptedIndex("Durable appending record is missing").into());
				};
				let rid = RecordId {
					table: self.ikb.table().clone(),
					key: bp.id.clone(),
				};
				let count_cond_match =
					appending.count_cond_match.map(|(old_matches, _)| (false, old_matches));
				self.index_initial_values(
					ctx,
					stack,
					&None,
					InitialIndexValue {
						rid: &rid,
						opt_values: appending.old_values,
						count_cond_match,
					},
					rc,
				)
				.await?;
				count += 1;
			}
		}
		if let Some(through) = scan.through {
			*scan.cursor = Some(through.clone());
		}
		Ok(count)
	}

	/// Look up an existing per-record appending marker before initial indexing.
	async fn check_existing_primary_appending(
		&self,
		lookup_tx: &Transaction,
		id_key: &RecordIdKey,
		v1_appending_sentinel: &mut bool,
	) -> Result<Option<Appending>> {
		match self.load_existing_primary_appending(lookup_tx, id_key).await? {
			ExistingPrimaryAppending::None => Ok(None),
			ExistingPrimaryAppending::Appending(appending) => Ok(Some(appending)),
			ExistingPrimaryAppending::Legacy => {
				self.cleanup_legacy_primary_appending(id_key).await?;
				if !*v1_appending_sentinel {
					*v1_appending_sentinel = true;
					warn!(
						"Found legacy v1 primary appending entry from an older version; legacy queued updates will be ignored. Consider rebuilding index {} on table {}.",
						self.ix.name, self.ix.table_name
					);
				}
				Ok(None)
			}
		}
	}

	/// Load the queued mutation that should replace the current record value.
	///
	/// Durable `!bp` markers point to generation-scoped `!bg` entries. Legacy
	/// `!ip` markers point to `!ig` entries unless they are old v1 markers with
	/// no batch id, which cannot be resolved safely and are cleaned up.
	async fn load_existing_primary_appending(
		&self,
		tx: &Transaction,
		id_key: &RecordIdKey,
	) -> Result<ExistingPrimaryAppending> {
		let generation = self.build_generation.load(Ordering::Acquire);
		if generation != 0 {
			let bp = self.ikb.new_bp_key(generation, id_key.clone());
			if let Some(ticket) = tx.get(&bp, None).await? {
				let bg = self.ikb.new_bg_key(generation, ticket);
				let Some(appending) = tx.get(&bg, None).await? else {
					return Err(Error::CorruptedIndex("Durable appending record is missing").into());
				};
				return Ok(ExistingPrimaryAppending::Appending(appending));
			}
		}
		let ip = self.ikb.new_ip_key(id_key.clone());
		let Some(pa) = tx.get(&ip, None).await? else {
			return Ok(ExistingPrimaryAppending::None);
		};
		// Use the old values from the queued update as the initial indexing input.
		if pa.1 == LEGACY_BATCH_ID {
			return Ok(ExistingPrimaryAppending::Legacy);
		}
		let ig = self.ikb.new_ig_key(pa.0, pa.1);
		let Some(appending) = tx.get(&ig, None).await? else {
			return Err(Error::CorruptedIndex("Appending record is missing").into());
		};
		Ok(ExistingPrimaryAppending::Appending(appending))
	}

	async fn cleanup_legacy_primary_appending(&self, id_key: &RecordIdKey) -> Result<()> {
		// Legacy v1 primary appending entries have no batch id and cannot be resolved to a
		// current !ig record. Clean them outside the initial-build write transaction so
		// normal concurrent appends cannot make that transaction conflict.
		let ctx = self.new_write_tx_ctx().await?;
		let tx = ctx.tx();
		let ip = self.ikb.new_ip_key(id_key.clone());
		let pa = catch!(tx, tx.get(&ip, None).await);
		if matches!(pa, Some(pa) if pa.1 == LEGACY_BATCH_ID) {
			catch!(tx, tx.del(&ip).await);
		}
		let res = tx.commit().await;
		match res {
			Ok(()) => Ok(()),
			Err(err) if is_retryable_transaction_conflict(&err) => {
				let _ = tx.cancel().await;
				warn!(
					"{}: transient conflict while cleaning legacy primary appending entry; continuing",
					self.ix.name
				);
				Ok(())
			}
			Err(err) => {
				let _ = tx.cancel().await;
				Err(err)
			}
		}
	}

	/// Apply one queued mutation and return the record key for queue cleanup.
	async fn apply_appending(
		&self,
		ctx: &FrozenContext,
		stack: &mut TreeStack,
		fulltext_index: &Option<FullTextIndex>,
		appending: Appending,
		rc: &mut bool,
	) -> Result<RecordIdKey> {
		let rid_key = appending.id;
		let rid = RecordId {
			table: self.ikb.table().clone(),
			key: rid_key.clone(),
		};
		let mut io = IndexOperation::new(
			ctx,
			&self.opt,
			self.ix_key.ns,
			self.ix_key.db,
			self.tb,
			&self.ix,
			appending.old_values,
			appending.new_values,
			&rid,
		);
		if let Some((old_matches, new_matches)) = appending.count_cond_match {
			io = io.with_count_cond_match(old_matches, new_matches);
		}
		if let Some(fulltext_index) = fulltext_index {
			stack
				.enter(|stk| io.compute_fulltext_with_index(stk, fulltext_index, rc))
				.finish()
				.await?;
		} else {
			stack.enter(|stk| io.compute(stk, rc)).finish().await?;
		}
		Ok(rid_key)
	}

	/// Replay legacy `!ig` mutations that were committed before this protocol.
	async fn index_appending_range(
		&self,
		ctx: &FrozenContext,
		tx: &Transaction,
		keys: Vec<Key>,
		count: &mut usize,
	) -> Result<()> {
		let mut rc = false;
		let mut stack = TreeStack::new();
		let fulltext_index =
			IndexOperation::create_fulltext_index(ctx, self.ix_key.ns, self.ix_key.db, &self.ix)
				.await?;
		for k in keys {
			if self.is_aborted().await {
				return Ok(());
			}
			self.is_beyond_threshold(Some(*count))?;
			let ig = IndexAppending::decode_key(&k)?;
			if let Some(appending) = tx.get(&ig, None).await? {
				let rid_key = self
					.apply_appending(ctx, &mut stack, &fulltext_index, appending, &mut rc)
					.await?;
				tx.del(&ig).await?;

				// We can delete the ip record if any
				let ip = self.ikb.new_ip_key(rid_key);
				tx.del(&ip).await?;
			}

			*count += 1;
		}
		// Trigger compaction if needed.
		self.check_index_compaction(tx, &mut rc).await?;
		// We're done.
		Ok(())
	}

	/// Replay durable `!bg` mutations and delete their `!bp` primary markers.
	async fn index_durable_appending_range(
		&self,
		ctx: &FrozenContext,
		tx: &Transaction,
		keys: Vec<Key>,
		count: &mut usize,
	) -> Result<()> {
		let mut rc = false;
		let mut stack = TreeStack::new();
		let fulltext_index =
			IndexOperation::create_fulltext_index(ctx, self.ix_key.ns, self.ix_key.db, &self.ix)
				.await?;
		for k in keys {
			if self.is_aborted().await {
				return Ok(());
			}
			self.is_beyond_threshold(Some(*count))?;
			let bg = Bg::decode_key(&k)?;
			if let Some(appending) = tx.get(&bg, None).await? {
				let rid_key = self
					.apply_appending(ctx, &mut stack, &fulltext_index, appending, &mut rc)
					.await?;
				tx.del(&bg).await?;
				let bp = self.ikb.new_bp_key(bg.generation, rid_key);
				tx.del(&bp).await?;
				tx.del(&self.ikb.new_br_key(bg.generation, bg.ticket)).await?;
			}
			*count += 1;
		}
		self.check_index_compaction(tx, &mut rc).await?;
		Ok(())
	}

	async fn check_index_compaction(&self, tx: &Transaction, rc: &mut bool) -> Result<()> {
		if !*rc {
			return Ok(());
		}
		IndexOperation::compaction_trigger(&self.ikb, tx, self.ctx.node_id()).await?;
		*rc = false;
		Ok(())
	}
}
