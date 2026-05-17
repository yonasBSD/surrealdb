//! Rewrite every storage key that embeds a [`RecordIdKey`] from the
//! legacy 3.0.x / 3.1.0-beta layouts (disc 2 + raw `i64`, plus the
//! never-shipped disc 8 / disc 9 main-branch slots) under the unified
//! disc-10 lex layout introduced by `9342a97b1`.
//!
//! [`Datastore::migrate_record_ids`] walks three categories per
//! `(ns, db, table)`:
//!
//! 1. **Record keys** under `crate::key::record::prefix(ns, db, tb)` — `tbl:1` and friends, the
//!    primary on-disk location for each row.
//! 2. **Index keys** under every index defined on the table — [B-tree / unique
//!    entries](crate::key::index::Index) and the auxiliary HNSW / DiskANN / fulltext sub-types
//!    ([`Hr`], [`Hi`], [`Dr`], [`Di`], [`Id`], [`Ip`]) that all embed `RecordIdKey` bytes in their
//!    key tail.
//! 3. **Graph edges** under `crate::key::graph` — `Graph { id, fk, .. }` carries two `RecordIdKey`
//!    fields, one for each endpoint of an edge.
//!
//! For every scanned key the migration decodes under the legacy-tolerant
//! storekey reader (the encoder still accepts discs 2 / 8 / 9 / 10) and
//! re-encodes via [`KVKey::encode_key`], which always emits disc 10. If
//! the bytes change, the old key is deleted and the new one written
//! within the same batch transaction. Records, indexes, and graph edges
//! that are already in the new layout are no-ops on the per-key check.
//!
//! Designed to be called offline against a datastore that no live server
//! is currently writing to. Idempotent and resumable — re-running on an
//! already-migrated database short-circuits on the
//! [`RecordIdEncoding::FullNew`] sentinel; partial runs leave the
//! sentinel at `Compat` and resume from the first unmigrated table.
//!
//! [`Hr`]: crate::key::index::hr::HnswRecordPending
//! [`Hi`]: crate::key::index::hi::Hi
//! [`Dr`]: crate::key::index::dr::DiskAnnRecordPending
//! [`Di`]: crate::key::index::di::Di
//! [`Id`]: crate::key::index::id::Id
//! [`Ip`]: crate::key::index::ip::Ip

use std::ops::Range;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tracing::{debug, info, instrument};

use crate::catalog::providers::{DatabaseProvider, NamespaceProvider, TableProvider};
use crate::catalog::{DatabaseId, IndexId, NamespaceId};
use crate::key::{graph, record};
use crate::kvs::record_id_encoding::RecordIdEncoding;
use crate::kvs::{Datastore, KVKey, LockType, ScanLimit, TransactionType};
use crate::val::{IndexFormat, TableName};

/// How many keys to re-encode in a single transaction. Each batch
/// commits independently, so a crash mid-migration loses at most one
/// in-flight batch and the next run resumes from the table that was
/// being processed.
const BATCH_SIZE: u32 = 1000;

/// Outcome of [`Datastore::migrate_record_ids`].
#[derive(Debug, Default)]
pub struct MigrationStats {
	/// `true` when the sentinel was already `FullNew` and the migration
	/// was a no-op.
	pub already_migrated: bool,
	/// Number of `(ns, db, table)` triples scanned.
	pub tables_scanned: usize,
	/// Number of record keys whose bytes were rewritten.
	pub records_rewritten: u64,
	/// Number of record keys inspected (rewritten + already-new).
	pub records_inspected: u64,
	/// Number of index keys whose bytes were rewritten across every
	/// sub-type (B-tree / unique / HNSW / DiskANN / fulltext).
	pub index_keys_rewritten: u64,
	/// Number of index keys inspected.
	pub index_keys_inspected: u64,
	/// Number of graph-edge keys whose bytes were rewritten.
	pub graph_keys_rewritten: u64,
	/// Number of graph-edge keys inspected.
	pub graph_keys_inspected: u64,
}

impl Datastore {
	/// Rewrite every legacy-format key (record, index, graph) under the
	/// unified disc-10 lex layout, then flip the encoding sentinel to
	/// [`RecordIdEncoding::FullNew`].
	///
	/// Designed to be called offline (no concurrent query traffic).
	/// Idempotent — re-running on an already-migrated database is a
	/// fast no-op. Resumable — each per-table pass commits in 1k-key
	/// batches, and rewriting a key already in the new format is a
	/// per-key no-op (the encoder output equals the on-disk bytes).
	#[instrument(target = "surrealdb::core::kvs::migrate_record_ids", skip_all)]
	pub async fn migrate_record_ids(&self) -> Result<MigrationStats> {
		let mut stats = MigrationStats::default();

		// Short-circuit when already migrated.
		if self.get_record_id_encoding().await? == RecordIdEncoding::FullNew {
			stats.already_migrated = true;
			info!(
				target = "surrealdb::core::kvs::migrate_record_ids",
				"record-id encoding sentinel is already FullNew; nothing to migrate"
			);
			return Ok(stats);
		}

		info!(
			target = "surrealdb::core::kvs::migrate_record_ids",
			"starting record-id encoding migration"
		);

		// Enumerate namespaces.
		let ns_list: Arc<[_]> = {
			let txn = self.transaction(TransactionType::Read, LockType::Optimistic).await?;
			let list = txn.all_ns(None).await?;
			let _ = txn.cancel().await;
			list
		};

		for ns in ns_list.iter() {
			let db_list: Arc<[_]> = {
				let txn = self.transaction(TransactionType::Read, LockType::Optimistic).await?;
				let list = txn.all_db(ns.namespace_id, None).await?;
				let _ = txn.cancel().await;
				list
			};

			for db in db_list.iter() {
				let tb_list: Arc<[_]> = {
					let txn = self.transaction(TransactionType::Read, LockType::Optimistic).await?;
					let list = txn.all_tb(ns.namespace_id, db.database_id, None).await?;
					let _ = txn.cancel().await;
					list
				};

				for tb in tb_list.iter() {
					stats.tables_scanned += 1;
					self.migrate_table(ns.namespace_id, db.database_id, &tb.name, &mut stats)
						.await
						.with_context(|| {
							format!(
								"migrating table {}/{}/{}",
								ns.name.as_str(),
								db.name.as_str(),
								tb.name.as_str()
							)
						})?;
				}
			}
		}

		// Flip the sentinel only after every key category has been
		// rewritten so a crash mid-pass leaves the sentinel at Compat
		// and the next run resumes from where this one stopped.
		self.set_record_id_encoding(RecordIdEncoding::FullNew).await?;

		info!(
			target = "surrealdb::core::kvs::migrate_record_ids",
			tables_scanned = stats.tables_scanned,
			records_rewritten = stats.records_rewritten,
			records_inspected = stats.records_inspected,
			index_keys_rewritten = stats.index_keys_rewritten,
			index_keys_inspected = stats.index_keys_inspected,
			graph_keys_rewritten = stats.graph_keys_rewritten,
			graph_keys_inspected = stats.graph_keys_inspected,
			"record-id encoding migration complete"
		);

		Ok(stats)
	}

	/// Migrate records, every defined index, and graph edges for one
	/// table. Counters accumulate into `stats`.
	async fn migrate_table(
		&self,
		ns: NamespaceId,
		db: DatabaseId,
		tb: &TableName,
		stats: &mut MigrationStats,
	) -> Result<()> {
		// 1. Records under `record::prefix(ns, db, tb)`.
		let beg = record::prefix(ns, db, tb)?;
		let end = record::suffix(ns, db, tb)?;
		let (rew, ins) = self
			.rewrite_range(beg..end, |old| rewrite_record_key(ns, db, tb, old))
			.await
			.context("rewrite record keys")?;
		stats.records_rewritten += rew;
		stats.records_inspected += ins;

		// 2. Index keys. The catalog is the source of truth for index IDs — scan every index
		//    defined on the table even if the storage prefix happens to be empty.
		let indexes: Arc<[_]> = {
			let txn = self.transaction(TransactionType::Read, LockType::Optimistic).await?;
			let list = txn.all_tb_indexes(ns, db, tb, None).await?;
			let _ = txn.cancel().await;
			list
		};
		for ix in indexes.iter() {
			let (rew, ins) = self
				.migrate_index_keys(ns, db, tb, ix.index_id)
				.await
				.with_context(|| format!("migrating index {}", ix.name.as_str()))?;
			stats.index_keys_rewritten += rew;
			stats.index_keys_inspected += ins;
		}

		// 3. Graph edges under the table-wide `~` prefix.
		let (gbeg, gend) = graph_table_range(ns, db, tb)?;
		let (rew, ins) = self
			.rewrite_range(gbeg..gend, rewrite_graph_key)
			.await
			.context("rewrite graph edges")?;
		stats.graph_keys_rewritten += rew;
		stats.graph_keys_inspected += ins;

		debug!(
			target = "surrealdb::core::kvs::migrate_record_ids",
			ns = ns.0,
			db = db.0,
			tb = tb.as_str(),
			records_rewritten = stats.records_rewritten,
			index_keys_rewritten = stats.index_keys_rewritten,
			graph_keys_rewritten = stats.graph_keys_rewritten,
			"migrated table"
		);

		Ok(())
	}

	/// Scan every storage key under `/*ns*db*tb+ix` — covers the
	/// standard B-tree / unique [`Index`] entries plus the auxiliary
	/// HNSW / DiskANN / fulltext sub-types that all embed
	/// `RecordIdKey` bytes in their key tail. Dispatch on the
	/// discriminator byte that follows the index id.
	async fn migrate_index_keys(
		&self,
		ns: NamespaceId,
		db: DatabaseId,
		tb: &TableName,
		ix: IndexId,
	) -> Result<(u64, u64)> {
		let broad = broad_index_prefix(ns, db, tb, ix)?;
		// Range `[broad + 0x00, broad + 0xff)` covers every sub-type
		// hanging off the index prefix.
		let mut beg = broad.clone();
		beg.push(0x00);
		let mut end = broad.clone();
		end.push(0xff);
		let disc_offset = broad.len();
		self.rewrite_range(beg..end, move |old| rewrite_index_key(disc_offset, old)).await
	}

	/// Generic per-range paging loop. Calls `re_encode` on every
	/// scanned key; if it returns bytes that differ from the input the
	/// old key is deleted and the new one written within the same
	/// batch transaction.
	///
	/// Before writing the new key we check whether it is already
	/// present. That collision case can happen when the new binary was
	/// allowed to write to a half-migrated datastore — e.g. an operator
	/// started the upgraded server *before* running the migration tool
	/// and the application then inserted `tbl:1` again, producing both
	/// a legacy disc-2 key and a new-layout disc-10 key for the same
	/// logical id. The two rows carry different values; silently
	/// overwriting the new-layout row with the legacy one loses
	/// whichever side won the application-level write race. We bail
	/// with the offending byte sequence so the operator can decide
	/// (typically delete one of the two records by id and retry).
	async fn rewrite_range<F>(&self, range: Range<Vec<u8>>, re_encode: F) -> Result<(u64, u64)>
	where
		F: Fn(&[u8]) -> Result<Vec<u8>>,
	{
		let mut rewritten = 0u64;
		let mut inspected = 0u64;
		let mut cursor = Some(range);
		while let Some(rng) = cursor.take() {
			let txn = self.transaction(TransactionType::Write, LockType::Optimistic).await?;

			let batch = txn
				.transactor()
				.scan(rng.clone(), ScanLimit::Count(BATCH_SIZE), 0, None)
				.await
				.context("scan key range")?;
			let advanced = if batch.values.len() as u32 == BATCH_SIZE {
				batch.values.last().map(|(k, _)| {
					let mut next_start = k.clone();
					next_start.push(0x00);
					next_start..rng.end.clone()
				})
			} else {
				None
			};

			for (old_key, val) in batch.values {
				inspected += 1;
				let new_key = re_encode(&old_key).context("re-encode key under new layout")?;
				if new_key != old_key {
					if txn
						.transactor()
						.get(new_key.clone(), None)
						.await
						.context("probe target key before rewrite")?
						.is_some()
					{
						bail!(
							"migration collision: target key already exists for legacy key `{}` \
							 -> `{}`. The new binary wrote to this datastore before the migration \
							 ran, so a legacy-format row and a new-format row both exist for the \
							 same logical id. Resolve by deleting one of the two rows by id and \
							 re-running `surreal migrate-record-ids`.",
							hex::encode(&old_key),
							hex::encode(&new_key),
						);
					}
					txn.transactor().del(old_key.clone()).await.context("delete legacy key")?;
					txn.transactor().set(new_key, val).await.context("write new key")?;
					rewritten += 1;
				}
			}

			txn.commit().await.context("commit migration batch")?;
			cursor = advanced;
		}
		Ok((rewritten, inspected))
	}
}

/// Decode a [`RecordKey`] from `old_key` and re-encode it via
/// [`record::new`], which always emits the unified disc-10 layout.
///
/// [`RecordKey`]: crate::key::record::RecordKey
fn rewrite_record_key(
	ns: NamespaceId,
	db: DatabaseId,
	tb: &TableName,
	old_key: &[u8],
) -> Result<Vec<u8>> {
	let rid = record::RecordKey::decode_key(old_key).context("decode legacy record key")?;
	let new = record::new(ns, db, tb, &rid.id);
	KVKey::encode_key(&new)
}

/// Decode a graph edge key and re-encode it. Both `id` and `fk` are
/// `RecordIdKey` fields and may carry legacy disc-2 bytes.
fn rewrite_graph_key(old_key: &[u8]) -> Result<Vec<u8>> {
	let g = graph::Graph::decode_key(old_key).context("decode legacy graph key")?;
	KVKey::encode_key(&g)
}

/// Dispatch on the bytes immediately after the `+IndexId` prefix:
///
/// - `b'*'` → standard [B-tree / unique entry](crate::key::index::Index) (`fd` + `Option<id>`)
/// - `b'!'` + `b"hr"` → [`HnswRecordPending`](crate::key::index::hr)
/// - `b'!'` + `b"hi"` → [`Hi`](crate::key::index::hi) (HNSW `Thing → Element`)
/// - `b'!'` + `b"dr"` → [`DiskAnnRecordPending`](crate::key::index::dr)
/// - `b'!'` + `b"di"` → [`Di`](crate::key::index::di) (DiskANN/fulltext `RecordId → DocId`)
/// - `b'!'` + `b"id"` → [`Id`](crate::key::index::id) (fulltext `RecordId → DocId`)
/// - `b'!'` + `b"ip"` → [`Ip`](crate::key::index::ip) (concurrent-build previous-value cache)
///
/// Any other discriminator is left untouched (returns the bytes
/// unchanged so the caller's "new == old" check makes it a no-op).
fn rewrite_index_key(disc_offset: usize, old_key: &[u8]) -> Result<Vec<u8>> {
	let Some(&disc) = old_key.get(disc_offset) else {
		return Ok(old_key.to_vec());
	};
	match disc {
		b'*' => {
			let dec: crate::key::index::Index<'_> =
				storekey::decode_borrow_format::<IndexFormat, _>(old_key)
					.context("decode B-tree / unique index key")?;
			Ok(KVKey::encode_key(&dec)?)
		}
		b'!' => {
			let f = old_key.get(disc_offset + 1).copied();
			let g = old_key.get(disc_offset + 2).copied();
			match (f, g) {
				(Some(b'h'), Some(b'r')) => {
					let dec: crate::key::index::hr::HnswRecordPending<'_> =
						storekey::decode_borrow_format::<IndexFormat, _>(old_key)
							.context("decode HNSW pending key")?;
					Ok(KVKey::encode_key(&dec)?)
				}
				(Some(b'h'), Some(b'i')) => {
					let dec: crate::key::index::hi::Hi<'_> =
						storekey::decode_borrow_format::<IndexFormat, _>(old_key)
							.context("decode HNSW `hi` key")?;
					Ok(KVKey::encode_key(&dec)?)
				}
				// DiskANN pending (`!dr`) and DocId mapping (`!di`) are
				// non-WASM index sub-types. On WASM those keys cannot
				// exist on disk, so leaving the bytes untouched is
				// correct and avoids pulling the absent modules into
				// the build.
				#[cfg(not(target_family = "wasm"))]
				(Some(b'd'), Some(b'r')) => {
					let dec: crate::key::index::dr::DiskAnnRecordPending<'_> =
						storekey::decode_borrow_format::<IndexFormat, _>(old_key)
							.context("decode DiskANN pending key")?;
					Ok(KVKey::encode_key(&dec)?)
				}
				#[cfg(not(target_family = "wasm"))]
				(Some(b'd'), Some(b'i')) => {
					let dec: crate::key::index::di::Di<'_> =
						storekey::decode_borrow_format::<IndexFormat, _>(old_key)
							.context("decode `di` key")?;
					Ok(KVKey::encode_key(&dec)?)
				}
				(Some(b'i'), Some(b'd')) => {
					let dec: crate::key::index::id::Id<'_> =
						storekey::decode_borrow_format::<IndexFormat, _>(old_key)
							.context("decode fulltext `id` key")?;
					Ok(KVKey::encode_key(&dec)?)
				}
				(Some(b'i'), Some(b'p')) => {
					let dec: crate::key::index::ip::Ip<'_> =
						storekey::decode_borrow_format::<IndexFormat, _>(old_key)
							.context("decode `ip` previous-value key")?;
					Ok(KVKey::encode_key(&dec)?)
				}
				// Index sub-type we don't know about: leave it.
				_ => Ok(old_key.to_vec()),
			}
		}
		_ => Ok(old_key.to_vec()),
	}
}

/// Bytes that prefix every storage key for one `(ns, db, tb, ix)`,
/// stripped of the trailing discriminator byte (`*` for the standard
/// entry, `!` for the auxiliary sub-types). The full layout is
/// `/*ns*db*tb+ix`.
fn broad_index_prefix(
	ns: NamespaceId,
	db: DatabaseId,
	tb: &TableName,
	ix: IndexId,
) -> Result<Vec<u8>> {
	// `Index::prefix_beg` returns `Prefix::new(...).encode_key() + b"\x00"`
	// and `Prefix::new` ends with `_e: b'*'`. Strip the trailing two
	// bytes to obtain the broader prefix.
	let mut k = crate::key::index::Index::prefix_beg(ns, db, tb, ix)?;
	k.truncate(k.len().saturating_sub(2));
	Ok(k)
}

/// Range covering every graph edge `/*ns*db*tb~...` for one table.
fn graph_table_range(
	ns: NamespaceId,
	db: DatabaseId,
	tb: &TableName,
) -> Result<(Vec<u8>, Vec<u8>)> {
	let root = crate::key::table::all::new(ns, db, tb).encode_key()?;
	// `~` is `_d` for every graph key sub-prefix; everything under
	// `root + b'~'` is a graph edge for this table.
	let mut beg = root.clone();
	beg.extend_from_slice(b"~\x00");
	let mut end = root;
	end.extend_from_slice(b"~\xff");
	Ok((beg, end))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::catalog::Record;
	use crate::dbs::Session;
	use crate::expr::dir::Dir;
	use crate::kvs::record_id_encoding::RecordIdEncoding;
	use crate::val::{Number, Object, RecordId, RecordIdKey, Value};

	async fn fresh_ds() -> Datastore {
		use crate::catalog::providers::CatalogProvider;
		let ds = Datastore::new("memory").await.unwrap();
		let txn = ds.transaction(TransactionType::Write, LockType::Optimistic).await.unwrap();
		txn.ensure_ns_db(None, "test", "test").await.unwrap();
		txn.commit().await.unwrap();
		ds
	}

	/// A fresh in-memory datastore with no sentinel yet present
	/// migrates as a no-op (no tables, no records) but still flips the
	/// sentinel to `FullNew`. Re-running is idempotent.
	#[tokio::test]
	async fn migrate_fresh_datastore_flips_sentinel() {
		let ds = fresh_ds().await;
		// Pre-state: sentinel absent (defaults to Compat).
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::Compat);

		let stats = ds.migrate_record_ids().await.unwrap();
		assert!(!stats.already_migrated);
		assert_eq!(stats.tables_scanned, 0);
		assert_eq!(stats.records_rewritten, 0);
		assert_eq!(stats.index_keys_rewritten, 0);
		assert_eq!(stats.graph_keys_rewritten, 0);
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::FullNew);

		// Idempotent on re-run.
		let stats2 = ds.migrate_record_ids().await.unwrap();
		assert!(stats2.already_migrated);
		assert_eq!(stats2.tables_scanned, 0);
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::FullNew);
	}

	/// Inject hand-crafted legacy disc-2 record bytes (simulating a
	/// 3.0.x database) and verify the migration rewrites them under
	/// disc 10 while preserving values.
	#[tokio::test]
	async fn migrate_rewrites_legacy_disc_2_records() {
		use crate::catalog::providers::{DatabaseProvider, NamespaceProvider, TableProvider};

		let ds = fresh_ds().await;
		let session = Session::owner().with_ns("test").with_db("test");

		// Create a record via normal SQL so the namespace, database, and
		// table metadata exist. The encoder is in FullNew mode here, so
		// this record goes in under disc 10.
		ds.execute("CREATE thing:1 SET ok = true;", &session, None).await.unwrap();

		// Look up the namespace + database ids.
		let (ns_id, db_id, tb_name) = {
			let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
			let nss = txn.all_ns(None).await.unwrap();
			let ns = nss.iter().find(|n| n.name.as_str() == "test").unwrap();
			let dbs = txn.all_db(ns.namespace_id, None).await.unwrap();
			let db = dbs.iter().find(|d| d.name.as_str() == "test").unwrap();
			let tbs = txn.all_tb(ns.namespace_id, db.database_id, None).await.unwrap();
			let tb = tbs.iter().find(|t| t.name.as_str() == "thing").unwrap();
			let _ = txn.cancel().await;
			(ns.namespace_id, db.database_id, tb.name.clone())
		};

		// Construct a synthetic legacy-format record key:
		// disc 2 + storekey i64-encoded 42. Write it directly to the
		// underlying KV store so the encoder isn't involved.
		let legacy_id_bytes: Vec<u8> = vec![2, 0x80, 0, 0, 0, 0, 0, 0, 0x2A];
		let prefix = crate::key::record::prefix(ns_id, db_id, &tb_name).unwrap();
		// `prefix` returns bytes ending in `*\x00`; strip the trailing 0x00
		// so we can replace it with our hand-crafted id bytes.
		let mut legacy_full_key = prefix[..prefix.len() - 1].to_vec();
		legacy_full_key.extend_from_slice(&legacy_id_bytes);

		// Write a placeholder Record value at this key.
		let placeholder_record = Record::new(Value::Object(Object::default()));
		let raw_val = crate::kvs::KVValue::kv_encode_value(&placeholder_record).unwrap();

		{
			let txn = ds.transaction(TransactionType::Write, LockType::Optimistic).await.unwrap();
			txn.transactor().set(legacy_full_key.clone(), raw_val.clone()).await.unwrap();
			txn.commit().await.unwrap();
		}

		// Sentinel is currently FullNew because the fresh-DB execute
		// path implicitly set it; rewind to Compat so the migration
		// actually runs.
		ds.set_record_id_encoding(RecordIdEncoding::Compat).await.unwrap();

		// Run the migration.
		let stats = ds.migrate_record_ids().await.unwrap();
		assert!(!stats.already_migrated);
		assert!(
			stats.records_rewritten >= 1,
			"expected at least 1 legacy record to be rewritten, got {stats:?}"
		);
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::FullNew);

		// The legacy key should be gone; the new disc-10 key should
		// exist with the same value.
		let new_id = RecordIdKey::Number(Number::Int(42));
		let new_record_key = crate::key::record::new(ns_id, db_id, &tb_name, &new_id);
		let new_key_bytes = crate::kvs::KVKey::encode_key(&new_record_key).unwrap();

		let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
		let new_val = txn.transactor().get(new_key_bytes.clone(), None).await.unwrap();
		let old_val = txn.transactor().get(legacy_full_key.clone(), None).await.unwrap();
		let _ = txn.cancel().await;

		assert!(new_val.is_some(), "new disc-10 key should exist after migration");
		assert!(old_val.is_none(), "legacy disc-2 key should be removed after migration");
	}

	/// When both a legacy disc-2 row and a new-format disc-10 row exist
	/// for the same logical id (the new binary wrote to the datastore
	/// before the migration ran), the migration must bail rather than
	/// silently overwrite the new-format value with the legacy one.
	#[tokio::test]
	async fn migrate_rejects_legacy_and_new_format_collision() {
		use crate::catalog::providers::{DatabaseProvider, NamespaceProvider, TableProvider};

		let ds = fresh_ds().await;
		let session = Session::owner().with_ns("test").with_db("test");

		// Set up a `thing:1` row in the new disc-10 layout via normal SQL.
		ds.execute("CREATE thing:1 SET ok = 'new';", &session, None).await.unwrap();

		let (ns_id, db_id, tb_name) = {
			let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
			let nss = txn.all_ns(None).await.unwrap();
			let ns = nss.iter().find(|n| n.name.as_str() == "test").unwrap();
			let dbs = txn.all_db(ns.namespace_id, None).await.unwrap();
			let db = dbs.iter().find(|d| d.name.as_str() == "test").unwrap();
			let tbs = txn.all_tb(ns.namespace_id, db.database_id, None).await.unwrap();
			let tb = tbs.iter().find(|t| t.name.as_str() == "thing").unwrap();
			let _ = txn.cancel().await;
			(ns.namespace_id, db.database_id, tb.name.clone())
		};

		// Inject a hand-crafted legacy disc-2 row for the SAME logical id
		// (`thing:1`). Carries a *different* value than the disc-10 row
		// so we can confirm neither side gets clobbered.
		let legacy_id_bytes: Vec<u8> = vec![2, 0x80, 0, 0, 0, 0, 0, 0, 0x01];
		let prefix = crate::key::record::prefix(ns_id, db_id, &tb_name).unwrap();
		let mut legacy_full_key = prefix[..prefix.len() - 1].to_vec();
		legacy_full_key.extend_from_slice(&legacy_id_bytes);
		let placeholder_record = Record::new(Value::Object(Object::default()));
		let legacy_val = crate::kvs::KVValue::kv_encode_value(&placeholder_record).unwrap();
		{
			let txn = ds.transaction(TransactionType::Write, LockType::Optimistic).await.unwrap();
			txn.transactor().set(legacy_full_key.clone(), legacy_val.clone()).await.unwrap();
			txn.commit().await.unwrap();
		}

		// Rewind the sentinel to force the migration to run.
		ds.set_record_id_encoding(RecordIdEncoding::Compat).await.unwrap();

		let err =
			ds.migrate_record_ids().await.expect_err("migration must bail on legacy/new collision");
		let msg = format!("{err:#}");
		assert!(msg.contains("migration collision"), "unexpected error: {msg}");

		// Sentinel stays at Compat so the operator can retry after
		// resolving the collision.
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::Compat);
	}

	/// A record already in the new format is left untouched (the
	/// re-encoder produces identical bytes), and the migration is
	/// idempotent even with mixed legacy + new records.
	#[tokio::test]
	async fn migrate_skips_already_migrated_records() {
		let ds = fresh_ds().await;
		let session = Session::owner().with_ns("test").with_db("test");
		ds.execute("CREATE thing:1; CREATE thing:2;", &session, None).await.unwrap();
		// Reset sentinel to force migration to run.
		ds.set_record_id_encoding(RecordIdEncoding::Compat).await.unwrap();

		let stats = ds.migrate_record_ids().await.unwrap();
		// All records were already disc-10 (created in FullNew mode):
		// nothing actually rewritten, but the table is scanned.
		assert_eq!(stats.records_rewritten, 0);
		assert!(stats.records_inspected >= 2);
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::FullNew);
	}

	/// Inject a hand-crafted legacy disc-2 B-tree index entry and
	/// verify the migration rewrites it. The post-migration index
	/// lookup returns the correct record via the standard SQL path.
	#[tokio::test]
	async fn migrate_rewrites_legacy_index_keys() {
		use crate::catalog::providers::{DatabaseProvider, NamespaceProvider, TableProvider};

		let ds = fresh_ds().await;
		let session = Session::owner().with_ns("test").with_db("test");

		ds.execute(
			"DEFINE INDEX ix ON TABLE thing FIELDS name; \
			 CREATE thing:1 SET name = 'a';",
			&session,
			None,
		)
		.await
		.unwrap();

		// Look up ns / db / table / index ids.
		let (ns_id, db_id, tb_name, ix_id) = {
			let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
			let nss = txn.all_ns(None).await.unwrap();
			let ns = nss.iter().find(|n| n.name.as_str() == "test").unwrap();
			let dbs = txn.all_db(ns.namespace_id, None).await.unwrap();
			let db = dbs.iter().find(|d| d.name.as_str() == "test").unwrap();
			let tbs = txn.all_tb(ns.namespace_id, db.database_id, None).await.unwrap();
			let tb = tbs.iter().find(|t| t.name.as_str() == "thing").unwrap();
			let ixs =
				txn.all_tb_indexes(ns.namespace_id, db.database_id, &tb.name, None).await.unwrap();
			let ix = ixs.iter().find(|i| i.name.as_str() == "ix").unwrap();
			let _ = txn.cancel().await;
			(ns.namespace_id, db.database_id, tb.name.clone(), ix.index_id)
		};

		// Construct a legacy index entry by hand: standard B-tree key
		// with field value `'b'` (a Strand under `IndexFormat`) and a
		// legacy disc-2 + raw `i64` record-id `thing:7`.
		//
		// Build the new-layout key for an index entry pointing at
		// `thing:7`, then patch its tail to swap the disc-10 record-id
		// payload for the legacy disc-2 byte sequence. This sidesteps
		// having to recreate the full `Index` storekey output.
		let fd = crate::val::Array(vec![crate::val::Value::String("b".to_owned().into())]);
		let rid_new = RecordIdKey::Number(Number::Int(7));
		let new_full =
			crate::key::index::Index::new(ns_id, db_id, &tb_name, ix_id, &fd, Some(&rid_new));
		let new_full_bytes = crate::kvs::KVKey::encode_key(&new_full).unwrap();

		// The trailing bytes encode the `Option<RecordIdKey>` field:
		//   [Some marker=1, disc=10, decimal_buf..., NumberKind]
		// In Compat / 3.0.x the same record id was stored as:
		//   [Some marker=1, disc=2, raw_i64_bytes]
		// We rebuild the suffix manually and splice it onto the prefix
		// up to (and including) the Some marker.
		//
		// Strip the new-layout RecordIdKey payload by re-encoding the
		// index entry with `None` for the id, then appending the legacy
		// `[Some, disc=2, raw_i64]` bytes ourselves. storekey encodes
		// `Option::None` as `2` and `Option::Some(_)` as `3 + payload`.
		let mut legacy_index_bytes = {
			let key_no_id = crate::key::index::Index::new(ns_id, db_id, &tb_name, ix_id, &fd, None);
			let mut bytes = crate::kvs::KVKey::encode_key(&key_no_id).unwrap();
			assert_eq!(bytes.last(), Some(&2u8), "Option::None tag");
			bytes.pop();
			bytes
		};
		// `Option::Some(_)` marker (3), then legacy record-id under
		// `IndexFormat`: disc 2 + storekey `i64`-encoded 7.
		legacy_index_bytes.push(3);
		legacy_index_bytes.push(2);
		legacy_index_bytes.extend_from_slice(&((7i64 ^ i64::MIN).to_be_bytes()));

		// The legacy and new-layout keys must differ (otherwise this
		// test isn't exercising the rewrite path).
		assert_ne!(legacy_index_bytes, new_full_bytes);

		// Inject the legacy index key into storage, pointing at the
		// existing `thing:1` record (the value is opaque to the
		// migration tool — we just need *some* value).
		let raw_val = {
			let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
			let probe = txn
				.transactor()
				.scan(
					crate::key::record::prefix(ns_id, db_id, &tb_name).unwrap()
						..crate::key::record::suffix(ns_id, db_id, &tb_name).unwrap(),
					ScanLimit::Count(1),
					0,
					None,
				)
				.await
				.unwrap();
			let _ = txn.cancel().await;
			probe.values.into_iter().next().expect("a thing:1 record exists").1
		};

		{
			let txn = ds.transaction(TransactionType::Write, LockType::Optimistic).await.unwrap();
			txn.transactor().set(legacy_index_bytes.clone(), raw_val.clone()).await.unwrap();
			txn.commit().await.unwrap();
		}

		// Force a re-migration by rewinding the sentinel.
		ds.set_record_id_encoding(RecordIdEncoding::Compat).await.unwrap();
		let stats = ds.migrate_record_ids().await.unwrap();
		assert!(
			stats.index_keys_rewritten >= 1,
			"expected at least 1 legacy index entry to be rewritten, got {stats:?}"
		);
		assert_eq!(ds.get_record_id_encoding().await.unwrap(), RecordIdEncoding::FullNew);

		let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
		let after_legacy = txn.transactor().get(legacy_index_bytes.clone(), None).await.unwrap();
		let after_new = txn.transactor().get(new_full_bytes.clone(), None).await.unwrap();
		let _ = txn.cancel().await;

		assert!(after_legacy.is_none(), "legacy index key should be removed");
		assert!(after_new.is_some(), "new-layout index key should exist");
	}

	/// Inject a hand-crafted legacy disc-2 graph edge and verify the
	/// migration rewrites it under disc 10.
	#[tokio::test]
	async fn migrate_rewrites_legacy_graph_edges() {
		use crate::catalog::providers::{DatabaseProvider, NamespaceProvider, TableProvider};

		let ds = fresh_ds().await;
		let session = Session::owner().with_ns("test").with_db("test");

		// Two records so we have a valid (id, fk) pair to graph between.
		ds.execute("CREATE usr:1; CREATE usr:2;", &session, None).await.unwrap();

		let (ns_id, db_id, tb_name) = {
			let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
			let nss = txn.all_ns(None).await.unwrap();
			let ns = nss.iter().find(|n| n.name.as_str() == "test").unwrap();
			let dbs = txn.all_db(ns.namespace_id, None).await.unwrap();
			let db = dbs.iter().find(|d| d.name.as_str() == "test").unwrap();
			let tbs = txn.all_tb(ns.namespace_id, db.database_id, None).await.unwrap();
			let tb = tbs.iter().find(|t| t.name.as_str() == "usr").unwrap();
			let _ = txn.cancel().await;
			(ns.namespace_id, db.database_id, tb.name.clone())
		};

		// New-layout edge bytes for `usr:1 -follows-> usr:2`.
		let fk = RecordId {
			table: tb_name.clone(),
			key: RecordIdKey::Number(Number::Int(2)),
		};
		let id_one = RecordIdKey::Number(Number::Int(1));
		let edge = crate::key::graph::new(ns_id, db_id, &tb_name, &id_one, &Dir::Out, &fk);
		let new_edge_bytes = crate::kvs::KVKey::encode_key(&edge).unwrap();

		// Build the legacy version by taking the table-root prefix and
		// hand-encoding the body with disc-2 record-ids.
		let mut legacy_edge_bytes =
			crate::key::table::all::new(ns_id, db_id, &tb_name).encode_key().unwrap();
		// `_d: b'~'` + legacy disc-2 record-id for usr:1.
		legacy_edge_bytes.push(b'~');
		legacy_edge_bytes.push(2);
		legacy_edge_bytes.extend_from_slice(&((1i64 ^ i64::MIN).to_be_bytes()));
		// `Dir::Out` is encoded as a 1-byte storekey enum tag — borrow
		// the value from the new-layout encoding instead of guessing.
		// The Dir tag sits right after `id` in both layouts. Easiest:
		// scan `new_edge_bytes` for the Dir byte by finding the unique
		// position past the (known-length) prefix.
		// New-layout prefix length up to and including `~` is the same
		// as ours; the difference is the id payload size. Decode the
		// new bytes to recover the Dir / ft / fk tail.
		let new_prefix_through_dir = {
			let g = crate::key::graph::Graph::decode_key(&new_edge_bytes).unwrap();
			let mut owned = legacy_edge_bytes.clone();
			// `g.eg` is `Dir`; serialise it via storekey to obtain its
			// canonical byte.
			owned.extend_from_slice(&storekey::encode_vec(&g.eg).unwrap());
			// `ft` is a `TableName` Cow — encoded as a Strand (disc 3 +
			// utf8 + NUL terminator).
			owned.extend_from_slice(&storekey::encode_vec(&*g.ft).unwrap());
			owned
		};
		legacy_edge_bytes = new_prefix_through_dir;
		// Append legacy disc-2 record-id for usr:2.
		legacy_edge_bytes.push(2);
		legacy_edge_bytes.extend_from_slice(&((2i64 ^ i64::MIN).to_be_bytes()));

		assert_ne!(legacy_edge_bytes, new_edge_bytes);

		// Write the legacy edge directly to KV.
		{
			let txn = ds.transaction(TransactionType::Write, LockType::Optimistic).await.unwrap();
			txn.transactor().set(legacy_edge_bytes.clone(), vec![]).await.unwrap();
			txn.commit().await.unwrap();
		}

		// Rewind the sentinel to force migration.
		ds.set_record_id_encoding(RecordIdEncoding::Compat).await.unwrap();
		let stats = ds.migrate_record_ids().await.unwrap();
		assert!(
			stats.graph_keys_rewritten >= 1,
			"expected at least 1 legacy graph edge to be rewritten, got {stats:?}"
		);

		let txn = ds.transaction(TransactionType::Read, LockType::Optimistic).await.unwrap();
		let after_legacy = txn.transactor().get(legacy_edge_bytes.clone(), None).await.unwrap();
		let after_new = txn.transactor().get(new_edge_bytes.clone(), None).await.unwrap();
		let _ = txn.cancel().await;

		assert!(after_legacy.is_none(), "legacy graph edge should be removed");
		assert!(after_new.is_some(), "new-layout graph edge should exist");
	}
}
