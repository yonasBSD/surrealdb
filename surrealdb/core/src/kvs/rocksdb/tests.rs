//! Tests for RocksDB SST file manager feature
//!
//! This module tests the SST file manager space monitoring feature that:
//! - Limits disk space usage for SST files via the `SURREAL_ROCKSDB_SST_MAX_ALLOWED_SPACE_USAGE`
//!   environment variable
//! - Transitions to read-and-deletion-only mode when the space limit is reached
//! - Allows read and delete operations during read-and-deletion-only mode (but blocks writes)
//! - Automatically recovers to normal mode when space drops below the limit after deletions and
//!   compaction

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use temp_dir::TempDir;

use crate::CommunityComposer;
use crate::cnf::ConfigMap;
use crate::kvs::Datastore;
use crate::kvs::LockType::Optimistic;
use crate::kvs::TransactionType::*;

#[tokio::test]
pub async fn read_and_deletion_only() {
	// This test demonstrates the read-and-deletion-only mode behavior.
	// When SURREAL_ROCKSDB_SST_MAX_ALLOWED_SPACE_USAGE is set, the datastore transitions
	// to read-and-deletion-only mode when SST file space usage reaches the configured limit.
	//
	// State Machine:
	// Normal -> ReadAndDeletionOnly (when SST space usage reaches the configured limit)
	// ReadAndDeletionOnly -> Normal (when space usage drops below the limit after deletions)
	//
	// In ReadAndDeletionOnly mode:
	// - Read operations are allowed
	// - Delete operations are allowed (to free up space)
	// - Write operations return kvs::Error::ReadAndDeleteOnly
	// - The error message indicates that deleting data will free space
	// - When space drops below the limit (after deletions and compaction), normal mode is restored

	// Required environment variables for this test:
	// - SURREAL_ROCKSDB_SST_MAX_ALLOWED_SPACE_USAGE = 10485760 (10MB space limit)
	// - SURREAL_ROCKSDB_WRITE_BUFFER_SIZE = 10240 (controls flush frequency)
	// - SURREAL_ROCKSDB_WAL_SIZE_LIMIT = 1 (forces frequent WAL flushes)

	// Create datastore (read-and-deletion-only mode is triggered by environment variables)
	let config = ConfigMap::empty()
		.with_key_value("rocksdb_sst_max_allowed_space_usage", "10485760")
		.with_key_value("rocksdb_write_buffer_size", "10240")
		.with_key_value("rocksdb_wal_size_limit", "1");

	let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
	let path = format!("rocksdb:{path}");

	// Setup the RocksDB datastore
	let ds = Datastore::builder()
		.with_config(config)
		.build_with_factory_path(&path, CommunityComposer())
		.await
		.unwrap();

	// Phase 1: Initial writes in normal mode (before reaching space limit)
	{
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.set(&"initial_key", &"initial_value".as_bytes().to_vec()).await.unwrap();
		tx.commit().await.unwrap();
	}

	// Start a transaction that will be left uncommitted until after mode transition
	let ongoing_tx = ds.transaction(Write, Optimistic).await.unwrap();
	ongoing_tx.set(&"ongoing_key", &"ongoing_value".as_bytes().to_vec()).await.unwrap();

	// Phase 2: Write data until space limit is reached and mode transitions to
	// read-and-deletion-only Write ~20MB of data (200 transactions × 100 keys × 1KB each)
	// Some transactions will succeed before the limit, then failures will occur after transition.
	//
	// Values are filled from a deterministic PRNG so they are effectively
	// incompressible: otherwise any per-level compression (e.g. Lz4/Zstd) would
	// shrink a zero-filled payload far below the configured SST limit and the
	// read-and-deletion-only transition would never fire.
	let mut rng = StdRng::seed_from_u64(0xA5A5_A5A5_A5A5_A5A5);
	let mut count_err = 0;
	for j in 0..200 {
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		for i in 0..100 {
			let key = format!("unlimited_key_{}_{}", i, j);
			let mut value = vec![0u8; 1024]; // 1KB per value
			rng.fill_bytes(&mut value);
			if let Err(e) = tx.set(&key, &value).await {
				assert!(
					e.to_string().contains("read-and-deletion-only mode"),
					"Unexpected error: {e}"
				);
				count_err += 1;
			}
		}
		if let Err(e) = tx.commit().await {
			assert!(e.to_string().contains("read-and-deletion-only mode"), "Unexpected error: {e}");
			count_err += 1;
		}
	}
	// Verify that mode transition occurred (expect significant number of errors)
	assert!(count_err > 50, "Count error: {}", count_err);

	// Phase 3: Verify behavior in read-and-deletion-only mode

	// Confirm new write transactions are blocked
	{
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		let res = tx.put(&"other_key", &"other_value".as_bytes().to_vec()).await;
		assert!(
			res.unwrap_err().to_string().contains("read-and-deletion-only mode"),
			"Expected read-and-deletion-only error"
		);
		tx.cancel().await.unwrap();
	}

	// Confirm pre-existing uncommitted transaction is rejected on commit
	{
		let res = ongoing_tx.commit().await;
		assert!(
			res.unwrap_err().to_string().contains("read-and-deletion-only mode"),
			"Expected read-and-deletion-only error"
		);
	}

	// Confirm read operations still work
	{
		let tx = ds.transaction(Read, Optimistic).await.unwrap();
		let val = tx.get(&"initial_key", None).await.unwrap();
		assert!(matches!(val.as_deref(), Some(b"initial_value")));
		tx.cancel().await.unwrap();
	}

	// Phase 4: Delete data to free space and trigger recovery to normal mode
	// Delete all keys that were successfully written (this frees space below the limit)
	for j in 0..200 {
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		for i in 0..100 {
			let key = format!("unlimited_key_{}_{}", i, j);
			tx.del(&key).await.unwrap();
		}
		tx.commit().await.unwrap();
	}

	// Phase 5: Verify recovery to normal mode
	// Confirm writes are allowed again after space usage drops below limit
	{
		let tx = ds.transaction(Write, Optimistic).await.unwrap();
		tx.put(&"other_key", &"other_value".as_bytes().to_vec()).await.unwrap();
		tx.commit().await.unwrap();
	}
}

/// Verifies that the memory manager clamps `min_write_buffer_number_to_merge`
/// against `max_write_buffer_number`. Without the clamp, setting
/// `min_write_buffer_number_to_merge > max_write_buffer_number` (for example
/// when an operator lowers `max_write_buffer_number=1` alongside the default
/// merge-of-2) causes RocksDB to wait indefinitely for a memtable merge that
/// can never happen, stalling every writer.
///
/// With the clamp in place the datastore must open cleanly and a write +
/// commit must succeed within a short budget; if the clamp regresses the
/// commit here will hang until the test timeout fires.
#[tokio::test(flavor = "multi_thread")]
async fn memtable_merge_count_clamp_non_versioned() {
	memtable_merge_count_clamp_inner(false).await;
}

/// Same invariant as `memtable_merge_count_clamp_non_versioned`, but with
/// versioning enabled so the default column family is opened through an
/// explicit `ColumnFamilyDescriptor`. Exercises the versioned open path
/// (`apply_cf_level_options` + `MemoryManager::apply_to_cf_options` on the
/// CF descriptor's `Options`) to confirm it runs cleanly end-to-end with a
/// misconfigured memtable setup.
#[tokio::test(flavor = "multi_thread")]
async fn memtable_merge_count_clamp_versioned() {
	memtable_merge_count_clamp_inner(true).await;
}

async fn memtable_merge_count_clamp_inner(versioned: bool) {
	// Configure a deliberately misconfigured memtable setup: the merge
	// target (2) exceeds the maximum number of memtables (1). Without
	// the clamp this would stall writers indefinitely.
	let mut config = ConfigMap::empty()
		.with_key_value("rocksdb_max_write_buffer_number", "1")
		.with_key_value("rocksdb_min_write_buffer_number_to_merge", "2");
	if versioned {
		config = config.with_key_value("datastore_versioned", "true");
	}

	let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
	let path = format!("rocksdb:{path}");

	let ds = Datastore::builder()
		.with_config(config)
		.build_with_factory_path(&path, CommunityComposer())
		.await
		.unwrap();

	// A successful write + commit within the timeout proves the clamp
	// ran and was applied to whichever CF RocksDB ended up using (the
	// implicit default for the non-versioned case, or the explicit
	// `ColumnFamilyDescriptor` for the versioned case).
	let tx = ds.transaction(Write, Optimistic).await.unwrap();
	tx.set(&"clamp_key", &"clamp_value".as_bytes().to_vec()).await.unwrap();
	tokio::time::timeout(std::time::Duration::from_secs(10), tx.commit())
		.await
		.expect("commit stalled: min_write_buffer_number_to_merge clamp regressed")
		.unwrap();
}

/// Sanity-check that `ALTER SYSTEM COMPACT` (which routes through
/// `Datastore::compact`) pushes all live data to the bottommost level and
/// drains the upper levels.
///
/// We construct the underlying RocksDB datastore directly so we can read
/// `rocksdb.num-files-at-levelN` for every level via `property_int_value`
/// and assert that L0–L5 are empty and L6 carries the SSTs after the
/// compaction completes.
#[tokio::test(flavor = "multi_thread")]
async fn compact_pushes_data_to_bottommost() {
	use rand::rngs::StdRng;
	use rand::{RngCore, SeedableRng};

	use crate::kvs::api::Transactable;
	use crate::kvs::rocksdb::{Datastore as RocksDbDatastore, RocksDbConfig};

	// Write enough deterministically-random data that compaction has at
	// least one SST to move. The values are random so per-level
	// compression cannot collapse the dataset to nothing.
	let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
	// Tiny SSTs so we exercise multi-level promotion even on a small
	// dataset; the bottommost-target assertion below is the invariant
	// under test, not the absolute file count.
	let config = RocksDbConfig {
		target_file_size_base: 64 * 1024,
		write_buffer_size: 64 * 1024,
		..RocksDbConfig::default()
	};

	let ds = RocksDbDatastore::new(&path, config).await.unwrap();

	// Drive a few dozen small commits so the WAL → memtable → L0 path
	// produces multiple SSTs before we compact.
	let mut rng = StdRng::seed_from_u64(0xC0FF_EEC0_FFEE_u64);
	for batch in 0..32u32 {
		let tx = ds.transaction(true, true).await.unwrap();
		for i in 0..32u32 {
			let key: Vec<u8> = format!("bottommost_test_{batch:04}_{i:04}").into_bytes();
			let mut value = vec![0u8; 256];
			rng.fill_bytes(&mut value);
			tx.set(key, value).await.unwrap();
		}
		tx.commit().await.unwrap();
	}

	// Run the manual compaction. `None` range covers the full keyspace.
	// `compact` is on the `Transactable` impl for `Transaction`, so spin up
	// a short-lived transaction just to dispatch it.
	{
		let tx = ds.transaction(false, true).await.unwrap();
		Transactable::compact(tx.as_ref(), None).await.unwrap();
		tx.cancel().await.unwrap();
	}

	// `num-files-at-levelN` is a per-CF integer property. The default CF
	// is what every Transactable scan touches.
	let level_file_count = |level: usize| -> u64 {
		let name = format!("rocksdb.num-files-at-level{level}");
		ds.db.property_int_value(&name).unwrap_or_default().unwrap_or_default()
	};

	for level in 0..6 {
		let n = level_file_count(level);
		assert_eq!(n, 0, "expected level {level} to be empty after compact, got {n} files");
	}
	let bottom = level_file_count(6);
	assert!(bottom > 0, "expected bottommost level (L6) to carry SSTs, got 0");
}

/// Sanity-check that `rocksdb_periodic_compaction_seconds` is wired into
/// the column-family options without crashing the open path.
///
/// The behavioural property (compactions actually firing after N seconds)
/// is timer-driven and intentionally not asserted here — this just
/// confirms the setter is reachable for both default-CF and explicit-CF
/// (versioned) open paths.
#[tokio::test(flavor = "multi_thread")]
async fn periodic_compaction_seconds_wired() {
	for versioned in [false, true] {
		let mut config =
			ConfigMap::empty().with_key_value("rocksdb_periodic_compaction_seconds", "60");
		if versioned {
			config = config.with_key_value("datastore_versioned", "true");
		}

		let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
		let path = format!("rocksdb:{path}");

		let _ds = Datastore::builder()
			.with_config(config)
			.build_with_factory_path(&path, CommunityComposer())
			.await
			.expect("periodic_compaction_seconds should not break the open path");
	}
}

/// Sanity-check that `compaction_style=universal` plus the universal-
/// specific tunables open cleanly. Mirrors the periodic-compaction test
/// above: the assertion is that the open path doesn't error and a
/// follow-up write succeeds, not that universal compaction fires.
#[tokio::test(flavor = "multi_thread")]
async fn universal_compaction_options_wired() {
	let config = ConfigMap::empty()
		.with_key_value("rocksdb_compaction_style", "universal")
		.with_key_value("rocksdb_universal_size_ratio", "5")
		.with_key_value("rocksdb_universal_min_merge_width", "3")
		.with_key_value("rocksdb_universal_max_merge_width", "16")
		.with_key_value("rocksdb_universal_max_size_amplification_percent", "150")
		.with_key_value("rocksdb_universal_compression_size_percent", "75")
		.with_key_value("rocksdb_universal_stop_style", "similar_size");

	let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
	let path = format!("rocksdb:{path}");

	let ds = Datastore::builder()
		.with_config(config)
		.build_with_factory_path(&path, CommunityComposer())
		.await
		.expect("universal compaction options should not break the open path");

	// A round-trip write proves the configured CF is healthy.
	let tx = ds.transaction(Write, Optimistic).await.unwrap();
	tx.set(&"universal_key", &"universal_value".as_bytes().to_vec()).await.unwrap();
	tx.commit().await.unwrap();
}

/// Verify the default-shutdown path: flush memtables, drain in-flight
/// compactions, cancel background work, shut down the memory manager.
/// Asserts the path returns `Ok` and that any auto-scheduled compaction
/// from the post-flush L0 file has either drained or been cancelled
/// before the bg workers are stopped.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_drains_cleanly_with_defaults() {
	use crate::kvs::rocksdb::{Datastore as RocksDbDatastore, RocksDbConfig};

	let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
	let config = RocksDbConfig {
		// Tiny SSTs + small write buffer so the very first commit
		// trips the auto-compaction trigger after the shutdown flush,
		// exercising the wait_for_compact branch.
		target_file_size_base: 64 * 1024,
		write_buffer_size: 64 * 1024,
		..RocksDbConfig::default()
	};

	let ds = RocksDbDatastore::new(&path, config).await.unwrap();
	{
		let tx = ds.transaction(true, true).await.unwrap();
		for i in 0..256u32 {
			let key: Vec<u8> = format!("shutdown_default_{i:04}").into_bytes();
			let value = vec![0u8; 256];
			tx.set(key, value).await.unwrap();
		}
		tx.commit().await.unwrap();
	}
	// Shutdown must succeed and not panic.
	ds.shutdown().await.expect("default shutdown should succeed");
	// And `num-running-compactions` should be zero — the cancel +
	// wait_for_compact pair drained everything.
	let running = ds
		.db
		.property_int_value("rocksdb.num-running-compactions")
		.unwrap_or_default()
		.unwrap_or_default();
	assert_eq!(
		running, 0,
		"expected no background compactions running after shutdown, got {running}"
	);
}

/// Verify the opt-in `compact_on_shutdown` path lands the dataset at the
/// bottommost level, exactly like a manual `ALTER SYSTEM COMPACT`. Same
/// assertion machinery as `compact_pushes_data_to_bottommost` but driven
/// through the shutdown path.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_compacts_to_bottommost_when_opted_in() {
	use rand::rngs::StdRng;
	use rand::{RngCore, SeedableRng};

	use crate::kvs::rocksdb::{Datastore as RocksDbDatastore, RocksDbConfig};

	let path = TempDir::new().unwrap().path().to_string_lossy().to_string();
	let config = RocksDbConfig {
		target_file_size_base: 64 * 1024,
		write_buffer_size: 64 * 1024,
		compact_on_shutdown: true,
		// Plenty of time on a local test box.
		shutdown_wait_for_compact_seconds: 30,
		..RocksDbConfig::default()
	};

	let ds = RocksDbDatastore::new(&path, config).await.unwrap();

	// Write enough deterministically-random data that at least one SST
	// is produced (random values defeat per-level compression collapse).
	let mut rng = StdRng::seed_from_u64(0xD15C_0DED_BEEF_FACE_u64);
	for batch in 0..32u32 {
		let tx = ds.transaction(true, true).await.unwrap();
		for i in 0..32u32 {
			let key: Vec<u8> = format!("shutdown_compact_{batch:04}_{i:04}").into_bytes();
			let mut value = vec![0u8; 256];
			rng.fill_bytes(&mut value);
			tx.set(key, value).await.unwrap();
		}
		tx.commit().await.unwrap();
	}

	// Shutdown must succeed and push everything down to L6.
	ds.shutdown().await.expect("compact-on-shutdown should succeed");

	let level_file_count = |level: usize| -> u64 {
		let name = format!("rocksdb.num-files-at-level{level}");
		ds.db.property_int_value(&name).unwrap_or_default().unwrap_or_default()
	};
	for level in 0..6 {
		let n = level_file_count(level);
		assert_eq!(n, 0, "expected level {level} empty after compact_on_shutdown, got {n} files",);
	}
	let bottom = level_file_count(6);
	assert!(bottom > 0, "expected bottommost (L6) to carry SSTs, got 0");
}
