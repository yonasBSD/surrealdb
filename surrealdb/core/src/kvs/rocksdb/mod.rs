#![cfg(feature = "kv-rocksdb")]

mod background_flusher;
mod cnf;
mod commit_coordinator;
mod comparator;
mod disk_space_manager;
mod garbage_collector;
mod memory_manager;

use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use background_flusher::BackgroundFlusher;
use commit_coordinator::CommitCoordinator;
use disk_space_manager::{DiskSpaceManager, DiskSpaceState, TransactionState};
use garbage_collector::GarbageCollector;
use memory_manager::MemoryManager;
use rocksdb::{
	ColumnFamilyDescriptor, DBCompactionStyle, DBCompressionType, FlushOptions, LogLevel,
	OptimisticTransactionDB, OptimisticTransactionOptions, Options, ReadOptions,
	SnapshotWithThreadMode, WriteOptions, properties,
};
use tokio::sync::{Mutex, MutexGuard};

use super::api::ScanLimit;
use super::config::{RocksDbConfig, SyncMode};
use super::err::{Error, Result};
use super::{Direction, ESTIMATED_BYTES_PER_KEY, ESTIMATED_BYTES_PER_KV};
use crate::key::debug::Sprintable;
use crate::kvs::api::Transactable;
use crate::kvs::ds::{Metric, Metrics};
use crate::kvs::timestamp::HlcTimeStamp;
use crate::kvs::{Key, Val};

const TARGET: &str = "surrealdb::core::kvs::rocksdb";

pub struct Datastore {
	/// The underlying RocksDB optimistic transaction database
	db: Pin<Arc<OptimisticTransactionDB>>,
	/// Whether user-defined timestamps (versioning) are enabled
	versioned: bool,
	/// Memory manager for managing memory usage
	memory_manager: Arc<MemoryManager>,
	/// Disk space manager for monitoring space usage and enforcing space limits
	disk_space_manager: Option<Arc<DiskSpaceManager>>,
	/// Commit coordinator for batching transaction commits when sync is enabled
	commit_coordinator: Option<Arc<CommitCoordinator>>,
	/// Background flusher for periodically flushing WAL to disk
	background_flusher: Option<Arc<BackgroundFlusher>>,
	/// Garbage collector for advancing the version GC watermark
	garbage_collector: Option<Arc<GarbageCollector>>,
}
pub struct Transaction {
	/// Is the transaction complete?
	done: AtomicBool,
	/// Is the transaction writeable?
	write: bool,
	/// Whether user-defined timestamps (versioning) are enabled
	versioned: bool,
	/// The read options containing the snapshot
	read_options: ReadOptions,
	/// The inner transaction and the transaction snapshot
	inner: Mutex<Option<TransactionInner>>,
	/// The current transaction state
	transaction_state: Arc<AtomicU8>,
	/// Reference to the disk space manager for checking current operational state during commit.
	disk_space_manager: Option<Arc<DiskSpaceManager>>,
	/// Commit coordinator for batching transaction commits when sync writes are enabled
	commit_coordinator: Option<Arc<CommitCoordinator>>,
	/// The above, supposedly 'static transaction actually points here, so we
	/// need to ensure the memory is kept alive. This pointer must be declared
	/// last, so that it is dropped last.
	db: Pin<Arc<OptimisticTransactionDB>>,
}

/// The rocksdb transaction and its pre-captured snapshot, bundled together so
/// that the snapshot is always dropped before the transaction it borrows from.
///
/// `snapshot` holds a `'static` reference into the boxed transaction: the
/// RocksDB snapshot's `db` field points at the `Transaction` allocation **inside**
/// `tx: Box<...>`, which has a stable address while `TransactionInner` is moved
/// (only the `Box` pointer moves, not the heap allocation). `tx` must outlive
/// `snapshot`. Two paths guarantee this:
///
/// * On natural drop, struct fields drop in declaration order. `snapshot` is declared before `tx`
///   and therefore drops first — while `tx` is still alive.
/// * On commit, the commit path destructures this struct, drops `snapshot` first, then consumes the
///   boxed transaction with `(*inner).commit()` (where `inner` is the
///   `Box<rocksdb::Transaction<…>>`).
struct TransactionInner {
	/// The snapshot for the underlying datastore transaction.
	///
	/// Declared before `tx` so it drops first on natural drop: the snapshot
	/// must be released before the boxed `Transaction` is destroyed.
	snapshot:
		SnapshotWithThreadMode<'static, rocksdb::Transaction<'static, OptimisticTransactionDB>>,
	/// The underlying datastore transaction (boxed so `snapshot` can safely
	/// hold a `&Transaction` into a stable allocation when `TransactionInner` moves).
	tx: Box<rocksdb::Transaction<'static, OptimisticTransactionDB>>,
}

impl Datastore {
	/// Open a new database
	pub(crate) async fn new(path: &str, config: RocksDbConfig) -> Result<Datastore> {
		// Configure custom options
		let mut opts = Options::default();
		// Ensure we use fdatasync
		opts.set_use_fsync(false);
		// Create database if missing
		opts.create_if_missing(true);
		// Create column families if missing
		opts.create_missing_column_families(true);
		// Default to WAL flush on every commit
		opts.set_manual_wal_flush(false);
		// Set incremental asynchronous bytes per sync to 2MiB
		opts.set_wal_bytes_per_sync(2 * 1024 * 1024);
		// Increase the background thread count
		let threads = cnf::ROCKSDB_THREAD_COUNT.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Background thread count: {threads}");
		opts.increase_parallelism(threads);
		// Specify the max concurrent background jobs
		let background_jobs = cnf::ROCKSDB_JOBS_COUNT.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Maximum background jobs count: {background_jobs}");
		opts.set_max_background_jobs(background_jobs);
		// Set the maximum number of open files that can be used by the database
		let max_open_files = cnf::ROCKSDB_MAX_OPEN_FILES.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Maximum number of open files: {max_open_files}");
		opts.set_max_open_files(max_open_files);
		// Set the number of log files to keep
		info!(target: TARGET, "Number of log files to keep: {}", *cnf::ROCKSDB_KEEP_LOG_FILE_NUM);
		opts.set_keep_log_file_num(*cnf::ROCKSDB_KEEP_LOG_FILE_NUM);
		// Set the target file size for compaction
		info!(target: TARGET, "Target file size for compaction: {}", *cnf::ROCKSDB_TARGET_FILE_SIZE_BASE);
		opts.set_target_file_size_base(*cnf::ROCKSDB_TARGET_FILE_SIZE_BASE);
		// Set the levelled target file size multipler
		let size_multiplier =
			cnf::ROCKSDB_TARGET_FILE_SIZE_MULTIPLIER.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Target file size compaction multiplier: {size_multiplier}");
		opts.set_target_file_size_multiplier(size_multiplier);
		// Delay compaction until the minimum number of files accumulate
		let compaction_trigger = cnf::ROCKSDB_FILE_COMPACTION_TRIGGER.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Number of files to trigger compaction: {compaction_trigger}");
		opts.set_level_zero_file_num_compaction_trigger(compaction_trigger);
		// Set the compaction readahead size
		info!(target: TARGET, "Compaction readahead size: {}", *cnf::ROCKSDB_COMPACTION_READAHEAD_SIZE);
		opts.set_compaction_readahead_size(*cnf::ROCKSDB_COMPACTION_READAHEAD_SIZE);
		// Set the max number of subcompactions
		info!(target: TARGET, "Maximum concurrent subcompactions: {}", *cnf::ROCKSDB_MAX_CONCURRENT_SUBCOMPACTIONS);
		opts.set_max_subcompactions(*cnf::ROCKSDB_MAX_CONCURRENT_SUBCOMPACTIONS);
		// Use separate write thread queues
		info!(target: TARGET, "Use separate thread queues: {}", *cnf::ROCKSDB_ENABLE_PIPELINED_WRITES);
		opts.set_enable_pipelined_write(*cnf::ROCKSDB_ENABLE_PIPELINED_WRITES);
		// Enable separation of keys and values
		info!(target: TARGET, "Enable separation of keys and values: {}", *cnf::ROCKSDB_ENABLE_BLOB_FILES);
		opts.set_enable_blob_files(*cnf::ROCKSDB_ENABLE_BLOB_FILES);
		// Store large values separate from keys
		info!(target: TARGET, "Minimum blob value size: {}", *cnf::ROCKSDB_MIN_BLOB_SIZE);
		opts.set_min_blob_size(*cnf::ROCKSDB_MIN_BLOB_SIZE);
		// Additional blob file options
		info!(target: TARGET, "Target blob file size: {}", *cnf::ROCKSDB_BLOB_FILE_SIZE);
		opts.set_blob_file_size(*cnf::ROCKSDB_BLOB_FILE_SIZE);
		// Set the blob compression type
		if let Some(c) = cnf::ROCKSDB_BLOB_COMPRESSION_TYPE.as_ref() {
			info!(target: TARGET, "Blob compression type: {c}");
			opts.set_blob_compression_type(match c.to_ascii_lowercase().as_str() {
				"none" => DBCompressionType::None,
				"snappy" => DBCompressionType::Snappy,
				"lz4" => DBCompressionType::Lz4,
				"zstd" => DBCompressionType::Zstd,
				c => {
					return Err(Error::Datastore(format!("Invalid compression type: {c}")));
				}
			});
		}
		// Whether to enable blob garbage collection
		info!(target: TARGET, "Enable blob garbage collection: {}", *cnf::ROCKSDB_ENABLE_BLOB_GC);
		opts.set_enable_blob_gc(*cnf::ROCKSDB_ENABLE_BLOB_GC);
		// Set the blob garbage collection age cutoff
		info!(target: TARGET, "Blob GC age cutoff: {}", *cnf::ROCKSDB_BLOB_GC_AGE_CUTOFF);
		opts.set_blob_gc_age_cutoff(*cnf::ROCKSDB_BLOB_GC_AGE_CUTOFF);
		// Set the blob garbage collection force threshold
		info!(target: TARGET, "Blob GC force threshold: {}", *cnf::ROCKSDB_BLOB_GC_FORCE_THRESHOLD);
		opts.set_blob_gc_force_threshold(*cnf::ROCKSDB_BLOB_GC_FORCE_THRESHOLD);
		// Set the blob compaction readahead size
		info!(target: TARGET, "Blob compaction readahead size: {}", *cnf::ROCKSDB_BLOB_COMPACTION_READAHEAD_SIZE);
		opts.set_blob_compaction_readahead_size(*cnf::ROCKSDB_BLOB_COMPACTION_READAHEAD_SIZE);
		// Set the write-ahead-log size limit in MB
		info!(target: TARGET, "Write-ahead-log file size limit: {}MB", *cnf::ROCKSDB_WAL_SIZE_LIMIT);
		opts.set_wal_size_limit_mb(*cnf::ROCKSDB_WAL_SIZE_LIMIT);
		// Allow multiple writers to update memtables in parallel
		info!(target: TARGET, "Allow concurrent memtable writes: true");
		opts.set_allow_concurrent_memtable_write(true);
		// Avoid unnecessary blocking io, preferring background threads
		info!(target: TARGET, "Avoid unnecessary blocking IO: true");
		opts.set_avoid_unnecessary_blocking_io(true);
		// Improve concurrency from write batch mutex
		info!(target: TARGET, "Allow adaptive write thread yielding: true");
		opts.set_enable_write_thread_adaptive_yield(true);
		// Set the delete compaction factory
		info!(target: TARGET, "Setting delete compaction factory: {} / {} ({})",
			*cnf::ROCKSDB_DELETION_FACTORY_WINDOW_SIZE,
			*cnf::ROCKSDB_DELETION_FACTORY_DELETE_COUNT,
			*cnf::ROCKSDB_DELETION_FACTORY_RATIO,
		);
		opts.add_compact_on_deletion_collector_factory(
			*cnf::ROCKSDB_DELETION_FACTORY_WINDOW_SIZE,
			*cnf::ROCKSDB_DELETION_FACTORY_DELETE_COUNT,
			*cnf::ROCKSDB_DELETION_FACTORY_RATIO,
		);
		// Set the datastore compaction style
		info!(target: TARGET, "Setting compaction style: {}", *cnf::ROCKSDB_COMPACTION_STYLE);
		opts.set_compaction_style(
			match cnf::ROCKSDB_COMPACTION_STYLE.to_ascii_lowercase().as_str() {
				"universal" => DBCompactionStyle::Universal,
				_ => DBCompactionStyle::Level,
			},
		);
		// Set specific compression levels
		info!(target: TARGET, "Setting compression level");
		opts.set_compression_per_level(&[
			DBCompressionType::None,
			DBCompressionType::None,
			DBCompressionType::Lz4,
			DBCompressionType::Lz4,
			DBCompressionType::Lz4,
		]);
		// Set specific storage log level
		info!(target: TARGET, "Setting storage engine log level: {}", *cnf::ROCKSDB_STORAGE_LOG_LEVEL);
		opts.set_log_level(match cnf::ROCKSDB_STORAGE_LOG_LEVEL.to_ascii_lowercase().as_str() {
			"debug" => LogLevel::Debug,
			"info" => LogLevel::Info,
			"warn" => LogLevel::Warn,
			"error" => LogLevel::Error,
			"fatal" => LogLevel::Fatal,
			l => {
				return Err(Error::Datastore(format!(
					"Invalid storage engine log level specified: {l}"
				)));
			}
		});
		// Configure the timestamp-aware comparator for user-defined timestamps
		let cf_opts = if config.versioned {
			info!(target: TARGET, "Enabling user-defined timestamps (versioning)");
			let mut cf_opts = Options::default();
			cf_opts.set_comparator_with_ts(
				comparator::NAME,
				comparator::TIMESTAMP_SIZE,
				Box::new(comparator::compare),
				Box::new(comparator::compare_ts),
				Box::new(comparator::compare_without_ts),
			);
			Some(cf_opts)
		} else {
			None
		};
		// Configure and create the memory manager
		let memory_manager = Arc::new(MemoryManager::configure(&mut opts)?);
		// Pre-configure the disk space manager
		let should_create_disk_space_manager = DiskSpaceManager::configure(&mut opts)?;
		// Pre-configure WAL options based on the resolved sync mode
		match config.sync_mode {
			// Pre-configure the background flusher
			SyncMode::Interval(_) => BackgroundFlusher::configure(&mut opts, &config),
			// Pre-configure the commit coordinator
			SyncMode::Every => CommitCoordinator::configure(&mut opts, &config),
			// No configuration needed
			SyncMode::Never => {}
		};
		// Create the disk space manager if enabled
		let disk_space_manager = if should_create_disk_space_manager {
			Some(Arc::new(DiskSpaceManager::new(&mut opts)?))
		} else {
			None
		};
		// Open the database, using an explicit "default" column family when
		// versioning is enabled so that cf_handle("default") is available
		// for the garbage collector to advance the full_history_ts_low watermark.
		let db = if let Some(cf_opts) = cf_opts {
			// Open the database with the "default" column family
			let descriptors = vec![ColumnFamilyDescriptor::new("default", cf_opts)];
			// Open the database with the "default" column family
			Arc::pin(OptimisticTransactionDB::open_cf_descriptors(&opts, path, descriptors)?)
		} else {
			// Open the database without a default column family
			Arc::pin(OptimisticTransactionDB::open(&opts, path)?)
		};
		// Create the commit coordinator if enabled
		let commit_coordinator = if let SyncMode::Every = config.sync_mode {
			Some(Arc::new(CommitCoordinator::new(db.clone())?))
		} else {
			None
		};
		// Create the background flusher if enabled
		let background_flusher = if let SyncMode::Interval(interval) = config.sync_mode {
			Some(Arc::new(BackgroundFlusher::new(db.clone(), interval)?))
		} else {
			None
		};
		// Create the garbage collector if versioning with a finite retention period
		let garbage_collector = if config.versioned && config.retention_ns > 0 {
			Some(Arc::new(GarbageCollector::new(db.clone(), config.retention_ns)?))
		} else {
			None
		};
		// Defer to the operating system buffers for disk sync. This means that the
		// transaction commits are written to WAL on commit, but are then flushed
		// to disk by the operating system at an unspecified time. In the event of
		// a system crash, data may be lost if the operating system has not yet
		// synced the data to disk.
		if let SyncMode::Never = config.sync_mode {
			info!(target: TARGET, "Sync mode: never (handled by the OS");
			opts.set_manual_wal_flush(false);
		}
		// Register the memory manager with the global allocator tracker
		memory_manager.register_with_allocator_tracker();
		// Return the datastore
		Ok(Datastore {
			db,
			versioned: config.versioned,
			memory_manager,
			disk_space_manager,
			background_flusher,
			commit_coordinator,
			garbage_collector,
		})
	}

	const BLOCK_CACHE_USAGE: &str = "rocksdb.block_cache_usage";
	const BLOCK_CACHE_PINNED_USAGE: &str = "rocksdb.block_cache_pinned_usage";
	const ESTIMATE_TABLE_READERS_MEM: &str = "rocksdb.estimate_table_readers_mem";
	const CUR_SIZE_ALL_MEM_TABLES: &str = "rocksdb.cur_size_all_mem_tables";

	/// Registers metrics for the RocksDB datastore.
	pub(crate) fn register_metrics(&self) -> Metrics {
		Metrics {
			name: "surrealdb.rocksdb",
			u64_metrics: vec![
				Metric {
					name: Self::BLOCK_CACHE_USAGE,
					description: "Returns the memory size (in bytes) for the entries residing in block cache.",
				},
				Metric {
					name: Self::BLOCK_CACHE_PINNED_USAGE,
					description: "Returns the memory size (in bytes) for the entries being pinned.",
				},
				Metric {
					name: Self::ESTIMATE_TABLE_READERS_MEM,
					description: "Returns estimated memory size (in bytes) used for reading SST tables, excluding memory used in block cache (e.g., filter and index blocks).",
				},
				Metric {
					name: Self::CUR_SIZE_ALL_MEM_TABLES,
					description: "Returns approximate size (in bytes) of active and unflushed immutable memtables",
				},
			],
		}
	}

	/// Collects a specific u64 metric by name from the RocksDB datastore.
	pub(crate) fn collect_u64_metric(&self, metric: &str) -> Option<u64> {
		let metric = match metric {
			Self::BLOCK_CACHE_USAGE => Some(properties::BLOCK_CACHE_USAGE),
			Self::BLOCK_CACHE_PINNED_USAGE => Some(properties::BLOCK_CACHE_PINNED_USAGE),
			Self::ESTIMATE_TABLE_READERS_MEM => Some(properties::ESTIMATE_TABLE_READERS_MEM),
			Self::CUR_SIZE_ALL_MEM_TABLES => Some(properties::CUR_SIZE_ALL_MEM_TABLES),
			_ => None,
		};
		metric.map(|metric| {
			self.db.property_int_value(metric).unwrap_or_default().unwrap_or_default()
		})
	}

	/// Shutdown the database
	pub(crate) async fn shutdown(&self) -> Result<()> {
		// Wait for the garbage collector to finish
		if let Some(garbage_collector) = &self.garbage_collector {
			garbage_collector.shutdown()?;
		}
		// Wait for the background flusher to finish
		if let Some(background_flusher) = &self.background_flusher {
			background_flusher.shutdown()?;
		}
		// Wait for the commit coordinator to finish
		if let Some(commit_coordinator) = &self.commit_coordinator {
			commit_coordinator.shutdown()?;
		}
		// Create new flush options
		let mut opts = FlushOptions::default();
		// Wait for the sync to finish
		opts.set_wait(true);
		// Flush the WAL to storage
		if let Err(e) = self.db.flush_wal(true) {
			error!("An error occurred flushing the WAL buffer to disk: {e}");
		}
		// Flush the memtables to SST
		if let Err(e) = self.db.flush_opt(&opts) {
			error!("An error occurred flushing memtables to SST files: {e}");
		}
		// Shutdown the memory manager
		self.memory_manager.shutdown()?;
		// All good
		Ok(())
	}

	/// Start a new transaction
	pub(crate) async fn transaction(&self, write: bool, _: bool) -> Result<Box<dyn Transactable>> {
		// Set the transaction options
		let mut to = OptimisticTransactionOptions::default();
		to.set_snapshot(true);
		// Set the write options
		let mut wo = WriteOptions::default();
		// Per-transaction sync is never used. When sync=every is configured, the commit
		// coordinator handles grouped fsync after parallel transaction commits. When
		// sync=<interval> or sync=never, no per-transaction fsync is needed either.
		wo.set_sync(false);
		// Create a new transaction
		let tx = self.db.transaction_opt(&wo, &to);
		// When versioning is enabled the default column family uses a
		// user-defined-timestamp (UDT) comparator. RocksDB then requires every
		// `OptimisticTransaction` to have a `read_timestamp_` strictly less
		// than `kMaxTxnTimestamp` (the default `u64::MAX` sentinel) and
		// strictly less than whatever `commit_timestamp_` we later set at
		// commit time. Specifically:
		//
		// - `DBImpl::GetLatestSequenceForKey`, invoked from the commit-time conflict check
		//   (`TransactionUtil::CheckKey`), asserts `timestamp != nullptr` whenever the column
		//   family's comparator has a non-zero timestamp size. `OptimisticTransaction` only
		//   populates that buffer when `read_timestamp_ < kMaxTxnTimestamp`, so without this call
		//   the first writeable commit aborts the process with `Assertion 'timestamp' failed`.
		// - `OptimisticTransaction::SetCommitTimestamp` rejects any `commit_ts <= read_timestamp_`
		//   with `Status::InvalidArgument`, which the Rust wrapper silently drops. A too-large
		//   `read_ts` (e.g. `u64::MAX - 1`) would therefore make the `set_commit_ timestamp` call
		//   in `commit()` a no-op, leading to a downstream `Must assign a commit timestamp` error.
		// - UDT-based validation fires when `read_ts < observed_ts`, so a too-small `read_ts` (e.g.
		//   `0`) would false-positive on every key whose latest version is visible through our
		//   snapshot.
		//
		// Seeding `read_ts` from the globally-monotonic HLC after
		// `transaction_opt()` (which captured the snapshot) satisfies all
		// three: every HLC assigned to a visible prior commit is strictly
		// smaller (their `set_commit_timestamp` + `db.Write` both happened
		// before our snapshot, hence before this call), and the HLC we use at
		// commit time via `HlcTimeStamp::next()` is strictly larger (the HLC
		// is a process-wide CAS counter).
		if self.versioned {
			let read_ts = HlcTimeStamp::next();
			tx.set_read_timestamp_for_validation(read_ts.0);
		}
		// SAFETY: The transaction lifetime is tied to the database through the db field.
		// The database is guaranteed to outlive the transaction because:
		// 1. The transaction holds a Pin<Arc<OptimisticTransactionDB>> reference
		// 2. The transaction struct ensures db is dropped after inner
		// 3. The Pin ensures the database isn't moved or dropped while referenced
		let tx = unsafe {
			std::mem::transmute::<
				rocksdb::Transaction<'_, OptimisticTransactionDB>,
				rocksdb::Transaction<'static, OptimisticTransactionDB>,
			>(tx)
		};
		// Heap-allocate before capturing the snapshot so `SnapshotWithThreadMode`'s
		// `db: &Transaction` points at a stable address: moving `TransactionInner`
		// only moves the `Box` pointer, not the transaction allocation.
		let tx = Box::new(tx);
		// Capture the transaction's internal snapshot (set by `set_snapshot(true)`
		// above) and extend its lifetime to `'static`. Using the transaction's
		// own snapshot ensures reads always see the sequence number used for
		// commit-time conflict detection; using a different snapshot (e.g. from
		// `db.snapshot()`) would allow read/conflict-detection to disagree and
		// break optimistic concurrency correctness.
		//
		// SAFETY: The snapshot borrows `&*tx` into the boxed transaction. The
		// transmute is sound because `tx` and `snapshot` live in the same
		// `TransactionInner` (with `snapshot` declared before `tx` so it drops
		// first), and the commit path drops `snapshot` before consuming the
		// boxed `Transaction` (see `Transactable::commit`).
		let snapshot = unsafe {
			std::mem::transmute::<
				SnapshotWithThreadMode<'_, rocksdb::Transaction<'static, OptimisticTransactionDB>>,
				SnapshotWithThreadMode<
					'static,
					rocksdb::Transaction<'static, OptimisticTransactionDB>,
				>,
			>(tx.as_ref().snapshot())
		};
		// Build the default read options pointing at the captured snapshot.
		// `set_snapshot` copies the internal snapshot pointer into the
		// `ReadOptions`, so `ReadOptions` remains valid as long as the
		// underlying rocksdb snapshot (owned by `inner`) is alive.
		let mut ro = ReadOptions::default();
		ro.set_snapshot(&snapshot);
		ro.set_async_io(true);
		ro.fill_cache(true);
		// When versioned, default reads fetch the latest version
		if self.versioned {
			ro.set_timestamp(u64::MAX.to_le_bytes().to_vec());
		}
		// Create a new transaction
		Ok(Box::new(Transaction {
			done: AtomicBool::new(false),
			write,
			versioned: self.versioned,
			read_options: ro,
			inner: Mutex::new(Some(TransactionInner {
				tx,
				snapshot,
			})),
			transaction_state: Arc::new(Default::default()),
			disk_space_manager: self.disk_space_manager.clone(),
			commit_coordinator: self.commit_coordinator.clone(),
			db: self.db.clone(),
		}))
	}
}

impl Transaction {
	/// Get the current transaction state
	fn current_state(&self) -> TransactionState {
		match self.transaction_state.load(Ordering::Acquire) {
			0 => TransactionState::ReadsOnly,
			1 => TransactionState::HasDeletes,
			2 => TransactionState::HasWrites,
			_ => unreachable!(),
		}
	}

	/// Mark the transaction as containing deletes
	fn store_deletes(&self) {
		if self.current_state() < TransactionState::HasDeletes {
			self.transaction_state.store(TransactionState::HasDeletes as u8, Ordering::Release);
		}
	}

	/// Mark the transaction as containing writes
	fn store_writes(&self) {
		if self.current_state() < TransactionState::HasWrites {
			self.transaction_state.store(TransactionState::HasWrites as u8, Ordering::Release);
		}
	}

	/// Check if the transaction contains writes
	fn contains_deletes(&self) -> bool {
		self.current_state() == TransactionState::HasDeletes
	}

	/// Check if the transaction contains writes
	fn contains_writes(&self) -> bool {
		self.current_state() == TransactionState::HasWrites
	}

	/// Check if disk space is restricted
	fn is_restricted(&self, recalculate: bool) -> bool {
		if let Some(dsm) = self.disk_space_manager.as_ref() {
			match recalculate {
				false => dsm.cached_state() == DiskSpaceState::ReadAndDeletionOnly,
				true => dsm.latest_state() == DiskSpaceState::ReadAndDeletionOnly,
			}
		} else {
			false
		}
	}

	/// Build a fresh `ReadOptions` for a versioned point read.
	///
	/// The caller must pass the already-borrowed `TransactionInner` so the read uses
	/// the transaction's captured snapshot (matching the conflict-detection
	/// view that will be used at commit time).
	fn versioned_read_options(
		&self,
		version: Option<u64>,
		inner: &TransactionInner,
	) -> ReadOptions {
		let mut ro = ReadOptions::default();
		ro.set_snapshot(&inner.snapshot);
		ro.set_async_io(true);
		ro.fill_cache(true);
		if self.versioned {
			let ts = version.unwrap_or(u64::MAX);
			ro.set_timestamp(ts.to_le_bytes().to_vec());
		}
		ro
	}

	/// Build a fresh `ReadOptions` for a scan over the given key range.
	/// Sets the iterate bounds, the captured snapshot, async-io, caching
	/// flags, and (when applicable) the version timestamp.
	fn scan_read_options(
		&self,
		rng: &Range<Key>,
		version: Option<u64>,
		inner: &TransactionInner,
	) -> ReadOptions {
		let mut ro = ReadOptions::default();
		ro.set_snapshot(&inner.snapshot);
		ro.set_iterate_lower_bound(rng.start.clone());
		ro.set_iterate_upper_bound(rng.end.clone());
		ro.set_async_io(true);
		ro.fill_cache(true);
		if self.versioned {
			let ts = version.unwrap_or(u64::MAX);
			ro.set_timestamp(ts.to_le_bytes().to_vec());
		}
		ro
	}

	/// Build a fresh `ReadOptions` for a count operation.
	/// Sets the iterate bounds, the captured snapshot, async-io, disables
	/// caching flags, and (when applicable) the version timestamp.
	fn count_read_options(
		&self,
		rng: &Range<Key>,
		version: Option<u64>,
		inner: &TransactionInner,
	) -> ReadOptions {
		let mut ro = ReadOptions::default();
		ro.set_snapshot(&inner.snapshot);
		ro.set_iterate_lower_bound(rng.start.clone());
		ro.set_iterate_upper_bound(rng.end.clone());
		ro.set_async_io(true);
		ro.fill_cache(false);
		if self.versioned {
			let ts = version.unwrap_or(u64::MAX);
			ro.set_timestamp(ts.to_le_bytes().to_vec());
		}
		ro
	}

	/// Whether a scan with the given limit should be offloaded to the blocking
	/// threadpool rather than executed inline on the async executor thread.
	///
	/// Small bounded scans run inline to avoid the cross-thread wakeup latency
	/// of the blocking pool. Larger scans are offloaded so they do not stall
	/// other async tasks on the executor.
	///
	/// The decision is made in bytes: `ScanLimit::Bytes(b)` is compared
	/// directly against the threshold, while `ScanLimit::Count(c)` converts
	/// the entry count to an approximate byte size using the caller-supplied
	/// per-entry estimate.
	///
	/// For `ScanLimit::BytesOrCount(b, c)`, iteration stops when *either* the
	/// byte budget `b` or the entry cap `c` is hit. The count-based estimate
	/// `c * bytes_per_entry` can understate worst-case I/O when real entries
	/// are larger than the heuristic. If `b` alone exceeds the inline
	/// threshold, we treat `b` as the authoritative upper bound so large byte
	/// budgets are not misclassified as small inline scans when `c` is small
	/// (e.g. scanner batches with a SQL `LIMIT`).
	/// Pass `ESTIMATED_BYTES_PER_KEY` for key-only scans (`keys`/`keysr`) and
	/// `ESTIMATED_BYTES_PER_KV` for key+value scans (`scan`/`scanr`), where the
	/// estimate is combined key+value bytes per entry (not value-only).
	///
	/// `skip` is included in the byte estimate because the skip loop in
	/// `consume_keys`/`consume_vals` advances the underlying iterator
	/// entry-by-entry before any result is collected. A large skip combined
	/// with a small limit would otherwise be classified as inline and block
	/// the async executor for the entire skip traversal.
	fn should_offload(limit: ScanLimit, skip: u32, bytes_per_entry: u32) -> bool {
		// Get the allowed inline scan threshold
		let threshold = *cnf::ROCKSDB_INLINE_SCAN_THRESHOLD;
		// Estimate the byte cost of the skip prefix that the iterator
		// must traverse before returning any result.
		let skip_bytes = skip.saturating_mul(bytes_per_entry);
		// Calculate the estimated bytes based on the configured inline limit.
		let limit_bytes = match limit {
			ScanLimit::Count(c) => c.saturating_mul(bytes_per_entry),
			ScanLimit::Bytes(b) => b,
			ScanLimit::BytesOrCount(b, c) => {
				let count_estimate = c.saturating_mul(bytes_per_entry);
				if b > threshold {
					b
				} else {
					b.min(count_estimate)
				}
			}
		};
		// Check if the combined skip+limit estimate is greater than the threshold
		skip_bytes.saturating_add(limit_bytes) > threshold
	}

	/// Synchronous implementation of `count` taking an already-acquired lock
	/// guard. Always dispatched via `affinitypool::spawn_local` from `count()`;
	/// this function is never called directly on the async executor thread.
	///
	/// Writeable transactions lock the transaction inner and iterate on the
	/// inner transaction so that pending writes in this transaction are
	/// visible to the iterator. Read-only transactions iterate directly on
	/// the database, holding the inner lock only long enough to build the
	/// `ReadOptions` (which copies out the raw snapshot pointer).
	fn count_blocking(
		&self,
		rng: Range<Key>,
		version: Option<u64>,
		guard: MutexGuard<'_, Option<TransactionInner>>,
	) -> Result<usize> {
		// Get the inner transaction state
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Get the ReadOptions with the snapshot and iterate bounds
		let ro = self.count_read_options(&rng, version, inner);
		// Initialize the result
		let mut res: usize = 0;
		// If the transaction is writable, we create the iterator on the
		// transaction. This ensures that all writes in this transaction
		// are merged with each iterator step, making the writes visible to
		// the iterator.
		if self.write {
			// Create the iterator on the transaction
			let mut iter = inner.tx.raw_iterator_opt(ro);
			// Seek to the start key
			iter.seek(&rng.start);
			// Count the items
			while iter.valid() {
				res += 1;
				iter.next();
			}
			// Catch any iterator errors
			iter.status()?;
		}
		// If the transaction is readonly, we iterate directly on the
		// database. This is faster than iterating on the transaction,
		// as it avoids the `BaseDeltaIterator` wrapper used by the
		// transactional iterator.
		else {
			// Release the inner lock before the scan: `ReadOptions` already
			// holds the raw snapshot pointer, and the underlying rocksdb
			// snapshot stays alive for as long as the boxed `inner.tx` (owned by this
			// `Transaction`) is alive. Read-only transactions never take the
			// inner out of the mutex, so the snapshot is safe to use unlocked.
			drop(guard);
			// Create the iterator on the database
			let mut iter = self.db.raw_iterator_opt(ro);
			// Seek to the start key
			iter.seek(&rng.start);
			// Count the items
			while iter.valid() {
				res += 1;
				iter.next();
			}
			// Catch any iterator errors
			iter.status()?;
		}
		// Return result
		Ok(res)
	}

	/// Synchronous implementation of `keys` and `keysr` taking an already-acquired
	/// lock guard.
	///
	/// Dispatches forward or backward iteration based on `dir`. Read-only
	/// transactions release the inner lock before iterating; writeable
	/// transactions hold the lock for the duration of the iterator so that
	/// pending writes are visible.
	fn keys_blocking(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
		dir: Direction,
		guard: MutexGuard<'_, Option<TransactionInner>>,
	) -> Result<Vec<Key>> {
		// Get the inner transaction state
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Get the ReadOptions with the snapshot and iterate bounds
		let ro = self.scan_read_options(&rng, version, inner);
		// If the transaction is writable, we create the iterator on the
		// transaction. This ensures that all writes in this transaction
		// are merged with each iterator step, making the writes visible to
		// the iterator.
		if self.write {
			// Create the iterator on the transaction
			let mut iter = inner.tx.raw_iterator_opt(ro);
			// Seek to the start (or end) key based on direction
			match dir {
				Direction::Forward => iter.seek(&rng.start),
				Direction::Backward => iter.seek_for_prev(&rng.end),
			}
			// Consume the iterator
			consume_keys(&mut iter, limit, skip, dir)
		}
		// If the transaction is readonly, we iterate directly on the
		// database. This is faster than iterating on the transaction,
		// as it avoids the `BaseDeltaIterator` wrapper used by the
		// transactional iterator.
		else {
			// Release the inner lock before the scan
			drop(guard);
			// Create the iterator on the database
			let mut iter = self.db.raw_iterator_opt(ro);
			// Seek to the start (or end) key based on direction
			match dir {
				Direction::Forward => iter.seek(&rng.start),
				Direction::Backward => iter.seek_for_prev(&rng.end),
			}
			// Consume the iterator
			consume_keys(&mut iter, limit, skip, dir)
		}
	}

	/// Synchronous implementation of `scan` and `scanr` taking an already-acquired
	/// lock guard.
	///
	/// Dispatches forward or backward iteration based on `dir`. Read-only
	/// transactions release the inner lock before iterating; writeable
	/// transactions hold the lock for the duration of the iterator so that
	/// pending writes are visible.
	fn scan_blocking(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
		dir: Direction,
		guard: MutexGuard<'_, Option<TransactionInner>>,
	) -> Result<Vec<(Key, Val)>> {
		// Get the inner transaction state
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Get the ReadOptions with the snapshot and iterate bounds
		let ro = self.scan_read_options(&rng, version, inner);
		// If the transaction is writable, we create the iterator on the
		// transaction. This ensures that all writes in this transaction
		// are merged with each iterator step, making the writes visible to
		// the iterator.
		if self.write {
			// Create the iterator on the transaction
			let mut iter = inner.tx.raw_iterator_opt(ro);
			// Seek to the start (or end) key based on direction
			match dir {
				Direction::Forward => iter.seek(&rng.start),
				Direction::Backward => iter.seek_for_prev(&rng.end),
			}
			// Consume the iterator
			consume_vals(&mut iter, limit, skip, dir)
		}
		// If the transaction is readonly, we iterate directly on the
		// database. This is faster than iterating on the transaction,
		// as it avoids the `BaseDeltaIterator` wrapper used by the
		// transactional iterator.
		else {
			// Release the inner lock before the scan
			drop(guard);
			// Create the iterator on the database
			let mut iter = self.db.raw_iterator_opt(ro);
			// Seek to the start (or end) key based on direction
			match dir {
				Direction::Forward => iter.seek(&rng.start),
				Direction::Backward => iter.seek_for_prev(&rng.end),
			}
			// Consume the iterator
			consume_vals(&mut iter, limit, skip, dir)
		}
	}
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl Transactable for Transaction {
	fn kind(&self) -> &'static str {
		"rocksdb"
	}

	/// Check if closed
	fn closed(&self) -> bool {
		self.done.load(Ordering::Relaxed)
	}

	/// Check if writeable
	fn writeable(&self) -> bool {
		self.write
	}

	/// Cancel a transaction.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self))]
	async fn cancel(&self) -> Result<()> {
		// Atomically mark transaction as done and check if it was already closed
		if self.done.swap(true, Ordering::AcqRel) {
			return Err(Error::TransactionFinished);
		}
		// Lock the inner transaction
		let inner = self.inner.lock().await;
		// Get the inner transaction
		let inner =
			inner.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Cancel this transaction
		inner.tx.rollback()?;
		// Continue
		Ok(())
	}

	/// Commit a transaction.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self))]
	async fn commit(&self) -> Result<()> {
		// Atomically mark transaction as done and check if it was already closed
		if self.done.swap(true, Ordering::AcqRel) {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Check if we are in read-and-deletion-only mode
		if self.is_restricted(true) && self.contains_writes() {
			return Err(Error::ReadAndDeleteOnly);
		}
		// Take ownership of the transaction state. The sync mutex guard is
		// released as soon as this statement completes, so no lock is held
		// across subsequent awaits (e.g. the commit coordinator wait below).
		let TransactionInner {
			tx: inner,
			snapshot,
		} = self
			.inner
			.lock()
			.await
			.take()
			.ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Explicitly drop the snapshot before consuming the boxed transaction.
		// `snapshot` borrows the transaction inside `inner`, and `commit` consumes
		// it, so the snapshot must be released first.
		drop(snapshot);
		// When versioned, stamp all writes with the current HLC timestamp
		if self.versioned {
			let ts = HlcTimeStamp::next();
			inner.set_commit_timestamp(ts.0);
		}
		// Always commit the RocksDB transaction on the caller thread for parallel commits
		(*inner).commit()?;
		// If we have a coordinator, wait for the grouped fsync
		if let Some(coordinator) = &self.commit_coordinator {
			coordinator.wait_for_sync().await?;
		}
		// Perform compaction if necessary
		if self.is_restricted(true) && self.contains_deletes() {
			self.compact(None).await?;
		}
		// Continue
		Ok(())
	}

	/// Check if a key exists.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn exists(&self, key: Key, version: Option<u64>) -> Result<bool> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Lock the inner transaction
		let guard = self.inner.lock().await;
		// Get the inner transaction
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Get the key
		let res = if version.is_some() {
			inner.tx.get_pinned_opt(key, &self.versioned_read_options(version, inner))
		} else {
			inner.tx.get_pinned_opt(key, &self.read_options)
		}?
		.is_some();
		// Return result
		Ok(res)
	}

	/// Fetch a key from the database.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn get(&self, key: Key, version: Option<u64>) -> Result<Option<Val>> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the inner transaction
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Get the key
		let res = if version.is_some() {
			inner.tx.get_opt(key, &self.versioned_read_options(version, inner))
		} else {
			inner.tx.get_opt(key, &self.read_options)
		}?;
		// Return result
		Ok(res)
	}

	/// Fetch many keys from the datastore.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(keys = keys.sprint()))]
	async fn getm(&self, keys: Vec<Key>, version: Option<u64>) -> Result<Vec<Option<Val>>> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the transaction inner
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Get the keys
		let res = if version.is_some() {
			inner.tx.multi_get_opt(keys, &self.versioned_read_options(version, inner))
		} else {
			inner.tx.multi_get_opt(keys, &self.read_options)
		};
		// Convert result
		let res = res.into_iter().map(|r| r.map_err(Into::into)).collect::<Result<_>>()?;
		// Return result
		Ok(res)
	}

	/// Insert or update a key in the database.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn set(&self, key: Key, val: Val) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Check if we are in read-and-deletion-only mode
		if self.is_restricted(false) {
			return Err(Error::ReadAndDeleteOnly);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the transaction inner
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Set the key
		inner.tx.put(key, val)?;
		// Mark this transaction as containing a write operation
		self.store_writes();
		// Return result
		Ok(())
	}

	/// Insert a key if it doesn't exist in the database.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn put(&self, key: Key, val: Val) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Check if we are in read-and-deletion-only mode
		if self.is_restricted(false) {
			return Err(Error::ReadAndDeleteOnly);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the transaction inner
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Set the key if empty
		match inner.tx.get_pinned_opt(&key, &self.read_options)? {
			None => inner.tx.put(key, val)?,
			_ => return Err(Error::TransactionKeyAlreadyExists),
		};
		// Mark this transaction as containing a write operation
		self.store_writes();
		// Return result
		Ok(())
	}

	/// Insert a key if the current value matches a condition.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn putc(&self, key: Key, val: Val, chk: Option<Val>) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Check if we are in read-and-deletion-only mode
		if self.is_restricted(false) {
			return Err(Error::ReadAndDeleteOnly);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the transaction inner
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Set the key if empty
		match (inner.tx.get_pinned_opt(&key, &self.read_options)?, chk) {
			(Some(v), Some(w)) if v.eq(&w) => inner.tx.put(key, val)?,
			(None, None) => inner.tx.put(key, val)?,
			_ => return Err(Error::TransactionConditionNotMet),
		};
		// Mark this transaction as containing a write operation
		self.store_writes();
		// Return result
		Ok(())
	}

	/// Delete a key.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn del(&self, key: Key) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the transaction inner
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Remove the key
		inner.tx.delete(key)?;
		// Mark this transaction as containing a delete operation
		self.store_deletes();
		// Return result
		Ok(())
	}

	/// Delete a key if the current value matches a condition.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn delc(&self, key: Key, chk: Option<Val>) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Lock the transaction inner
		let guard = self.inner.lock().await;
		// Get the transaction inner
		let inner =
			guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
		// Delete the key if valid
		match (inner.tx.get_pinned_opt(&key, &self.read_options)?, chk) {
			(Some(v), Some(w)) if v.eq(&w) => inner.tx.delete(key)?,
			(None, None) => inner.tx.delete(key)?,
			_ => return Err(Error::TransactionConditionNotMet),
		};
		// Mark this transaction as containing a delete operation
		self.store_deletes();
		// Return result
		Ok(())
	}

	/// Count the total number of keys within a range.
	///
	/// `count()` has no `ScanLimit` parameter, so it always iterates the
	/// entire provided key range without an early-exit limit. It is therefore
	/// always offloaded to the blocking threadpool to avoid stalling the
	/// async executor during the full range scan.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn count(&self, rng: Range<Key>, version: Option<u64>) -> Result<usize> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Always offload to the blocking threadpool
		affinitypool::spawn_local(move || {
			let guard = self.inner.blocking_lock();
			self.count_blocking(rng, version, guard)
		})
		.await
	}

	/// Retrieve a range of keys.
	///
	/// Small bounded scans run inline on the async executor thread to avoid
	/// the cross-thread wakeup latency of the blocking threadpool. Large
	/// bounded scans are offloaded to avoid stalling other async tasks on the
	/// executor. See `ROCKSDB_INLINE_SCAN_THRESHOLD`. The unbounded `count()`
	/// path is always offloaded separately and does not use `ScanLimit`.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn keys(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<Vec<Key>> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(limit, skip, ESTIMATED_BYTES_PER_KEY) {
			affinitypool::spawn_local(move || {
				let guard = self.inner.blocking_lock();
				self.keys_blocking(rng, limit, skip, version, Direction::Forward, guard)
			})
			.await
		} else {
			let guard = self.inner.lock().await;
			self.keys_blocking(rng, limit, skip, version, Direction::Forward, guard)
		}
	}

	/// Retrieve a range of keys, in reverse.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn keysr(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<Vec<Key>> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(limit, skip, ESTIMATED_BYTES_PER_KEY) {
			affinitypool::spawn_local(move || {
				let guard = self.inner.blocking_lock();
				self.keys_blocking(rng, limit, skip, version, Direction::Backward, guard)
			})
			.await
		} else {
			let guard = self.inner.lock().await;
			self.keys_blocking(rng, limit, skip, version, Direction::Backward, guard)
		}
	}

	/// Retrieve a range of key-value pairs.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn scan(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<Vec<(Key, Val)>> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(limit, skip, ESTIMATED_BYTES_PER_KV) {
			affinitypool::spawn_local(move || {
				let guard = self.inner.blocking_lock();
				self.scan_blocking(rng, limit, skip, version, Direction::Forward, guard)
			})
			.await
		} else {
			let guard = self.inner.lock().await;
			self.scan_blocking(rng, limit, skip, version, Direction::Forward, guard)
		}
	}

	/// Retrieve a range of key-value pairs, in reverse.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn scanr(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<Vec<(Key, Val)>> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(limit, skip, ESTIMATED_BYTES_PER_KV) {
			affinitypool::spawn_local(move || {
				let guard = self.inner.blocking_lock();
				self.scan_blocking(rng, limit, skip, version, Direction::Backward, guard)
			})
			.await
		} else {
			let guard = self.inner.lock().await;
			self.scan_blocking(rng, limit, skip, version, Direction::Backward, guard)
		}
	}

	/// Set a new save point on the transaction.
	async fn new_save_point(&self) -> Result<()> {
		let guard = self.inner.lock().await;
		if let Some(state) = guard.as_ref() {
			state.tx.set_savepoint();
		}
		Ok(())
	}

	/// Rollback to the last save point.
	async fn rollback_to_save_point(&self) -> Result<()> {
		let guard = self.inner.lock().await;
		if let Some(state) = guard.as_ref() {
			state.tx.rollback_to_savepoint()?;
		}
		Ok(())
	}

	/// Release the last save point.
	async fn release_last_save_point(&self) -> Result<()> {
		Ok(())
	}

	async fn compact(&self, range: Option<Range<Key>>) -> anyhow::Result<()> {
		let (start, end) = match range {
			Some(r) => (Some(r.start), Some(r.end)),
			None => (None, None),
		};
		self.db.compact_range(start, end);
		Ok(())
	}
}

// Consume and iterate over only keys
fn consume_keys<D: rocksdb::DBAccess>(
	iter: &mut rocksdb::DBRawIteratorWithThreadMode<'_, D>,
	limit: ScanLimit,
	skip: u32,
	dir: Direction,
) -> Result<Vec<Key>> {
	// Skip entries efficiently without allocation
	for _ in 0..skip {
		if iter.valid() {
			match dir {
				Direction::Forward => iter.next(),
				Direction::Backward => iter.prev(),
			}
		} else {
			// Catch any iterator errors
			iter.status()?;
			// Return an empty result
			return Ok(Vec::new());
		}
	}
	let res = match limit {
		ScanLimit::Count(c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Check that we don't exceed the count limit
			while res.len() < c as usize {
				// Check the key
				if let Some(k) = iter.key() {
					res.push(k.to_vec());
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			// Return the result
			res
		}
		ScanLimit::Bytes(b) => {
			// Create the result set
			let mut res = Vec::with_capacity((b / ESTIMATED_BYTES_PER_KEY).min(4096) as usize);
			// Count the bytes fetched
			let mut bytes_fetched = 0usize;
			// Check that we don't exceed the byte limit
			while bytes_fetched < b as usize {
				// Check the key
				if let Some(k) = iter.key() {
					bytes_fetched += k.len();
					res.push(k.to_vec());
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			// Return the result
			res
		}
		ScanLimit::BytesOrCount(b, c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Count the bytes fetched
			let mut bytes_fetched = 0usize;
			// Check that we don't exceed the count limit AND the byte limit
			while res.len() < c as usize && bytes_fetched < b as usize {
				// Check the key
				if let Some(k) = iter.key() {
					bytes_fetched += k.len();
					res.push(k.to_vec());
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			// Return the result
			res
		}
	};
	// Catch any iterator errors
	iter.status()?;
	// Return the result
	Ok(res)
}

// Consume and iterate over keys and values
fn consume_vals<D: rocksdb::DBAccess>(
	iter: &mut rocksdb::DBRawIteratorWithThreadMode<'_, D>,
	limit: ScanLimit,
	skip: u32,
	dir: Direction,
) -> Result<Vec<(Key, Val)>> {
	// Skip entries efficiently without allocation
	for _ in 0..skip {
		if iter.valid() {
			match dir {
				Direction::Forward => iter.next(),
				Direction::Backward => iter.prev(),
			}
		} else {
			// Catch any iterator errors
			iter.status()?;
			// Return an empty result
			return Ok(Vec::new());
		}
	}
	let res = match limit {
		ScanLimit::Count(c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Check that we don't exceed the count limit
			while res.len() < c as usize {
				// Check the key and value
				if let Some((k, v)) = iter.item() {
					res.push((k.to_vec(), v.to_vec()));
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			// Return the result
			res
		}
		ScanLimit::Bytes(b) => {
			// Create the result set
			let mut res = Vec::with_capacity((b / ESTIMATED_BYTES_PER_KV).min(4096) as usize);
			// Count the bytes fetched
			let mut bytes_fetched = 0usize;
			// Check that we don't exceed the byte limit
			while bytes_fetched < b as usize {
				// Check the key and value
				if let Some((k, v)) = iter.item() {
					bytes_fetched += k.len() + v.len();
					res.push((k.to_vec(), v.to_vec()));
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			// Return the result
			res
		}
		ScanLimit::BytesOrCount(b, c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Count the bytes fetched
			let mut bytes_fetched = 0usize;
			// Check that we don't exceed the count limit AND the byte limit
			while res.len() < c as usize && bytes_fetched < b as usize {
				// Check the key and value
				if let Some((k, v)) = iter.item() {
					bytes_fetched += k.len() + v.len();
					res.push((k.to_vec(), v.to_vec()));
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			// Return the result
			res
		}
	};
	// Catch any iterator errors
	iter.status()?;
	// Return the result
	Ok(res)
}
