#![cfg(feature = "kv-rocksdb")]

mod background_flusher;
mod cnf;
mod commit_coordinator;
mod comparator;
mod disk_space_manager;
mod garbage_collector;
mod memory_manager;
mod prefix_extractor;
mod range_shard;
#[cfg(test)]
mod tests;

use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use background_flusher::BackgroundFlusher;
pub use cnf::RocksDbConfig;
use commit_coordinator::CommitCoordinator;
use disk_space_manager::{DiskSpaceManager, DiskSpaceState, TransactionState};
use garbage_collector::GarbageCollector;
use memory_manager::MemoryManager;
use range_shard::{COUNT_PARALLEL_MAX_SHARDS, shard_range};
use rocksdb::{
	BottommostLevelCompaction, ColumnFamilyDescriptor, CompactOptions, DBCompactionStyle,
	DBCompressionType, FlushOptions, LogLevel, OptimisticTransactionDB,
	OptimisticTransactionOptions, Options, ReadOptions, SnapshotWithThreadMode,
	UniversalCompactOptions, UniversalCompactionStopStyle, WaitForCompactOptions, WriteOptions,
	properties,
};
use tokio::sync::{Mutex, MutexGuard};

use super::api::{GetMultiResult, KeysResult, ScanLimit, ScanResult};
use super::config::SyncMode;
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
	/// Whether the custom SurrealDB prefix extractor is enabled on the
	/// column family. Propagated to each transaction so range scans can
	/// pick the correct prefix-seek mode without consulting global state.
	prefix_extractor_enabled: bool,
	/// threshold of estimated size above which we run a scan in separate thread.
	inline_scan_threshold: u32,
	/// Whether scan/count `ReadOptions` set `verify_checksums(true)`.
	/// When false, CRC32C verification is skipped on cold block reads.
	scan_verify_checksums: bool,
	/// Whether `shutdown` should run a full-keyspace compaction (down to
	/// the bottommost level) after flushing memtables. Off by default —
	/// the operation is O(database size) and is intended for maintenance
	/// shutdowns rather than the SIGTERM-grace-period path.
	compact_on_shutdown: bool,
	/// Timeout (seconds) for the post-flush `wait_for_compact` step
	/// during shutdown. `0` waits indefinitely.
	shutdown_wait_for_compact_seconds: u64,
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
	/// Whether the custom SurrealDB prefix extractor is enabled on the
	/// column family. Controls whether `apply_prefix_mode` sets
	/// `prefix_same_as_start` / `total_order_seek` on scan `ReadOptions`.
	prefix_extractor_enabled: bool,
	/// threshold of estimated size above which we run a scan in separate thread.
	inline_scan_threshold: u32,
	/// Whether scan/count `ReadOptions` set `verify_checksums(true)`.
	scan_verify_checksums: bool,
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

/// Apply the column-family-level RocksDB options derived from `config`
/// to `target`. Keeping these grouped in one helper means that when
/// versioning is enabled - and the default CF is opened via an
/// explicit `ColumnFamilyDescriptor` with its own options - the
/// explicit CF receives the same compaction, blob, compression and
/// prefix-filter settings as the implicit default CF would have
/// inherited from the main `opts`.
fn apply_cf_level_options(target: &mut Options, config: &RocksDbConfig) {
	// Set the target file size for compaction
	info!(target: TARGET, "Target file size for compaction: {}", config.target_file_size_base);
	target.set_target_file_size_base(config.target_file_size_base);
	// Set the levelled target file size multipler
	let size_multiplier = config.target_file_size_multiplier.min(i32::MAX as usize) as i32;
	info!(target: TARGET, "Target file size compaction multiplier: {size_multiplier}");
	target.set_target_file_size_multiplier(size_multiplier);
	// Delay compaction until the minimum number of files accumulate
	let compaction_trigger = config.file_compaction_trigger.min(i32::MAX as usize) as i32;
	info!(target: TARGET, "Number of files to trigger compaction: {compaction_trigger}");
	target.set_level_zero_file_num_compaction_trigger(compaction_trigger);
	// L0 file-count watermark at which writes start to self-throttle.
	info!(target: TARGET, "Level-0 slowdown writes trigger: {}", config.level0_slowdown_writes_trigger);
	target.set_level_zero_slowdown_writes_trigger(config.level0_slowdown_writes_trigger);
	// L0 file-count watermark at which writes are halted entirely.
	info!(target: TARGET, "Level-0 stop writes trigger: {}", config.level0_stop_writes_trigger);
	target.set_level_zero_stop_writes_trigger(config.level0_stop_writes_trigger);
	// Periodic compaction safety net for cold ranges.
	if config.periodic_compaction_seconds > 0 {
		info!(target: TARGET, "Periodic compaction seconds: {}", config.periodic_compaction_seconds);
		target.set_periodic_compaction_seconds(config.periodic_compaction_seconds);
	} else {
		info!(target: TARGET, "Periodic compaction: disabled");
	}
	// Enable separation of keys and values
	info!(target: TARGET, "Enable separation of keys and values: {}", config.enable_blob_files);
	target.set_enable_blob_files(config.enable_blob_files);
	// Store large values separate from keys
	info!(target: TARGET, "Minimum blob value size: {}", config.min_blob_size);
	target.set_min_blob_size(config.min_blob_size);
	// Additional blob file options
	info!(target: TARGET, "Target blob file size: {}", config.blob_file_size);
	target.set_blob_file_size(config.blob_file_size);
	// Set the blob compression type
	let (db_compression, name) = match config.blob_compression_type {
		cnf::BlobCompression::Snappy => (DBCompressionType::Snappy, "snappy"),
		cnf::BlobCompression::Lz4 => (DBCompressionType::Lz4, "lz4"),
		cnf::BlobCompression::Zstd => (DBCompressionType::Zstd, "zstd"),
		cnf::BlobCompression::None => (DBCompressionType::None, "none"),
	};
	info!(target: TARGET, "Blob compression type: {name}");
	target.set_blob_compression_type(db_compression);
	// Whether to enable blob garbage collection
	info!(target: TARGET, "Enable blob garbage collection: {}", config.enable_blob_gc);
	target.set_enable_blob_gc(config.enable_blob_gc);
	// Set the blob garbage collection age cutoff
	info!(target: TARGET, "Blob GC age cutoff: {}", config.blob_gc_age_cutoff);
	target.set_blob_gc_age_cutoff(config.blob_gc_age_cutoff);
	// Set the blob garbage collection force threshold
	info!(target: TARGET, "Blob GC force threshold: {}", config.blob_gc_force_threshold);
	target.set_blob_gc_force_threshold(config.blob_gc_force_threshold);
	// Set the blob compaction readahead size
	info!(target: TARGET, "Blob compaction readahead size: {}", config.blob_compaction_readahead_size);
	target.set_blob_compaction_readahead_size(config.blob_compaction_readahead_size);
	// Set the delete compaction factory
	info!(target: TARGET, "Setting delete compaction factory: {} / {} ({})",
		config.deletion_factory_window_size,
		config.deletion_factory_delete_count,
		config.deletion_factory_ratio,
	);
	target.add_compact_on_deletion_collector_factory(
		config.deletion_factory_window_size,
		config.deletion_factory_delete_count,
		config.deletion_factory_ratio,
	);
	// Set the datastore compaction style
	info!(target: TARGET, "Setting compaction style: {}", config.compaction_style);
	let style = match config.compaction_style.to_ascii_lowercase().as_str() {
		"universal" => DBCompactionStyle::Universal,
		_ => DBCompactionStyle::Level,
	};
	target.set_compaction_style(style);
	// Universal-compaction-specific options
	if matches!(style, DBCompactionStyle::Universal) {
		// Create the universal compaction options
		let mut uco = UniversalCompactOptions::default();
		// Set the intended size ratio
		info!(target: TARGET, "Universal compaction size ratio: {}", config.universal_size_ratio);
		uco.set_size_ratio(config.universal_size_ratio);
		// Set the minimum merge width
		let min = config.universal_min_merge_width.min(i32::MAX as u32);
		info!(target: TARGET, "Universal compaction min merge width: {min}");
		uco.set_min_merge_width(min as i32);
		// Set the maximum merge width
		let max = config.universal_max_merge_width.min(i32::MAX as u32);
		info!(target: TARGET, "Universal compaction max merge width: {max}");
		uco.set_max_merge_width(max as i32);
		// Set the max size amplification percentage
		let amp_pct = config.universal_max_size_amplification_percent.min(i32::MAX as u32);
		info!(target: TARGET, "Universal compaction max size amplification percent: {amp_pct}");
		uco.set_max_size_amplification_percent(amp_pct as i32);
		// Set the compression size percentage. Note this field is `i32`
		// rather than `u32` because RocksDB uses `-1` as the sentinel
		// meaning "compress all output"; no clamp is needed.
		let compress_pct = config.universal_compression_size_percent;
		info!(target: TARGET, "Universal compaction compression size percent: {compress_pct}");
		uco.set_compression_size_percent(compress_pct);
		// Set the compaction stop style
		let style = config.universal_stop_style.to_ascii_lowercase();
		info!(target: TARGET, "Universal compaction stop style: {style}");
		uco.set_stop_style(match style.as_str() {
			"similar_size" | "similar" => UniversalCompactionStopStyle::Similar,
			_ => UniversalCompactionStopStyle::Total,
		});
		// Set the universal compaction options
		target.set_universal_compaction_options(&uco);
	}
	// Set specific compression levels
	info!(target: TARGET, "Setting compression level");
	target.set_compression_per_level(&[
		DBCompressionType::None, // L0
		DBCompressionType::Lz4,  // L1
		DBCompressionType::Lz4,  // L2
		DBCompressionType::Lz4,  // L3
		DBCompressionType::Lz4,  // L4
		DBCompressionType::Zstd, // L5
		DBCompressionType::Zstd, // L6
		DBCompressionType::Zstd, // L7
	]);
	// Set the bottommost compression type
	info!(target: TARGET, "Setting bottommost compression type: Zstd");
	target.set_bottommost_compression_type(DBCompressionType::Zstd);
	// Use Zstd typed dictionary training
	info!(target: TARGET, "Using Zstd typed dictionary training");
	target.set_bottommost_zstd_max_train_bytes(0, true);
	// Configure the custom table-level prefix extractor. See
	// `prefix_extractor.rs` for the semantics.
	if config.prefix_extractor_enabled {
		info!(target: TARGET, "Prefix extractor: enabled ({})", prefix_extractor::NAME);
		target.set_prefix_extractor(prefix_extractor::build());
		let ratio = config.memtable_prefix_bloom_ratio;
		if ratio > 0.0 {
			info!(target: TARGET, "Memtable prefix bloom ratio: {ratio}");
			target.set_memtable_prefix_bloom_ratio(ratio);
		}
	} else {
		info!(target: TARGET, "Prefix extractor: disabled");
	}
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
		let threads = config.thread_count.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Background thread count: {threads}");
		opts.increase_parallelism(threads);
		// Specify the max concurrent background jobs
		let background_jobs = config.jobs_count.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Maximum background jobs count: {background_jobs}");
		opts.set_max_background_jobs(background_jobs);
		// Set the maximum number of open files that can be used by the database
		let max_open_files = config.max_open_files.min(i32::MAX as usize) as i32;
		info!(target: TARGET, "Maximum number of open files: {max_open_files}");
		opts.set_max_open_files(max_open_files);
		// Set the number of log files to keep
		info!(target: TARGET, "Number of log files to keep: {}", config.keep_log_file_num);
		opts.set_keep_log_file_num(config.keep_log_file_num);
		// Set the compaction readahead size
		info!(target: TARGET, "Compaction readahead size: {}", config.compaction_readahead_size);
		opts.set_compaction_readahead_size(config.compaction_readahead_size);
		// Set the max number of subcompactions
		info!(target: TARGET, "Maximum concurrent subcompactions: {}", config.max_concurrent_subcompactions);
		opts.set_max_subcompactions(config.max_concurrent_subcompactions);
		// Use separate write thread queues
		info!(target: TARGET, "Use separate thread queues: {}", config.enable_pipelined_writes);
		opts.set_enable_pipelined_write(config.enable_pipelined_writes);
		// Set the write-ahead-log size limit in MB
		info!(target: TARGET, "Write-ahead-log file size limit: {}MB", config.wal_size_limit);
		opts.set_wal_size_limit_mb(config.wal_size_limit);
		// Allow multiple writers to update memtables in parallel
		info!(target: TARGET, "Allow concurrent memtable writes: true");
		opts.set_allow_concurrent_memtable_write(true);
		// Avoid unnecessary blocking io, preferring background threads
		info!(target: TARGET, "Avoid unnecessary blocking IO: true");
		opts.set_avoid_unnecessary_blocking_io(true);
		// Improve concurrency from write batch mutex
		info!(target: TARGET, "Allow adaptive write thread yielding: true");
		opts.set_enable_write_thread_adaptive_yield(true);
		// Set specific storage log level
		info!(target: TARGET, "Setting storage engine log level: {}", config.storage_log_level);
		opts.set_log_level(match config.storage_log_level.to_ascii_lowercase().as_str() {
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
		// Apply the column-family-level settings to the main `opts`. These
		// govern the implicit default CF used when versioning is disabled;
		// when versioning is enabled the same settings are mirrored onto
		// the explicit CF descriptor's options below.
		apply_cf_level_options(&mut opts, &config);
		// Configure and create the memory manager. This also applies its
		// per-CF settings (write buffer size, max/min memtables,
		// block-based table factory, blob cache) to `opts`.
		let memory_manager = Arc::new(MemoryManager::configure(&mut opts, &config)?);
		// Configure the timestamp-aware comparator for user-defined
		// timestamps. When versioning is enabled we open the database
		// with an explicit default CF descriptor; RocksDB uses this
		// descriptor's options for CF-level settings, so every CF-level
		// setting applied above on `opts` must also be applied here.
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
			apply_cf_level_options(&mut cf_opts, &config);
			memory_manager.apply_to_cf_options(&mut cf_opts, &config);
			Some(cf_opts)
		} else {
			None
		};
		// Pre-configure the disk space manager
		let should_create_disk_space_manager = DiskSpaceManager::configure(&mut opts, &config)?;
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
			Some(Arc::new(DiskSpaceManager::new(&mut opts, &config)?))
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
			Some(Arc::new(CommitCoordinator::new(db.clone(), &config)?))
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
		let garbage_collector = if config.versioned && config.retention != Duration::ZERO {
			Some(Arc::new(GarbageCollector::new(db.clone(), config.retention)?))
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
			prefix_extractor_enabled: config.prefix_extractor_enabled,
			inline_scan_threshold: config.inline_scan_threshold,
			scan_verify_checksums: config.scan_verify_checksums,
			compact_on_shutdown: config.compact_on_shutdown,
			shutdown_wait_for_compact_seconds: config.shutdown_wait_for_compact_seconds,
		})
	}

	const BLOCK_CACHE_USAGE: &str = "rocksdb.block_cache_usage";
	const BLOCK_CACHE_PINNED_USAGE: &str = "rocksdb.block_cache_pinned_usage";
	const ESTIMATE_TABLE_READERS_MEM: &str = "rocksdb.estimate_table_readers_mem";
	const CUR_SIZE_ALL_MEM_TABLES: &str = "rocksdb.cur_size_all_mem_tables";
	const TOTAL_SST_FILES_SIZE: &str = "rocksdb.total_sst_files_size";
	const LIVE_SST_FILES_SIZE: &str = "rocksdb.live_sst_files_size";
	const ESTIMATE_LIVE_DATA_SIZE: &str = "rocksdb.estimate_live_data_size";
	const ESTIMATE_NUM_KEYS: &str = "rocksdb.estimate_num_keys";
	const COMPACTION_PENDING: &str = "rocksdb.compaction_pending";
	const NUM_RUNNING_COMPACTIONS: &str = "rocksdb.num_running_compactions";
	const NUM_RUNNING_FLUSHES: &str = "rocksdb.num_running_flushes";

	/// Registers metrics for the RocksDB datastore.
	///
	/// The first four metrics capture memory usage; the remainder expose
	/// on-disk size, logical data size, compaction, and flush activity so
	/// operators can alert on stalled LSM trees. Every metric is a direct
	/// RocksDB `property_int_value` lookup and is therefore O(1).
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
				Metric {
					name: Self::TOTAL_SST_FILES_SIZE,
					description: "Total on-disk size (bytes) of all SST files, including obsolete ones that are still referenced by snapshots.",
				},
				Metric {
					name: Self::LIVE_SST_FILES_SIZE,
					description: "On-disk size (bytes) of SST files referenced by the current LSM tree.",
				},
				Metric {
					name: Self::ESTIMATE_LIVE_DATA_SIZE,
					description: "Estimated logical live data size (bytes) after applying tombstones.",
				},
				Metric {
					name: Self::ESTIMATE_NUM_KEYS,
					description: "Estimated number of live keys in the LSM tree.",
				},
				Metric {
					name: Self::COMPACTION_PENDING,
					description: "1 if a compaction is pending, 0 otherwise.",
				},
				Metric {
					name: Self::NUM_RUNNING_COMPACTIONS,
					description: "Number of compactions currently running.",
				},
				Metric {
					name: Self::NUM_RUNNING_FLUSHES,
					description: "Number of memtable flushes currently running.",
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
			Self::TOTAL_SST_FILES_SIZE => Some(properties::TOTAL_SST_FILES_SIZE),
			Self::LIVE_SST_FILES_SIZE => Some(properties::LIVE_SST_FILES_SIZE),
			Self::ESTIMATE_LIVE_DATA_SIZE => Some(properties::ESTIMATE_LIVE_DATA_SIZE),
			Self::ESTIMATE_NUM_KEYS => Some(properties::ESTIMATE_NUM_KEYS),
			Self::COMPACTION_PENDING => Some(properties::COMPACTION_PENDING),
			Self::NUM_RUNNING_COMPACTIONS => Some(properties::NUM_RUNNING_COMPACTIONS),
			Self::NUM_RUNNING_FLUSHES => Some(properties::NUM_RUNNING_FLUSHES),
			_ => None,
		};
		metric.map(|metric| {
			self.db.property_int_value(metric).unwrap_or_default().unwrap_or_default()
		})
	}

	/// Gracefully shut down the database.
	///
	/// Order of operations matters and is documented inline. Roughly:
	///
	/// 1. Stop the application-level pumps (garbage collector, background flusher, commit
	///    coordinator) so nothing schedules new work.
	/// 2. Flush the WAL to storage and the memtables to L0 SSTs so the next startup needs minimal
	///    recovery.
	/// 3. *Optionally* run a full-keyspace compaction (`compact_on_shutdown`) down to the
	///    bottommost level, mirroring `ALTER SYSTEM COMPACT`.
	/// 4. Drain in-flight compactions with a bounded `wait_for_compact` so we do not abandon work
	///    that was already in progress (typical case: the flush above just produced an L0 file that
	///    tripped `level_zero_file_num_compaction_trigger`).
	/// 5. `cancel_all_background_work(wait=true)` so the bg thread pool is drained cleanly before
	///    the `Arc<OptimisticTransactionDB>` is dropped.
	/// 6. Shut down the memory manager.
	///
	/// Steps 1, 2, and 6 already existed; 3-5 are new. All errors are
	/// logged-and-continued rather than propagated: a partial shutdown is
	/// always better than panicking on the way out.
	pub(crate) async fn shutdown(&self) -> Result<()> {
		// (1) Stop the application-level pumps so nothing schedules new
		//     compactions / flushes / commits while we tear the LSM down.
		if let Some(garbage_collector) = &self.garbage_collector {
			garbage_collector.shutdown()?;
		}
		if let Some(background_flusher) = &self.background_flusher {
			background_flusher.shutdown()?;
		}
		if let Some(commit_coordinator) = &self.commit_coordinator {
			commit_coordinator.shutdown()?;
		}
		// (2) Build the flush options once: every flush waits for completion.
		let mut flush_opts = FlushOptions::default();
		flush_opts.set_wait(true);
		// (2a) Flush the WAL so anything sitting in the WAL buffer is
		//      fsynced to disk before we touch the memtable.
		if let Err(e) = self.db.flush_wal(true) {
			error!("An error occurred flushing the WAL buffer to disk: {e}");
		}
		// (2b) Flush the memtables so the next startup does not have to
		//      replay them from the WAL.
		if let Err(e) = self.db.flush_opt(&flush_opts) {
			error!("An error occurred flushing memtables to SST files: {e}");
		}
		// (3-5) Offload the LSM-cleanup steps to the affinity pool because
		//       `compact_range_opt` and `wait_for_compact` are synchronous
		//       and can block for a long time on large databases. We do not
		//       want to stall the async runtime for the duration.
		let compact_on_shutdown = self.compact_on_shutdown;
		let wait_for_compact_seconds = self.shutdown_wait_for_compact_seconds;
		let cleanup: anyhow::Result<()> = affinitypool::spawn_local(move || {
			// (3) Optional full-keyspace compaction. Mirrors the
			//     `Transactable::compact` impl: change_level=true,
			//     target_level=6, bottommost_level_compaction=Force so
			//     the data lands at the configured bottommost-Zstd
			//     level and superseded versions there are rewritten
			//     away. Skipped by default because it is O(database
			//     size).
			if compact_on_shutdown {
				info!(
					target: TARGET,
					"Running full-keyspace compaction on shutdown",
				);
				let mut copts = CompactOptions::default();
				copts.set_exclusive_manual_compaction(true);
				copts.set_change_level(true);
				copts.set_target_level(6);
				copts.set_bottommost_level_compaction(BottommostLevelCompaction::Force);
				// Turbofish required: with `None, None` the compiler
				// cannot otherwise infer the byte-slice types.
				self.db.compact_range_opt::<&[u8], &[u8]>(None, None, &copts);
			}
			// (4) Drain in-flight compactions. After the memtable flush
			//     above, the new L0 file may have crossed
			//     `level_zero_file_num_compaction_trigger`; waiting for
			//     that to settle means the next startup does not have
			//     to recover or re-perform the work.
			let mut wfco = WaitForCompactOptions::default();
			// `set_timeout` takes microseconds. `0` waits indefinitely.
			let timeout_us = wait_for_compact_seconds.saturating_mul(1_000_000);
			wfco.set_timeout(timeout_us);
			info!(
				target: TARGET,
				"Waiting for in-flight compactions to drain (timeout: {wait_for_compact_seconds}s)",
			);
			if let Err(e) = self.db.wait_for_compact(&wfco) {
				error!("An error occurred waiting for compactions to drain: {e}");
			}
			// (5) Cancel any remaining scheduled bg work and wait for
			//     currently-running jobs to finish. After this point
			//     RocksDB will not start any new flush or compaction.
			info!(target: TARGET, "Cancelling background work");
			self.db.cancel_all_background_work(true);
			Ok(())
		})
		.await;
		if let Err(e) = cleanup {
			error!("An error occurred during shutdown cleanup: {e}");
		}
		// (6) Shut down the memory manager last, after we are sure no
		//     bg thread is going to touch the write buffer manager.
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
			prefix_extractor_enabled: self.prefix_extractor_enabled,
			inline_scan_threshold: self.inline_scan_threshold,
			scan_verify_checksums: self.scan_verify_checksums,
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

	/// Apply the appropriate prefix-seek setting to the read options used
	/// by a range scan.
	///
	/// With a prefix extractor configured on the column family, iterators
	/// have two safe modes:
	///
	/// * `prefix_same_as_start(true)` — the iterator stays within the extracted prefix of the seek
	///   key. This is what lets RocksDB skip SSTs via the per-SST prefix bloom filter and terminate
	///   `FindNextUserEntry` early at prefix boundaries. We enable it only when *both* range
	///   endpoints are in-domain AND resolve to the same extracted prefix (all common record /
	///   index / graph / ref scans satisfy this).
	/// * `total_order_seek(true)` — the iterator does a total-order seek and ignores the prefix
	///   extractor. This is required for catalog scans whose bounds live outside the prefix
	///   extractor's domain (e.g. listing tables, indexes, users, etc.); without it RocksDB
	///   documents the returned keys as "undefined" when the upper bound has a different prefix
	///   than the seek key.
	///
	/// When the prefix extractor is disabled at the datastore level,
	/// neither option is set (default behaviour).
	fn apply_prefix_mode(&self, ro: &mut ReadOptions, rng: &Range<Key>) {
		// Check if the prefix extractor is enabled
		if !self.prefix_extractor_enabled {
			return;
		}
		// Check if the bounds are in-domain and share the same extracted prefix
		match (prefix_extractor::extract(&rng.start), prefix_extractor::extract(&rng.end)) {
			// Both bounds are in-domain and share the same extracted prefix:
			// safe to enable prefix-scan optimisations. This is the hot path
			// for record and index scans.
			(Some(sp), Some(ep)) if sp == ep => {
				ro.set_prefix_same_as_start(true);
			}
			// Any other case: either one or both bounds are out-of-domain,
			// or they sit in different prefixes. Fall back to total-order
			// seek so we keep correctness at the cost of prefix bloom
			// filter optimisations.
			_ => {
				ro.set_total_order_seek(true);
			}
		}
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
		ro.set_auto_readahead_size(true);
		ro.set_async_io(true);
		ro.fill_cache(true);
		ro.set_verify_checksums(self.scan_verify_checksums);
		self.apply_prefix_mode(&mut ro, rng);
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
		ro.set_auto_readahead_size(true);
		ro.set_async_io(true);
		ro.fill_cache(false);
		ro.set_verify_checksums(self.scan_verify_checksums);
		self.apply_prefix_mode(&mut ro, rng);
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
	fn should_offload(threshold: u32, limit: ScanLimit, skip: u32, bytes_per_entry: u32) -> bool {
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
	) -> Result<KeysResult> {
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
	) -> Result<ScanResult> {
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
	async fn getm(&self, keys: Vec<Key>, version: Option<u64>) -> Result<GetMultiResult> {
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
		// Convert result, accumulating the hit count and value bytes during
		// the same pass so callers do not need to re-walk the result.
		let mut records = 0u64;
		let mut value_bytes = 0u64;
		let values = res
			.into_iter()
			.map(|r| match r {
				Ok(Some(v)) => {
					records += 1;
					value_bytes += v.len() as u64;
					Ok(Some(v))
				}
				Ok(None) => Ok(None),
				Err(e) => Err(e.into()),
			})
			.collect::<Result<Vec<Option<Val>>>>()?;
		Ok(GetMultiResult {
			values,
			records,
			value_bytes,
		})
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
	///
	/// Writable transactions iterate the inner transaction so that pending
	/// writes are merged into the count, and run as a single serial scan.
	/// Read-only transactions shard the range across the affinitypool and
	/// scan all shards in parallel against a shared snapshot, which is a
	/// significant speed-up on large ranges (e.g. full-table `COUNT(*)`).
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
		// Writable transactions iterate on the inner transaction so that
		// pending writes are visible; this cannot safely be sharded across
		// threads, so we fall back to a single serial scan.
		if self.write {
			return affinitypool::spawn_local(move || {
				// Acquire the inner lock inside the task
				let guard = self.inner.blocking_lock();
				// Run the serial count
				self.count_blocking(rng, version, guard)
			})
			.await;
		}
		// Decide how many shards to dispatch, bounded by the machine
		// parallelism so we don't oversubscribe the affinitypool, and
		// further bounded by `COUNT_PARALLEL_MAX_SHARDS` so very large
		// CPU counts don't produce many tiny shards that all touch the
		// same SSTs.
		let desired = std::thread::available_parallelism()
			.map(|n| n.get())
			.unwrap_or(8)
			.min(COUNT_PARALLEL_MAX_SHARDS);
		// Compute the disjoint sub-ranges that together cover `[start, end)`.
		// Returns a single shard when the range is too narrow to split
		// meaningfully along its first differing byte.
		let sub_ranges = shard_range(&rng.start, &rng.end, desired);
		// Fall back to a single serial scan when the range is too narrow
		// to split: dispatching a single shard would just add the overhead
		// of an extra task hop with no parallelism benefit.
		if sub_ranges.len() <= 1 {
			return affinitypool::spawn_local(move || {
				// Acquire the inner lock inside the task
				let guard = self.inner.blocking_lock();
				// Run the serial count
				self.count_blocking(rng, version, guard)
			})
			.await;
		}
		// Build all shard `ReadOptions` under the inner lock so each shard
		// captures the same snapshot pointer. The lock is dropped before
		// dispatching shards: the snapshot stays alive for as long as
		// `inner.tx` is alive (owned by this `Transaction`), and read-only
		// transactions never take the inner out of the mutex.
		let scans = {
			// Acquire the inner lock
			let guard = self.inner.lock().await;
			// Get the inner transaction state
			let inner =
				guard.as_ref().ok_or_else(|| Error::Internal("expected a transaction".into()))?;
			// Build one (sub-range, ReadOptions) pair per shard
			sub_ranges
				.into_iter()
				.map(|(lo, hi)| {
					// Construct the shard's sub-range
					let sub_rng = lo..hi;
					// Build the ReadOptions for this shard
					let ro = self.count_read_options(&sub_rng, version, inner);
					(sub_rng, ro)
				})
				.collect::<Vec<_>>()
		};
		let mut tasks = Vec::with_capacity(scans.len());
		for (sub_rng, ro) in scans {
			// Clone the Arc'd handle so each shard owns its own reference
			let db = self.db.clone();
			tasks.push(affinitypool::spawn_local(move || -> Result<usize> {
				// Create the iterator on the database
				let mut iter = db.raw_iterator_opt(ro);
				// Seek to the start key
				iter.seek(&sub_rng.start);
				// Initialize the per-shard count
				let mut res: usize = 0;
				// Count the items
				while iter.valid() {
					res += 1;
					iter.next();
				}
				// Catch any iterator errors
				iter.status()?;
				// Return the per-shard count
				Ok(res)
			}));
		}
		// Run all shard scans concurrently and sum the per-shard counts
		let counts = futures::future::try_join_all(tasks).await?;
		// Return result
		Ok(counts.into_iter().sum())
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
	) -> Result<KeysResult> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(self.inline_scan_threshold, limit, skip, ESTIMATED_BYTES_PER_KEY) {
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
	) -> Result<KeysResult> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(self.inline_scan_threshold, limit, skip, ESTIMATED_BYTES_PER_KEY) {
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
	) -> Result<ScanResult> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(self.inline_scan_threshold, limit, skip, ESTIMATED_BYTES_PER_KV) {
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
	) -> Result<ScanResult> {
		// Versioned queries require a versioned datastore
		if !self.versioned && version.is_some() {
			return Err(Error::UnsupportedVersionedQueries);
		}
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Dispatch inline for small bounded scans, offload for large bounded
		if Self::should_offload(self.inline_scan_threshold, limit, skip, ESTIMATED_BYTES_PER_KV) {
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
		// Create new flush options
		let mut fopts = FlushOptions::default();
		// Wait for the sync to finish
		fopts.set_wait(true);
		// Create new compact options
		let mut copts = CompactOptions::default();
		// Set the exclusive manual compaction flag
		copts.set_exclusive_manual_compaction(true);
		// Allow files to move to a higher level
		copts.set_change_level(true);
		// Set the target level for SSTs
		copts.set_target_level(6);
		// Force the bottommost SSTs to be rewritten
		copts.set_bottommost_level_compaction(BottommostLevelCompaction::Force);
		// Spawn a new task to compact the range
		affinitypool::spawn_local(move || {
			// Flush the WAL to storage
			self.db.flush_wal(true)?;
			// Flush the memtables to SST
			self.db.flush_opt(&fopts)?;
			// Get the compaction range
			let (start, end) = match range {
				Some(r) => (Some(r.start), Some(r.end)),
				None => (None, None),
			};
			// Compact the specified range with the bottommost target.
			self.db.compact_range_opt(start, end, &copts);
			// All ok
			Ok(())
		})
		.await
	}
}

// Consume and iterate over only keys
fn consume_keys<D: rocksdb::DBAccess>(
	iter: &mut rocksdb::DBRawIteratorWithThreadMode<'_, D>,
	limit: ScanLimit,
	skip: u32,
	dir: Direction,
) -> Result<KeysResult> {
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
			return Ok(KeysResult::default());
		}
	}
	let mut key_bytes = 0u64;
	let keys = match limit {
		ScanLimit::Count(c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Check that we don't exceed the count limit
			while res.len() < c as usize {
				// Check the key
				if let Some(k) = iter.key() {
					key_bytes += k.len() as u64;
					res.push(k.to_vec());
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			res
		}
		ScanLimit::Bytes(b) => {
			// Create the result set
			let mut res = Vec::with_capacity((b / ESTIMATED_BYTES_PER_KEY).min(4096) as usize);
			// Check that we don't exceed the byte limit
			while key_bytes < b as u64 {
				// Check the key
				if let Some(k) = iter.key() {
					key_bytes += k.len() as u64;
					res.push(k.to_vec());
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			res
		}
		ScanLimit::BytesOrCount(b, c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Check that we don't exceed the count limit AND the byte limit
			while res.len() < c as usize && key_bytes < b as u64 {
				// Check the key
				if let Some(k) = iter.key() {
					key_bytes += k.len() as u64;
					res.push(k.to_vec());
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			res
		}
	};
	// Catch any iterator errors
	iter.status()?;
	// Return the result
	Ok(KeysResult {
		keys,
		key_bytes,
	})
}

// Consume and iterate over keys and values
fn consume_vals<D: rocksdb::DBAccess>(
	iter: &mut rocksdb::DBRawIteratorWithThreadMode<'_, D>,
	limit: ScanLimit,
	skip: u32,
	dir: Direction,
) -> Result<ScanResult> {
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
			return Ok(ScanResult::default());
		}
	}
	// Track the cumulative bytes for the metric. The byte-bounded limit
	// branches still rely on `bytes_fetched` (key + value bytes) to decide
	// when to stop, so the two counters are kept separate.
	let mut key_bytes = 0u64;
	let mut value_bytes = 0u64;
	let values = match limit {
		ScanLimit::Count(c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Check that we don't exceed the count limit
			while res.len() < c as usize {
				// Check the key and value
				if let Some((k, v)) = iter.item() {
					key_bytes += k.len() as u64;
					value_bytes += v.len() as u64;
					res.push((k.to_vec(), v.to_vec()));
					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			res
		}
		ScanLimit::Bytes(b) => {
			// Create the result set
			let mut res = Vec::with_capacity((b / ESTIMATED_BYTES_PER_KV).min(4096) as usize);
			// Count the bytes fetched
			let mut bytes_fetched = 0u64;
			// Check that we don't exceed the byte limit
			while bytes_fetched < b as u64 {
				// Check the key and value
				if let Some((k, v)) = iter.item() {
					let key_len = k.len() as u64;
					let value_len = v.len() as u64;

					bytes_fetched += key_len + value_len;
					key_bytes += key_len;
					value_bytes += value_len;

					res.push((k.to_vec(), v.to_vec()));

					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			res
		}
		ScanLimit::BytesOrCount(b, c) => {
			// Create the result set
			let mut res = Vec::with_capacity(c.min(4096) as usize);
			// Count the bytes fetched
			let mut bytes_fetched = 0u64;
			// Check that we don't exceed the count limit AND the byte limit
			while res.len() < c as usize && bytes_fetched < b as u64 {
				// Check the key and value
				if let Some((k, v)) = iter.item() {
					let key_len = k.len() as u64;
					let value_len = v.len() as u64;

					bytes_fetched += key_len + value_len;
					key_bytes += key_len;
					value_bytes += value_len;

					res.push((k.to_vec(), v.to_vec()));

					match dir {
						Direction::Forward => iter.next(),
						Direction::Backward => iter.prev(),
					};
				} else {
					break;
				}
			}
			res
		}
	};
	// Catch any iterator errors
	iter.status()?;
	// Return the result
	Ok(ScanResult {
		values,
		key_bytes,
		value_bytes,
	})
}
