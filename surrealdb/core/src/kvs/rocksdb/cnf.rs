use std::str::FromStr;
use std::time::Duration;

use crate::cnf::Config;
use crate::kvs::config::{SyncMode, parse_duration};

// --------------------------------------------------
// Basic options
// --------------------------------------------------

#[derive(Default, Clone, Debug)]
pub enum BlobCompression {
	#[default]
	Snappy,
	Lz4,
	Zstd,
	None,
}

impl FromStr for BlobCompression {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.eq_ignore_ascii_case("none") {
			Ok(Self::None)
		} else if s.eq_ignore_ascii_case("lz4") {
			Ok(Self::Lz4)
		} else if s.eq_ignore_ascii_case("snappy") {
			Ok(Self::Snappy)
		} else if s.eq_ignore_ascii_case("zstd") {
			Ok(Self::Zstd)
		} else {
			Err(())
		}
	}
}

/// Configuration for the RocksDB storage engine, parsed from query parameters.
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
	/// Whether MVCC versioning is enabled.
	pub versioned: bool,
	/// Version retention period in nanoseconds (0 = unlimited).
	pub retention: Duration,
	/// Disk sync mode.
	pub sync_mode: SyncMode,
	/// The number of threads to start for flushing and compaction (default: number
	/// of CPUs)
	pub thread_count: usize,
	/// The maximum number of threads to use for flushing and compaction (default:
	/// number of CPUs * 2)
	pub jobs_count: usize,
	/// The maximum number of open files which can be opened by RocksDB (default:
	/// 1024)
	pub max_open_files: usize,
	/// The size of each uncompressed data block in bytes (default: 64 KiB)
	pub block_size: usize,
	/// The write-ahead-log size limit in MiB (default: 0)
	pub wal_size_limit: u64,
	/// The target file size for compaction in bytes (default: 64 MiB)
	pub target_file_size_base: u64,
	/// The target file size multiplier for each compaction level (default: 2)
	pub target_file_size_multiplier: usize,
	/// The number of files needed to trigger level 0 compaction (default: 4)
	pub file_compaction_trigger: usize,
	/// The readahead buffer size used during compaction
	/// (default: dynamic from 4 MiB to 16 MiB)
	pub compaction_readahead_size: usize,
	/// The maximum number threads which will perform compactions (default: 4)
	pub max_concurrent_subcompactions: u32,
	/// Use separate queues for WAL writes and memtable writes (default: true)
	pub enable_pipelined_writes: bool,
	/// The maximum number of information log files to keep (default: 10)
	pub keep_log_file_num: usize,
	/// The information log level of the RocksDB library (default: "warn")
	pub storage_log_level: String,
	/// Use to specify the database compaction style (default: "level")
	pub compaction_style: String,
	/// The size of the window used to track deletions (default: 1000)
	pub deletion_factory_window_size: usize,
	/// The number of deletions to track in the window (default: 50)
	pub deletion_factory_delete_count: usize,
	/// The ratio of deletions to track in the window (default: 0.5)
	pub deletion_factory_ratio: f64,
	/// Whether to enable separate key and value file storage (default: true)
	pub enable_blob_files: bool,
	/// The minimum size of a value for it to be stored in blob files (default: 4
	/// KiB)
	pub min_blob_size: u64,
	/// The target blob file size (default: 256 MiB)
	pub blob_file_size: u64,
	/// Compression type used for blob files (default: "snappy")
	/// Supported values: "none", "snappy", "lz4", "zstd"
	pub blob_compression_type: BlobCompression,
	/// Whether to enable blob garbage collection (default: true)
	pub enable_blob_gc: bool,
	/// Fractional age cutoff for blob GC eligibility between 0 and 1 (default: 0.5)
	pub blob_gc_age_cutoff: f64,
	/// Discardable ratio threshold to force GC between 0 and 1 (default: 0.5)
	pub blob_gc_force_threshold: f64,
	/// Readahead size for blob compaction/GC (default: 0)
	pub blob_compaction_readahead_size: u64,
	/// The size of the least-recently-used block cache
	/// (default: dynamic depending on system memory)
	pub block_cache_size: usize,
	/// The amount of data each write buffer can build up in memory
	/// (default: dynamic from 32 MiB to 128 MiB)
	pub write_buffer_size: usize,
	/// The maximum number of write buffers which can be used
	/// (default: dynamic from 2 to 32)
	pub max_write_buffer_number: usize,
	/// The minimum number of write buffers to merge before writing to disk
	/// (default: 2)
	pub min_write_buffer_number_to_merge: usize,
	/// The maximum allowed space usage for SST files in bytes (default: 0, meaning unlimited).
	/// When this limit is reached, the datastore enters read-and-deletion-only mode, where only
	/// read and delete operations are allowed. This allows gradual space recovery through data
	/// deletion. Set to 0 to disable space monitoring.
	pub sst_max_allowed_space_usage: u64,
	/// The maximum wait time in nanoseconds before forcing a grouped commit (default: 5ms).
	/// This timeout ensures that transactions don't wait indefinitely under low concurrency and
	/// balances commit latency against write throughput.
	pub grouped_commit_timeout: u64,
	/// Threshold for deciding whether to wait for more transactions (default: 12)
	/// If the current batch size is greater or equal to this threshold (and below
	/// ROCKSDB_GROUPED_COMMIT_MAX_BATCH_SIZE), then the coordinator will wait up to
	/// ROCKSDB_GROUPED_COMMIT_TIMEOUT to collect more transactions. Smaller batches are flushed
	/// immediately to preserve low latency.
	pub grouped_commit_wait_threshold: usize,
	/// The maximum number of transactions in a single grouped commit batch (default: 4096)
	/// This prevents unbounded memory growth while still allowing large batches for efficiency.
	/// Larger batches improve throughput but increase memory usage and commit latency.
	pub grouped_commit_max_batch_size: usize,

	/// The initial readahead size used by RocksDB's implicit (auto) iterator
	/// prefetcher. Once an iterator performs `file_reads_for_auto_readahead`
	/// sequential file reads, RocksDB starts prefetching at this size and then
	/// doubles it on each subsequent read up to `max_auto_readahead_size`
	/// (default: 8 KiB)
	pub initial_auto_readahead_size: usize,
	/// The upper bound on RocksDB's implicit (auto) iterator readahead size.
	/// Raising this cap (from the RocksDB default of 256 KiB) can significantly
	/// improve throughput on long range scans at the cost of additional I/O
	/// and memory per iterator (default: 4 MiB)
	pub max_auto_readahead_size: usize,
	/// The number of sequential file reads an iterator must perform on a
	/// single SST before RocksDB begins its implicit (auto) readahead. Set to
	/// 0 to start prefetching from the very first read (default: 2)
	pub file_reads_for_auto_readahead: u64,

	/// Whether to enable the custom SurrealDB prefix extractor on the
	/// RocksDB column family. When enabled, SST bloom filters are built on
	/// table+category prefixes (records, indexes, graph edges, refs,
	/// per-table metadata) which allows scans to skip entire SSTs that do
	/// not contain the scanning table. See `prefix_extractor.rs` for the
	/// extractor semantics (default: true)
	pub prefix_extractor_enabled: bool,
	/// When the prefix extractor is enabled, controls whether whole keys
	/// are also added to the SST bloom filter (in addition to the prefix).
	/// * true (default): bloom filter carries both whole keys and prefixes. Point lookups benefit
	///   from the whole-key filter, at the cost of a larger bloom filter footprint.
	/// * false: bloom filter carries only prefixes. Smaller bloom filter, but point lookups fall
	///   back to prefix filter + block index search. Useful when the workload is scan-heavy.
	pub whole_key_filtering: bool,
	/// When the prefix extractor is enabled, configures the per-memtable
	/// prefix bloom filter size as a ratio of the write buffer size (capped
	/// at 0.25 by RocksDB). Set to 0 to disable the memtable prefix bloom
	/// (default: 0.1).
	pub memtable_prefix_bloom_ratio: f64,

	/// Scans whose estimated byte size is at or below this threshold execute
	/// inline on the async executor thread; above this threshold they are offloaded
	/// to the blocking threadpool so they do not stall other async tasks. This
	/// applies uniformly to all `ScanLimit` variants: `Bytes(b)` compares `b`
	/// directly, while `Count(c)` and `BytesOrCount(b, c)` convert the entry count
	/// to an approximate byte size using the caller-supplied per-entry size. The
	/// unbounded `count()` path is always offloaded via `affinitypool::spawn_local`
	/// regardless of this value (default: 4 MiB)
	pub inline_scan_threshold: u32,
}

impl Default for RocksDbConfig {
	fn default() -> Self {
		let cpu_count = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
		Self {
			versioned: false,
			retention: Duration::ZERO,
			sync_mode: SyncMode::Every,
			thread_count: cpu_count,
			jobs_count: cpu_count * 2,
			max_open_files: 1026,
			block_size: 64 * 1024,
			wal_size_limit: 0,
			target_file_size_base: 64 * 1024 * 1024,
			target_file_size_multiplier: 2,
			file_compaction_trigger: 4,
			// TODO: Fix to old behavior
			compaction_readahead_size: 16 * 1024 * 1024,
			max_concurrent_subcompactions: 4,
			enable_pipelined_writes: true,
			keep_log_file_num: 10,
			storage_log_level: "warn".to_owned(),
			compaction_style: "level".to_owned(),
			deletion_factory_window_size: 1000,
			deletion_factory_delete_count: 50,
			deletion_factory_ratio: 0.5,
			enable_blob_files: true,
			min_blob_size: 4 * 1024,
			blob_file_size: 256 * 1024 * 1024,
			blob_compression_type: Default::default(),
			enable_blob_gc: true,
			blob_gc_age_cutoff: 0.5,
			blob_gc_force_threshold: 0.5,
			blob_compaction_readahead_size: 0,
			// TODO: Fix to old behavior
			block_cache_size: 16 * 1024 * 1024,
			write_buffer_size: 128 * 1024 * 1024,
			max_write_buffer_number: 32,
			min_write_buffer_number_to_merge: 2,
			sst_max_allowed_space_usage: 0,
			grouped_commit_timeout: Duration::from_millis(5).as_nanos() as u64,
			grouped_commit_wait_threshold: 12,
			grouped_commit_max_batch_size: 4096,
			initial_auto_readahead_size: 8 * 1024,
			max_auto_readahead_size: 4 * 1024 * 1024,
			file_reads_for_auto_readahead: 2,
			prefix_extractor_enabled: true,
			whole_key_filtering: true,
			memtable_prefix_bloom_ratio: 0.1,
			inline_scan_threshold: 4 * 1024 * 1024,
		}
	}
}

impl Config for RocksDbConfig {
	fn parse(&mut self, map: &crate::cnf::ConfigMap) {
		map.parse_key_bool("datastore_versioned", &mut self.versioned)
			.parse_key_with("datastore_retention", &mut self.retention, |x| parse_duration(x).ok())
			.parse_key("rocksdb_thread_count", &mut self.thread_count)
			.parse_key("rocksdb_jobs_count", &mut self.jobs_count)
			.parse_key("rocksdb_max_open_files", &mut self.max_open_files)
			.parse_key("rocksdb_block_size", &mut self.block_size)
			.parse_key("rocksdb_wal_size_limit", &mut self.wal_size_limit)
			.parse_key("rocksdb_target_file_size_base", &mut self.target_file_size_base)
			.parse_key("rocksdb_target_file_size_multiplier", &mut self.target_file_size_multiplier)
			.parse_key("rocksdb_file_compaction_trigger", &mut self.file_compaction_trigger)
			.parse_key("rocksdb_compaction_readahead_size", &mut self.compaction_readahead_size)
			.parse_key(
				"rocksdb_max_concurrent_subcompactions",
				&mut self.max_concurrent_subcompactions,
			)
			.parse_key_bool("rocksdb_enable_pipelined_writes", &mut self.enable_pipelined_writes)
			.parse_key("rocksdb_keep_log_file_num", &mut self.keep_log_file_num)
			.parse_key("rocksdb_storage_log_level", &mut self.storage_log_level)
			.parse_key("rocksdb_compaction_style", &mut self.compaction_style)
			.parse_key(
				"rocksdb_deletion_factory_window_size",
				&mut self.deletion_factory_window_size,
			)
			.parse_key(
				"rocksdb_deletion_factory_delete_count",
				&mut self.deletion_factory_delete_count,
			)
			.parse_key("rocksdb_deletion_factory_ratio", &mut self.deletion_factory_ratio)
			.parse_key_bool("rocksdb_enable_blob_files", &mut self.enable_blob_files)
			.parse_key("rocksdb_min_blob_size", &mut self.min_blob_size)
			.parse_key("rocksdb_blob_file_size", &mut self.blob_file_size)
			.parse_key("rocksdb_blob_compression_type", &mut self.blob_compression_type)
			.parse_key_bool("rocksdb_enable_blob_gc", &mut self.enable_blob_gc)
			.parse_key("rocksdb_blob_gc_age_cutoff", &mut self.blob_gc_age_cutoff)
			.parse_key("rocksdb_blob_gc_force_threshold", &mut self.blob_gc_force_threshold)
			.parse_key(
				"rocksdb_blob_compaction_readahead_size",
				&mut self.blob_compaction_readahead_size,
			)
			.parse_key("rocksdb_block_cache_size", &mut self.block_cache_size)
			.parse_key("rocksdb_write_buffer_size", &mut self.write_buffer_size)
			.parse_key("rocksdb_max_write_buffer_number", &mut self.max_write_buffer_number)
			.parse_key(
				"rocksdb_min_write_buffer_number_to_merge",
				&mut self.min_write_buffer_number_to_merge,
			)
			.parse_key("rocksdb_sst_max_allowed_space_usage", &mut self.sst_max_allowed_space_usage)
			.parse_key("rocksdb_grouped_commit_timeout", &mut self.grouped_commit_timeout)
			.parse_key(
				"rocksdb_grouped_commit_wait_threshold",
				&mut self.grouped_commit_wait_threshold,
			)
			.parse_key(
				"rocksdb_grouped_commit_max_batch_size",
				&mut self.grouped_commit_max_batch_size,
			)
			.parse_key("rocksdb_initial_auto_readahead_size", &mut self.initial_auto_readahead_size)
			.parse_key("rocksdb_max_auto_readahead_size", &mut self.max_auto_readahead_size)
			.parse_key(
				"rocksdb_file_reads_for_auto_readahead",
				&mut self.file_reads_for_auto_readahead,
			)
			.parse_key_bool("rocksdb_prefix_extractor_enabled", &mut self.prefix_extractor_enabled)
			.parse_key_bool("rocksdb_whole_key_filtering", &mut self.whole_key_filtering)
			.parse_key(
				"rocksdb_memtable_prefix_bloom_ratio",
				&mut self.memtable_prefix_bloom_ratio,
			);

		if map.has_key("datastore_sync") {
			map.parse_key("datastore_sync", &mut self.sync_mode);
		} else {
			map.parse_key("datastore_sync_data", &mut self.sync_mode);
		}
	}
}

#[cfg(test)]
mod test {
	use std::time::Duration;

	use crate::cnf::ConfigMap;
	use crate::kvs::config::SyncMode;
	use crate::kvs::rocksdb::RocksDbConfig;

	#[test]
	fn test_rocksdb_config_defaults() {
		let map = ConfigMap::empty();
		let config = map.load::<RocksDbConfig>();
		assert!(!config.versioned);
		assert_eq!(config.retention, Duration::ZERO);
		assert_eq!(config.sync_mode, SyncMode::Every);
	}

	#[test]
	fn test_rocksdb_config_sync_every() {
		let map =
			ConfigMap::from_config_string("sync=every").map_keys(|x| format!("datastore_{x}"));
		let config = map.load::<RocksDbConfig>();
		assert_eq!(config.sync_mode, SyncMode::Every);
	}

	#[test]
	fn test_rocksdb_config_sync_never() {
		let map =
			ConfigMap::from_config_string("sync=never").map_keys(|x| format!("datastore_{x}"));
		let config = map.load::<RocksDbConfig>();
		assert_eq!(config.sync_mode, SyncMode::Never);
	}

	#[test]
	fn test_rocksdb_config_sync_periodic() {
		let map =
			ConfigMap::from_config_string("sync=200ms").map_keys(|x| format!("datastore_{x}"));
		let config = map.load::<RocksDbConfig>();
		assert_eq!(config.sync_mode, SyncMode::Interval(Duration::from_millis(200)));
	}

	#[test]
	fn test_rocksdb_config_sync_periodic_seconds() {
		let map = ConfigMap::from_config_string("sync=5s").map_keys(|x| format!("datastore_{x}"));
		let config = map.load::<RocksDbConfig>();
		assert_eq!(config.sync_mode, SyncMode::Interval(Duration::from_secs(5)));
	}

	#[test]
	fn test_rocksdb_config_full_params() {
		let map = ConfigMap::from_config_string("versioned=true&retention=30d&sync=every")
			.map_keys(|x| format!("datastore_{x}"));
		let config = map.load::<RocksDbConfig>();
		assert!(config.versioned);
		assert_eq!(config.retention, Duration::from_secs(30 * 24 * 60 * 60));
		assert_eq!(config.sync_mode, SyncMode::Every);
	}
}
