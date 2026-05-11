use std::str::FromStr;
use std::time::Duration;

use crate::cnf::Config;
use crate::kvs::config::{SyncMode, parse_duration};
use crate::sys::TOTAL_SYSTEM_MEMORY;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// The default compaction readahead size is 256 KiB.
/// This is should ideally be aligned with max_sectors_kb,
/// because the kernel splits each 2MB read into multiple smaller
/// IO requests, adding CPU overhead.
/// 256kb is based on the assumption that that for most workloads,
/// this will be the default sector size.
fn default_compaction_readahead_size() -> usize {
	(256 * KIB) as usize
}

/// Size the LRU block cache from available memory:
/// `max(total_memory / 2 - 1 GiB, 16 MiB)`.
fn default_block_cache_size() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	mem.saturating_div(2).saturating_sub(GIB).max(16 * MIB) as usize
}

/// Scale each write buffer with system memory.
/// < 1 GiB: 32 MiB, < 16 GiB: 64 MiB, otherwise 128 MiB.
fn default_write_buffer_size() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		(32 * MIB) as usize
	} else if mem < 16 * GIB {
		(64 * MIB) as usize
	} else {
		(128 * MIB) as usize
	}
}

/// Scale the maximum number of write buffers with system memory.
/// < 4 GiB: 2, < 16 GiB: 4, < 64 GiB: 8, otherwise 32.
fn default_max_write_buffer_number() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < 4 * GIB {
		2
	} else if mem < 16 * GIB {
		4
	} else if mem < 64 * GIB {
		8
	} else {
		32
	}
}

/// Scale the maximum number of subcompactions with the CPU count
/// available to the process. `available_parallelism` respects cgroup
/// CPU quotas on Linux, so a large host running inside a small
/// cgroup is clipped to its quota. The result is clamped into the
/// range `[1, 4]` so at least one subcompaction is permitted and so
/// no more subcompactions are spawned than are useful for a single
/// LSM level.
fn default_max_concurrent_subcompactions() -> u32 {
	let cpu_count = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
	(cpu_count as u32).clamp(1, 4)
}

/// Cap the maximum number of background jobs (flush and compaction
/// workers) against the process memory budget. Each background job
/// carries a thread stack (~8 MiB on Linux) plus compaction
/// readahead and scratch buffers, so memory tends to be the
/// effective ceiling before CPU does on constrained deployments.
/// Use `cpu_count * 2` as the upper bound (the previous default),
/// capped at roughly one job per 128 MiB of system memory and
/// never below 2.
fn default_jobs_count() -> usize {
	let cpu_count = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
	let memory_limited_jobs = (*TOTAL_SYSTEM_MEMORY / (128 * MIB)).max(2) as usize;
	(cpu_count * 2).min(memory_limited_jobs)
}

/// Scale the target file size for compaction with system memory.
/// Smaller SSTs on small systems keep per-compaction work, readahead
/// buffers and disk headroom in proportion. Note that with
/// `target_file_size_multiplier` (default 2) and
/// `file_compaction_trigger` (default 4), L0 can accumulate up to
/// `4 * base` bytes before compaction triggers and each deeper level
/// doubles in size, so the base also caps the on-disk pyramid.
/// < 1 GiB: 8 MiB, < 4 GiB: 16 MiB, < 16 GiB: 32 MiB, otherwise 64 MiB.
fn default_target_file_size_base() -> u64 {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		8 * MIB
	} else if mem < 4 * GIB {
		16 * MIB
	} else if mem < 16 * GIB {
		32 * MIB
	} else {
		64 * MIB
	}
}

/// Scale the grouped-commit batch cap with system memory. Each
/// queued transaction holds its write set in memory until the
/// coordinator flushes, so an unbounded cap can transiently inflate
/// RSS under bursty write load. Larger systems retain the previous
/// throughput-oriented cap of 4096.
/// < 1 GiB: 256, < 4 GiB: 1024, otherwise 4096.
fn default_grouped_commit_max_batch_size() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		256
	} else if mem < 4 * GIB {
		1024
	} else {
		4096
	}
}

/// Scale the number of RocksDB info log files to keep on disk. Each
/// rolled log file is bounded but retained; reducing the retention
/// count saves disk on small deployments.
/// < 1 GiB: 2, < 4 GiB: 5, otherwise 10.
fn default_keep_log_file_num() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		2
	} else if mem < 4 * GIB {
		5
	} else {
		10
	}
}

/// Scale the per-iterator auto-readahead cap with system memory. The
/// implicit iterator prefetcher can grow up to this size per active
/// iterator, so many concurrent range scans multiply the cost. On
/// small systems the cap is reduced proportionally.
/// < 1 GiB: 512 KiB, < 4 GiB: 1 MiB, otherwise 4 MiB.
fn default_max_auto_readahead_size() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		(512 * KIB) as usize
	} else if mem < 4 * GIB {
		MIB as usize
	} else {
		(4 * MIB) as usize
	}
}

/// Scale the inline scan threshold with system memory. Scans at or
/// below this threshold run directly on the async executor thread;
/// larger scans are offloaded to the blocking thread-pool. On
/// constrained CPU budgets a smaller threshold prevents long scans
/// from monopolising a tokio worker.
/// < 1 GiB: 512 KiB, < 4 GiB: 1 MiB, otherwise 4 MiB.
fn default_inline_scan_threshold() -> u32 {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		(512 * KIB) as u32
	} else if mem < 4 * GIB {
		MIB as u32
	} else {
		(4 * MIB) as u32
	}
}

/// Scale the maximum number of files RocksDB can keep open
/// simultaneously with system memory. Each open SST pins table
/// reader state (index, filter, prefix metadata) in memory, so on
/// small deployments a tight cap keeps table-reader memory
/// proportionate to the available budget. Larger systems retain the
/// previous default of 1026 FDs.
/// < 1 GiB: 256, < 4 GiB: 512, otherwise 1026.
fn default_max_open_files() -> usize {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		256
	} else if mem < 4 * GIB {
		512
	} else {
		1026
	}
}

/// Always enable blob file separation. The `min_blob_size` threshold
/// (default 4 KiB) is the safety mechanism that keeps small values in
/// the LSM where they belong; only values that exceed the threshold
/// pay the cost of blob storage. Per-blob-file in-memory metadata is
/// ~100 bytes; blob files share the `max_open_files` budget with
/// SSTs (no separate FD pool); blob cache shares the block cache (no
/// separate memory allocation).
fn default_enable_blob_files() -> bool {
	true
}

/// Scale the target blob file size with system memory. Blob files
/// store large values (>= `min_blob_size`, default 4 KiB) separately
/// from SSTs, so a single blob file can otherwise pin hundreds of MiB
/// of disk on small deployments.
/// < 1 GiB: 16 MiB, < 4 GiB: 64 MiB, < 16 GiB: 128 MiB, otherwise 256 MiB.
fn default_blob_file_size() -> u64 {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		16 * MIB
	} else if mem < 4 * GIB {
		64 * MIB
	} else if mem < 16 * GIB {
		128 * MIB
	} else {
		256 * MIB
	}
}

/// Scale the WAL size limit (in MiB) with system memory. This governs
/// how many MiB of *archived* (obsolete) WAL files RocksDB keeps
/// around before deleting the oldest ones; it does not force flushes
/// or affect the active WAL. Bounding it prevents archived WAL files
/// from consuming otherwise scarce disk on small deployments, while
/// larger systems retain the RocksDB default of unlimited retention.
/// Returns the limit in MiB (as required by `set_wal_size_limit_mb`);
/// 0 means unlimited.
/// < 1 GiB: 32 MiB, < 16 GiB: 128 MiB, otherwise 0 (unlimited).
fn default_wal_size_limit() -> u64 {
	let mem = *TOTAL_SYSTEM_MEMORY;
	if mem < GIB {
		32
	} else if mem < 16 * GIB {
		128
	} else {
		0
	}
}

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
	/// The maximum number of background jobs (flush and compaction
	/// workers) that RocksDB may run concurrently. Defaults to
	/// `cpu_count * 2`, capped at roughly one job per 128 MiB of
	/// system memory and never below 2, so that a large host running
	/// inside a small cgroup does not spawn more background threads
	/// than the memory budget comfortably supports.
	pub jobs_count: usize,
	/// The maximum number of open files which can be opened by RocksDB
	/// (default: dynamic from 256 to 1026 depending on system memory).
	/// Each open SST pins table reader state (index, filter, prefix
	/// metadata) in memory, so the cap is kept proportional to the
	/// available memory budget.
	pub max_open_files: usize,
	/// The size of each uncompressed data block in bytes (default: 64 KiB)
	pub block_size: usize,
	/// The limit (in MiB) on archived write-ahead-log retention; once
	/// obsolete WAL files exceed this budget RocksDB deletes the oldest
	/// first. Does not affect the active WAL or force flushes. Set to
	/// 0 for unlimited retention (default: dynamic from 32 MiB to
	/// unlimited depending on system memory).
	pub wal_size_limit: u64,
	/// The target file size for compaction in bytes
	/// (default: dynamic from 8 MiB to 64 MiB depending on system memory)
	pub target_file_size_base: u64,
	/// The target file size multiplier for each compaction level (default: 2)
	pub target_file_size_multiplier: usize,
	/// The number of files needed to trigger level 0 compaction (default: 4)
	pub file_compaction_trigger: usize,
	/// The readahead buffer size used during compaction
	/// (default: dynamic from 4 MiB to 16 MiB)
	pub compaction_readahead_size: usize,
	/// The maximum number of threads which will perform subcompactions
	/// (default: `min(cpu_count, 4)`). Clamped against the process's
	/// available parallelism so a large host running inside a small
	/// cgroup does not oversubscribe the CPU budget with subcompaction
	/// workers.
	pub max_concurrent_subcompactions: u32,
	/// Use separate queues for WAL writes and memtable writes (default: true)
	pub enable_pipelined_writes: bool,
	/// The maximum number of information log files to keep on disk
	/// (default: dynamic from 2 to 10 depending on system memory).
	/// Lower retention saves disk on small deployments; larger systems
	/// retain the previous default for easier post-mortem debugging.
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
	/// Whether to enable separate key and value file storage
	/// (default: true on systems with >= 1 GiB of memory, false below).
	/// The blob GC loop, extra file descriptors and additional
	/// compaction readahead are not worth the complexity on very small
	/// deployments.
	pub enable_blob_files: bool,
	/// The minimum size of a value for it to be stored in blob files (default: 4
	/// KiB)
	pub min_blob_size: u64,
	/// The target blob file size
	/// (default: dynamic from 16 MiB to 256 MiB depending on system memory)
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
	/// The maximum number of transactions in a single grouped commit batch
	/// (default: dynamic from 256 to 4096 depending on system memory).
	/// Each queued transaction holds its write set in memory until the
	/// coordinator flushes, so smaller systems use smaller batches to
	/// cap transient RSS under bursty write load. Larger batches improve
	/// throughput but increase memory usage and commit latency.
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
	/// and memory per iterator. Because each active iterator can grow its
	/// readahead up to this cap, many concurrent scans multiply the memory
	/// footprint, so the default scales down on small systems
	/// (default: dynamic from 512 KiB to 4 MiB depending on system memory).
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
	/// regardless of this value
	/// (default: dynamic from 512 KiB to 4 MiB depending on system memory)
	pub inline_scan_threshold: u32,

	/// Whether to verify per-block CRC32C checksums when iterating during
	/// scans and counts. Verification runs on first read of a block (cold
	/// path); cached blocks are not re-checksummed. Disabling trades
	/// integrity for cold-scan throughput; only safe on trusted storage.
	/// Applies to both `scan_read_options` and `count_read_options`
	/// (default: true).
	pub scan_verify_checksums: bool,
}

impl Default for RocksDbConfig {
	fn default() -> Self {
		let cpu_count = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
		Self {
			versioned: false,
			retention: Duration::ZERO,
			sync_mode: SyncMode::Every,
			thread_count: cpu_count,
			jobs_count: default_jobs_count(),
			max_open_files: default_max_open_files(),
			block_size: 64 * 1024,
			wal_size_limit: default_wal_size_limit(),
			target_file_size_base: default_target_file_size_base(),
			target_file_size_multiplier: 2,
			file_compaction_trigger: 4,
			compaction_readahead_size: default_compaction_readahead_size(),
			max_concurrent_subcompactions: default_max_concurrent_subcompactions(),
			enable_pipelined_writes: true,
			keep_log_file_num: default_keep_log_file_num(),
			storage_log_level: "warn".to_owned(),
			compaction_style: "level".to_owned(),
			deletion_factory_window_size: 1000,
			deletion_factory_delete_count: 50,
			deletion_factory_ratio: 0.5,
			enable_blob_files: default_enable_blob_files(),
			min_blob_size: 4 * 1024,
			blob_file_size: default_blob_file_size(),
			blob_compression_type: Default::default(),
			enable_blob_gc: true,
			blob_gc_age_cutoff: 0.5,
			blob_gc_force_threshold: 0.5,
			blob_compaction_readahead_size: 0,
			block_cache_size: default_block_cache_size(),
			write_buffer_size: default_write_buffer_size(),
			max_write_buffer_number: default_max_write_buffer_number(),
			min_write_buffer_number_to_merge: 2,
			sst_max_allowed_space_usage: 0,
			grouped_commit_timeout: Duration::from_millis(5).as_nanos() as u64,
			grouped_commit_wait_threshold: 12,
			grouped_commit_max_batch_size: default_grouped_commit_max_batch_size(),
			initial_auto_readahead_size: 8 * 1024,
			max_auto_readahead_size: default_max_auto_readahead_size(),
			file_reads_for_auto_readahead: 2,
			prefix_extractor_enabled: true,
			whole_key_filtering: true,
			memtable_prefix_bloom_ratio: 0.1,
			inline_scan_threshold: default_inline_scan_threshold(),
			scan_verify_checksums: true,
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
			.parse_key("rocksdb_memtable_prefix_bloom_ratio", &mut self.memtable_prefix_bloom_ratio)
			.parse_key_bool("rocksdb_scan_verify_checksums", &mut self.scan_verify_checksums);

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
