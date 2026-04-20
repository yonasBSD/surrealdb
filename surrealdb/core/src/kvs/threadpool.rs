#![cfg(any(feature = "kv-mem", feature = "kv-rocksdb", feature = "kv-surrealkv"))]

/// Minimum number of worker threads in the blocking threadpool when running
/// on small-core hosts. Provides enough slack to absorb short bursts of
/// blocking I/O (e.g. cold rocksdb block reads) without saturating the pool
/// on 1-8 core deployments. At or above this threshold, the pool uses
/// `thread_per_core` so each worker is pinned to a dedicated core.
#[cfg(not(target_family = "wasm"))]
const MINIMUM_WORKER_THREADS: usize = 16;

/// Create a new blocking threadpool
pub(super) fn initialise() {
	// Create the threadpool and ignore errors
	#[cfg(not(target_family = "wasm"))]
	{
		// Get the number of CPU cores
		let cores = num_cpus::get();
		// Create the threadpool builder
		let builder = affinitypool::Builder::new().thread_name("surrealdb-threadpool");
		// Check if the core count is at or above the threshold
		let builder = if cores >= MINIMUM_WORKER_THREADS {
			builder.thread_per_core(true)
		} else {
			builder.worker_threads(MINIMUM_WORKER_THREADS)
		};
		// Create the threadpool and ignore errors
		let _ = builder.build().build_global();
	}
}
