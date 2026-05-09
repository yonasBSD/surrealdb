mod entry;
mod key;
mod lookup;
mod weight;

pub(crate) use entry::Entry;
pub(crate) use lookup::Lookup;
use quick_cache::sync::DefaultLifecycle;
use quick_cache::{DefaultHashBuilder, OptionsBuilder};

pub(crate) type Cache = quick_cache::sync::Cache<key::Key, Entry, weight::Weight>;

pub struct TransactionCache {
	/// Store the cache entries
	cache: Cache,
}

impl TransactionCache {
	/// Creates a new transaction cache.
	///
	/// The cache is per-transaction and not concurrently accessed across
	/// threads, so `shards = 1` is used. The default `available_parallelism() *
	/// 4` would allocate hundreds of sharded `CacheShard` structs per
	/// transaction on large boxes, all of which then get dropped at commit or
	/// cancel.
	pub(in crate::kvs) fn new(size: usize) -> Self {
		let options = OptionsBuilder::new()
			.estimated_items_capacity(size)
			.weight_capacity(size as u64)
			.shards(1)
			.build()
			.expect("valid transaction cache options");
		let cache = Cache::with_options(
			options,
			weight::Weight,
			DefaultHashBuilder::default(),
			DefaultLifecycle::default(),
		);
		Self {
			cache,
		}
	}

	/// Fetch an item from the datastore cache
	pub(crate) fn get(&self, lookup: &Lookup) -> Option<Entry> {
		self.cache.get(lookup)
	}

	/// Insert an item into the datastore cache
	pub(crate) fn insert(&self, lookup: Lookup, entry: Entry) {
		self.cache.insert(lookup.into(), entry);
	}

	/// Remove an item from the datastore cache
	pub(crate) fn remove(&self, lookup: &Lookup<'_>) {
		self.cache.remove(lookup);
	}

	/// Clear all items from the datastore cache
	pub(crate) fn clear(&self) {
		self.cache.clear();
	}
}
