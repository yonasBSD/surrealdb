//! This module defines the API for a transaction in a key-value store.
#![warn(clippy::missing_docs_in_private_items)]

use std::ops::Range;

use anyhow::bail;

use super::err::{Error, Result};
use super::util;
use crate::key::debug::Sprintable;
use crate::kvs::batch::Batch;
use crate::kvs::timestamp::IncTimeStamp;
use crate::kvs::{
	BoxTimeStamp, BoxTimeStampImpl, COUNT_BATCH_SIZE, HlcTimeStamp, HlcTimeStampImpl,
	IncTimeStampImpl, Key, NORMAL_BATCH_SIZE, Val,
};

/// Specifies the limit for scan operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanLimit {
	/// Fetch up to the specified number of entries
	Count(u32),
	/// Fetch at least the specified number of bytes
	Bytes(u32),
	/// Fetch at least the specified number of bytes, limited by the specified number of entries
	BytesOrCount(u32, u32),
}

impl From<u32> for ScanLimit {
	fn from(count: u32) -> Self {
		ScanLimit::Count(count)
	}
}

/// The result of a [`Transactable::scan`] or [`Transactable::scanr`] operation.
///
/// Contains the fetched key-value pairs together with the total number of
/// key and value bytes consumed during the scan. Backends accumulate the
/// counters while iterating their underlying cursor, so callers do not need
/// to make a second pass over the result to compute them.
#[derive(Debug, Default)]
pub struct ScanResult {
	/// The fetched key-value pairs.
	pub values: Vec<(Key, Val)>,

	/// The total number of key bytes in the result.
	pub key_bytes: u64,

	/// The total number of value bytes in the result.
	pub value_bytes: u64,
}

/// The result of a [`Transactable::keys`] or [`Transactable::keysr`] operation.
///
/// Contains the fetched keys together with the total number of key bytes in
/// the result, accumulated by the backend during the same iteration that
/// produced the keys.
#[derive(Debug, Default)]
pub struct KeysResult {
	/// The fetched keys.
	pub keys: Vec<Key>,

	/// The total number of key bytes in the result.
	pub key_bytes: u64,
}

/// The result of a [`Transactable::getm`] operation.
///
/// `key_bytes` is intentionally omitted: callers pass the input keys in and
/// already know their total length, so re-counting them here would be
/// duplicate work on the hot path.
#[derive(Debug, Default)]
pub struct GetMultiResult {
	/// One entry per input key, preserving input order. `None` indicates a
	/// miss.
	pub values: Vec<Option<Val>>,

	/// The number of input keys that were found (count of `Some` entries).
	pub records: u64,

	/// The total number of value bytes across the `Some` entries.
	pub value_bytes: u64,
}

pub mod requirements {
	//! This module defines the trait requirements for a transaction.
	//!
	//! The reason this exists is to allow for swapping out the `Send`
	//! requirement for WASM targets, where we don't want to require `Send` for
	//! transactions. But for non-WASM targets, we do want to require `Send`
	//! for transactions.
	//!
	//! There is no `cfg` / `cfg_attr` support for trait requirements, so we use
	//! this dependent trait to conditionally require `Send` based on the
	//! target family.
	//!
	//! Without this, we would have had to duplicate the entire `Transaction`
	//! trait for WASM and non-WASM targets, which would have been a pain to
	//! maintain.

	/// This trait defines WASM requirements for a transaction.
	#[cfg(target_family = "wasm")]
	pub trait TransactionRequirements {}

	/// Implements the `TransactionRequirements` trait for all types.
	#[cfg(target_family = "wasm")]
	impl<T> TransactionRequirements for T {}

	/// This trait defines non-WASM requirements for a transaction.
	#[cfg(not(target_family = "wasm"))]
	pub trait TransactionRequirements: Send + Sync {}

	/// Implements the `TransactionRequirements` trait for all types that are
	/// `Send`.
	#[cfg(not(target_family = "wasm"))]
	impl<T: Send + Sync> TransactionRequirements for T {}
}

/// This trait defines the API for a transaction in a key-value store.
///
/// All keys and values are represented as byte arrays, encoding is handled
/// by [`super::tr::Transactor`].
#[allow(dead_code, reason = "Not used when none of the storage backends are enabled.")]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait Transactable: requirements::TransactionRequirements {
	/// Get the name of the transaction type.
	fn kind(&self) -> &'static str;

	/// Check if transaction is finished.
	///
	/// If the transaction has been cancelled or committed,
	/// then this function will return [`true`], and any further
	/// calls to functions on this transaction will result
	/// in a [`crate::kvs::Error::TransactionFinished`] error.
	fn closed(&self) -> bool;

	/// Check if transaction is writeable.
	///
	/// If the transaction has been marked as a writeable
	/// transaction, then this function will return [`true`].
	/// This fuction can be used to check whether a transaction
	/// allows data to be modified, and if not then the function
	/// will return a [`crate::kvs::Error::TransactionReadonly`] error.
	fn writeable(&self) -> bool;

	/// Cancel a transaction.
	///
	/// This reverses all changes made within the transaction.
	async fn cancel(&self) -> Result<()>;

	/// Commit a transaction.
	///
	/// This attempts to commit all changes made within the transaction.
	async fn commit(&self) -> Result<()>;

	/// Check if a key exists in the datastore.
	async fn exists(&self, key: Key, version: Option<u64>) -> Result<bool>;

	/// Fetch a key from the datastore.
	async fn get(&self, key: Key, version: Option<u64>) -> Result<Option<Val>>;

	/// Insert or update a key in the datastore.
	async fn set(&self, key: Key, val: Val) -> Result<()>;

	/// Insert a key if it doesn't exist in the datastore.
	async fn put(&self, key: Key, val: Val) -> Result<()>;

	/// Update a key in the datastore if the current value matches a condition.
	async fn putc(&self, key: Key, val: Val, chk: Option<Val>) -> Result<()>;

	/// Delete a key from the datastore.
	async fn del(&self, key: Key) -> Result<()>;

	/// Delete a key from the datastore if the current value matches a
	/// condition.
	async fn delc(&self, key: Key, chk: Option<Val>) -> Result<()>;

	/// Retrieve a specific range of keys from the datastore.
	///
	/// This function fetches the full range of keys without values, in a single
	/// request to the underlying datastore. Implementations also return the
	/// total number of key bytes scanned, accumulated during the same
	/// iteration that produces the keys, so callers can record metrics
	/// without re-walking the result.
	async fn keys(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<KeysResult>;

	/// Retrieve a specific range of keys from the datastore, in reverse order.
	///
	/// This function fetches the full range of keys without values, in a single
	/// request to the underlying datastore. Implementations also return the
	/// total number of key bytes scanned, accumulated during the same
	/// iteration that produces the keys, so callers can record metrics
	/// without re-walking the result.
	async fn keysr(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<KeysResult>;

	/// Retrieve a specific range of keys from the datastore.
	///
	/// This function fetches the full range of key-value pairs, in a single
	/// request to the underlying datastore. Implementations also return the
	/// total number of value bytes scanned, accumulated during the same
	/// iteration that produces the values, so callers can record metrics
	/// without re-walking the result.
	async fn scan(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<ScanResult>;

	/// Retrieve a specific range of keys from the datastore in reverse order.
	///
	/// This function fetches the full range of key-value pairs, in a single
	/// request to the underlying datastore. Implementations also return the
	/// total number of value bytes scanned, accumulated during the same
	/// iteration that produces the values, so callers can record metrics
	/// without re-walking the result.
	async fn scanr(
		&self,
		rng: Range<Key>,
		limit: ScanLimit,
		skip: u32,
		version: Option<u64>,
	) -> Result<ScanResult>;

	/// Insert or replace a key in the datastore.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn replace(&self, key: Key, val: Val) -> Result<()> {
		self.set(key, val).await
	}

	/// Delete all versions of a key from the datastore.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn clr(&self, key: Key) -> Result<()> {
		self.del(key).await
	}

	/// Delete all versions of a key from the datastore if the current value
	/// matches a condition.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn clrc(&self, key: Key, chk: Option<Val>) -> Result<()> {
		self.delc(key, chk).await
	}

	/// Fetch many keys from the datastore.
	///
	/// This function fetches all matching keys pairs from the underlying
	/// datastore concurrently. The returned [`GetMultiResult`] also reports
	/// the number of input keys that were found and the total value bytes
	/// across the hits, accumulated in the same loop that performs the
	/// individual point gets.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(keys = keys.sprint()))]
	async fn getm(&self, keys: Vec<Key>, version: Option<u64>) -> Result<GetMultiResult> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Continue with function logic
		let mut out = Vec::with_capacity(keys.len());
		let mut records = 0u64;
		let mut value_bytes = 0u64;
		for key in keys {
			if let Some(val) = self.get(key, version).await? {
				records += 1;
				value_bytes += val.len() as u64;
				out.push(Some(val));
			} else {
				out.push(None);
			}
		}
		Ok(GetMultiResult {
			values: out,
			records,
			value_bytes,
		})
	}

	/// Retrieve a range of prefixed keys from the datastore.
	///
	/// This function fetches all matching key-value pairs from the underlying
	/// datastore in grouped batches. The returned [`ScanResult`] also reports
	/// the total key and value bytes consumed during the scan.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn getp(&self, key: Key, version: Option<u64>) -> Result<ScanResult> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Continue with function logic
		let range = util::to_prefix_range(key)?;
		self.getr(range, version).await
	}

	/// Retrieve a range of keys from the datastore.
	///
	/// This function fetches all matching key-value pairs from the underlying
	/// datastore in grouped batches. The returned [`ScanResult`] also reports
	/// the total key and value bytes consumed during the scan, accumulated
	/// while merging successive batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn getr(&self, rng: Range<Key>, version: Option<u64>) -> Result<ScanResult> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Continue with function logic
		let mut out: Vec<(Key, Val)> = vec![];
		let mut key_bytes = 0u64;
		let mut value_bytes = 0u64;
		let mut next = Some(rng);
		while let Some(rng) = next {
			let res = self.batch_keys_vals(rng, NORMAL_BATCH_SIZE, version).await?;
			next = res.next;
			for (k, v) in res.result {
				key_bytes += k.len() as u64;
				value_bytes += v.len() as u64;
				out.push((k, v));
			}
		}
		Ok(ScanResult {
			values: out,
			key_bytes,
			value_bytes,
		})
	}

	/// Delete a range of prefixed keys from the datastore.
	///
	/// This function deletes all matching key-value pairs from the underlying
	/// datastore in grouped batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn delp(&self, key: Key) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Continue with function logic
		let range = util::to_prefix_range(key)?;
		self.delr(range).await
	}

	/// Delete a range of keys from the datastore.
	///
	/// This function deletes all matching key-value pairs from the underlying
	/// datastore in grouped batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn delr(&self, rng: Range<Key>) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Continue with function logic
		let mut next = Some(rng);
		while let Some(rng) = next {
			let res = self.batch_keys(rng, NORMAL_BATCH_SIZE, None).await?;
			next = res.next;
			for k in res.result {
				self.del(k).await?;
			}
		}
		Ok(())
	}

	/// Delete all versions of a range of prefixed keys from the datastore.
	///
	/// This function deletes all matching key-value pairs from the underlying
	/// datastore in grouped batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(key = key.sprint()))]
	async fn clrp(&self, key: Key) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Continue with function logic
		let range = util::to_prefix_range(key)?;
		self.clrr(range).await
	}

	/// Delete all versions of a range of keys from the datastore.
	///
	/// This function deletes all matching key-value pairs from the underlying
	/// datastore in grouped batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn clrr(&self, rng: Range<Key>) -> Result<()> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Check to see if transaction is writable
		if !self.writeable() {
			return Err(Error::TransactionReadonly);
		}
		// Continue with function logic
		let mut next = Some(rng);
		while let Some(rng) = next {
			let res = self.batch_keys(rng, NORMAL_BATCH_SIZE, None).await?;
			next = res.next;
			for k in res.result {
				self.clr(k).await?;
			}
		}
		Ok(())
	}

	/// Count the total number of keys within a range in the datastore.
	///
	/// This function fetches the total key count from the underlying datastore
	/// in grouped batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn count(&self, rng: Range<Key>, version: Option<u64>) -> Result<usize> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Continue with function logic
		let mut len = 0;
		let mut next = Some(rng);
		while let Some(rng) = next {
			let res = self.batch_keys(rng, COUNT_BATCH_SIZE, version).await?;
			next = res.next;
			len += res.result.len();
		}
		Ok(len)
	}

	// --------------------------------------------------
	// Batch functions
	// --------------------------------------------------

	/// Retrieve a batched scan over a specific range of keys in the datastore.
	///
	/// This function fetches keys, in batches, with multiple requests to the
	/// underlying datastore.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn batch_keys(
		&self,
		rng: Range<Key>,
		batch: u32,
		version: Option<u64>,
	) -> Result<Batch<Key>> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Continue with function logic
		let end = rng.end.clone();
		// Scan for the next batch (we only need the keys here; the byte
		// total is intended for metrics consumers higher up the stack)
		let res = self.keys(rng, ScanLimit::Count(batch), 0, version).await?.keys;
		// Check if range is consumed
		if res.len() < batch as usize && batch > 0 {
			Ok(Batch::<Key>::new(None, res))
		} else {
			match res.last() {
				Some(k) => {
					let mut k = k.clone();
					util::advance_key(&mut k);
					Ok(Batch::<Key>::new(
						Some(Range {
							start: k,
							end,
						}),
						res,
					))
				}
				// We have checked the length above, so
				// there should be a last item in the
				// vector, so we shouldn't arrive here
				None => Ok(Batch::<Key>::new(None, res)),
			}
		}
	}

	/// Retrieve a batched scan over a specific range of keys in the datastore.
	///
	/// This function fetches key-value pairs, in batches, with multiple
	/// requests to the underlying datastore.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::api", skip(self), fields(rng = rng.sprint()))]
	async fn batch_keys_vals(
		&self,
		rng: Range<Key>,
		batch: u32,
		version: Option<u64>,
	) -> Result<Batch<(Key, Val)>> {
		// Check to see if transaction is closed
		if self.closed() {
			return Err(Error::TransactionFinished);
		}
		// Continue with function logic
		let end = rng.end.clone();
		// Scan for the next batch (we only need the values here; the byte
		// total is intended for metrics consumers higher up the stack)
		let res = self.scan(rng, ScanLimit::Count(batch), 0, version).await?.values;
		// Check if range is consumed
		if res.len() < batch as usize && batch > 0 {
			Ok(Batch::<(Key, Val)>::new(None, res))
		} else {
			match res.last() {
				Some((k, _)) => {
					let mut k = k.clone();
					util::advance_key(&mut k);
					Ok(Batch::<(Key, Val)>::new(
						Some(Range {
							start: k,
							end,
						}),
						res,
					))
				}
				// We have checked the length above, so
				// there should be a last item in the
				// vector, so we shouldn't arrive here
				None => Ok(Batch::<(Key, Val)>::new(None, res)),
			}
		}
	}

	// --------------------------------------------------
	// Savepoint functions
	// --------------------------------------------------

	/// Set a new save point on the transaction.
	async fn new_save_point(&self) -> Result<()>;

	/// Release the last save point.
	async fn release_last_save_point(&self) -> Result<()>;

	/// Rollback to the last save point.
	async fn rollback_to_save_point(&self) -> Result<()>;

	// --------------------------------------------------
	// Timestamp functions
	// --------------------------------------------------

	/// Get the current monotonic timestamp
	async fn timestamp(&self) -> Result<BoxTimeStamp> {
		if cfg!(test) {
			Ok(BoxTimeStamp::new(IncTimeStamp::next()))
		} else {
			Ok(BoxTimeStamp::new(HlcTimeStamp::next()))
		}
	}

	fn timestamp_impl(&self) -> BoxTimeStampImpl {
		if cfg!(test) {
			Box::new(IncTimeStampImpl)
		} else {
			Box::new(HlcTimeStampImpl)
		}
	}

	async fn compact(&self, _range: Option<Range<Key>>) -> anyhow::Result<()> {
		bail!(Error::CompactionNotSupported)
	}
}
