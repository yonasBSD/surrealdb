//! Storage key for the [`RecordIdEncoding`] sentinel.
//!
//! Encoded as `!re` (root metadata, "record-id encoding"). Sorts strictly
//! before [`crate::key::version::new()`] (`!v`) so the `proceeding()`
//! "any data after the version key?" check in `Datastore::get_version`
//! does not treat the sentinel as user data.
//!
//! [`RecordIdEncoding`]: crate::kvs::record_id_encoding::RecordIdEncoding

use storekey::{BorrowDecode, Encode};

use crate::key::category::{Categorise, Category};
use crate::kvs::impl_kv_key_storekey;

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Encode, BorrowDecode)]
pub(crate) struct RecordIdEncodingKey {
	__: u8,
	_a: u8,
	_b: u8,
}

impl_kv_key_storekey!(
	RecordIdEncodingKey => crate::kvs::record_id_encoding::RecordIdEncoding
);

pub fn new() -> RecordIdEncodingKey {
	RecordIdEncodingKey::new()
}

impl Categorise for RecordIdEncodingKey {
	fn categorise(&self) -> Category {
		// Reuses the existing Version category — both are root-level
		// metadata describing on-disk storage state.
		Category::Version
	}
}

impl RecordIdEncodingKey {
	pub fn new() -> Self {
		Self {
			__: b'!',
			_a: b'r',
			_b: b'e',
		}
	}
}

impl Default for RecordIdEncodingKey {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::kvs::KVKey;

	#[test]
	fn key_bytes() {
		let key = RecordIdEncodingKey::new();
		let enc = RecordIdEncodingKey::encode_key(&key).unwrap();
		assert_eq!(enc, b"!re");
	}

	#[test]
	fn sorts_before_version_key() {
		let me = RecordIdEncodingKey::encode_key(&RecordIdEncodingKey::new()).unwrap();
		let v = crate::key::version::new();
		let v_bytes = crate::kvs::KVKey::encode_key(&v).unwrap();
		assert!(
			me < v_bytes,
			"!re must sort before !v so it is invisible to version::proceeding()"
		);
	}
}
