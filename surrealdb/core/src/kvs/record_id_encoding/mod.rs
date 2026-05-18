//! Persistent flag tracking whether a datastore's record-id keys have
//! been rewritten under the unified disc-10 lex layout introduced by
//! `9342a97b1`.
//!
//! Storage byte order on numeric record-ids used to be dominated by a
//! per-variant discriminant byte (`Int=2`, `Float=8`, `Decimal=9`), so a
//! table with mixed `Int` / `Float` / `Decimal` ids returned `ORDER BY id`
//! results in storage-byte order rather than `Number::cmp` numeric order.
//!
//! The fix is a single discriminant + lex-sortable payload so byte order =
//! numeric order. Every encoder path now emits disc 10 unconditionally —
//! the [`crate::val::record_id`] codec no longer branches on this enum.
//!
//! The sentinel survives as a one-time migration marker:
//!
//! - [`RecordIdEncoding::Compat`] means "this datastore was opened with at least one pre-existing
//!   record but no sentinel, so legacy disc-2 / disc-8 / disc-9 record-id keys may still be on
//!   disk". Lookups by numeric id will miss those records until
//!   [`crate::kvs::Datastore::migrate_record_ids`] rewrites every record, index, and graph key
//!   under the unified layout.
//! - [`RecordIdEncoding::FullNew`] means "every storage key on this datastore uses the unified
//!   disc-10 layout". Either the datastore was fresh when this binary opened it, or the migration
//!   tool has run.
//!
//! Fresh datastores auto-flip to `FullNew` during `check_version`.
//! Existing-without-sentinel datastores stay implicitly at `Compat` and
//! surface a startup warning until the operator runs the migration.

use anyhow::Result;

use crate::err::Error;
use crate::kvs::KVValue;

/// On-disk record-id encoding mode. Persistence-only marker used by the
/// migration tool to short-circuit when no rewrite is needed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RecordIdEncoding {
	/// Legacy disc-2 / disc-8 / disc-9 record-id keys may still exist on
	/// disk. [`crate::kvs::Datastore::migrate_record_ids`] must rewrite
	/// them before id-based lookups can resolve.
	Compat,
	/// Every record, index, and graph key uses the unified disc-10
	/// layout. Default for fresh datastores; also the post-migration
	/// state.
	FullNew,
}

impl RecordIdEncoding {
	fn as_u16(self) -> u16 {
		match self {
			Self::Compat => 0,
			Self::FullNew => 1,
		}
	}

	fn from_u16(v: u16) -> Result<Self> {
		match v {
			0 => Ok(Self::Compat),
			1 => Ok(Self::FullNew),
			other => {
				Err(Error::Serialization(format!("Unknown RecordIdEncoding mode: {other}")).into())
			}
		}
	}
}

impl KVValue for RecordIdEncoding {
	type KeyContext = ();

	#[inline]
	fn kv_encode_value(&self) -> Result<Vec<u8>> {
		Ok(self.as_u16().to_be_bytes().to_vec())
	}

	#[inline]
	fn kv_decode_value(v: &[u8], _: ()) -> Result<Self> {
		let bin = v.try_into().map_err(|_| {
			Error::Serialization("RecordIdEncoding value must be exactly 2 bytes".to_string())
		})?;
		Self::from_u16(u16::from_be_bytes(bin))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encode_decode_roundtrip() {
		for mode in [RecordIdEncoding::Compat, RecordIdEncoding::FullNew] {
			let encoded = mode.kv_encode_value().unwrap();
			let decoded = RecordIdEncoding::kv_decode_value(&encoded, ()).unwrap();
			assert_eq!(decoded, mode);
		}
	}

	#[test]
	fn compat_encodes_as_zero() {
		assert_eq!(RecordIdEncoding::Compat.kv_encode_value().unwrap(), vec![0, 0]);
	}

	#[test]
	fn full_new_encodes_as_one() {
		assert_eq!(RecordIdEncoding::FullNew.kv_encode_value().unwrap(), vec![0, 1]);
	}

	#[test]
	fn decode_rejects_unknown() {
		assert!(RecordIdEncoding::kv_decode_value(&[0, 2], ()).is_err());
	}

	#[test]
	fn decode_rejects_wrong_length() {
		assert!(RecordIdEncoding::kv_decode_value(&[0], ()).is_err());
		assert!(RecordIdEncoding::kv_decode_value(&[0, 0, 0], ()).is_err());
	}
}
