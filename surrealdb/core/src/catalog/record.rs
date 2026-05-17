//! Record module for SurrealDB
//!
//! This module provides the `Record` type which represents a database record with metadata.
//! Records can contain both data and metadata about the record type (e.g., whether it's an edge).

use std::sync::Arc;

use anyhow::{Result, anyhow};
use revision::{DeserializeRevisioned, Revisioned, SerializeRevisioned, revisioned};
use surrealdb_collections::VecMap;
use surrealdb_strand::Strand;

use crate::catalog::aggregation::AggregationStat;
use crate::kvs::KVValue;
use crate::val::{Object, RecordId, Value};

/// Represents a record stored in the database
///
/// A `Record` contains both the actual data and optional metadata about the record.
/// The metadata can include information such as the record type (e.g., Edge for graph edges).
///
/// # Examples
///
/// ```no_compile
/// use surrealdb_core::catalog::Record;
/// use surrealdb_core::val::{Object, Value};
///
/// // Create a new record with data
/// let record = Record::new(Value::Object(Object::default()));
///
/// // Check if it's an edge record
/// assert!(!record.is_edge());
/// ```
#[revisioned(revision = 1)]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Record {
	/// Optional metadata about the record (e.g., record type)
	pub(crate) metadata: Option<Metadata>,
	/// The actual data stored in the record
	// TODO (DB-655): Switch to `Object`.
	pub(crate) data: Value,
}

/// Strand value for the `"id"` field name. Used by the in-place id
/// splicer during decode so we don't allocate a fresh `Strand` per record.
const ID_KEY: Strand = Strand::new_static("id");

/// On-disk prefix the `#[revisioned]` derive emits for the `data`
/// field when it holds a `Value::Object`, up to (and including) the
/// inner `Object`'s revision tag — i.e. everything that precedes the
/// `VecMap` length.
///
/// The three bytes are:
///
/// * `Value::revision()` — `u16(1)` encoded as a varint (`0x01`).
/// * `Value::Object` variant discriminant — `u32(10)` encoded as a varint (`0x0A`). Matches the
///   position of `Object` in the `Value` enum definition at `surrealdb/core/src/val/mod.rs`.
/// * `Object::revision()` — `u16(1)` encoded as a varint (`0x01`).
///
/// Hard-coded here for zero-overhead splicing in [`Record::kv_encode_value`]
/// and zero-overhead peek detection in [`Record::decode_rev1_with_id`].
/// Drift between this constant and the derive's actual output is caught
/// at test time by `value_object_prefix_matches_derive_payload` and
/// `custom_encode_matches_derive_encode_of_stripped_record`.
const VALUE_OBJECT_PREFIX: &[u8] = &[0x01, 0x0A, 0x01];

impl KVValue for Record {
	/// Encode a `Record` for storage, skipping the top-level `id` field of
	/// `data` if present. The id is reconstructed from the storage key on
	/// read (see [`Record::kv_decode_value_with_id`]), so storing it in the
	/// serialized payload would be redundant.
	///
	/// The output is byte-identical to the `#[revisioned]` derive applied
	/// to `Record` *except* the entry for `"id"` (if any) is dropped from
	/// the top-level `Object`. The wire format itself is unchanged: a node
	/// that reads `Record` via the standard derived deserializer will
	/// simply observe an `Object` without an `id` key.
	///
	/// The skip is surgical: only the top-level `id` of `Record::data` is
	/// dropped. Any nested `Value::Object` containing an `id` field — e.g.
	/// `{ author: { id: ... } }` — serializes unchanged through the
	/// standard `Value` encoder.
	///
	/// No `clone` of the record or its inner `Value` tree is required.
	fn kv_encode_value(&self) -> Result<Vec<u8>> {
		let mut buf = Vec::new();
		// Mirror the auto-derive prologue: every revisioned encoding
		// starts with the type's `u16` revision tag.
		SerializeRevisioned::serialize_revisioned(&<Self as Revisioned>::revision(), &mut buf)?;
		// metadata field is unchanged from the derive.
		SerializeRevisioned::serialize_revisioned(&self.metadata, &mut buf)?;
		// data field: custom-encode when the top-level Object carries an id.
		match &self.data {
			Value::Object(obj) if obj.0.contains_key("id") => {
				// Splice in the `Value::Object` prefix (Value rev +
				// variant discriminant + Object rev), then emit the
				// VecMap length minus one and the entries with "id"
				// skipped. Drift from the derived wire format is caught
				// by `value_object_prefix_matches_derive_payload`.
				buf.extend_from_slice(VALUE_OBJECT_PREFIX);
				// Calculate the VecMap length without including the 'id'.
				let len = obj.0.len() - 1;
				// Serialize the VecMap length without including the 'id'.
				SerializeRevisioned::serialize_revisioned(&len, &mut buf)?;
				for (k, v) in obj.0.iter() {
					// Skip the 'id' field.
					if k.as_str() == "id" {
						continue;
					}
					// Serialize the key and value.
					SerializeRevisioned::serialize_revisioned(k, &mut buf)?;
					SerializeRevisioned::serialize_revisioned(v, &mut buf)?;
				}
			}
			other => {
				SerializeRevisioned::serialize_revisioned(other, &mut buf)?;
			}
		}
		Ok(buf)
	}

	/// Standard revisioned decode. Callers that need the `id` field
	/// reconstructed from the storage key should use
	/// [`Record::kv_decode_value_with_id`] instead — this method does not
	/// inject one.
	fn kv_decode_value(bytes: Vec<u8>) -> Result<Self> {
		Ok(revision::from_slice(&bytes)?)
	}
}

impl Record {
	/// Compile-time guard: every revision of [`Record`] supported on
	/// disk must have a corresponding arm in
	/// [`Record::kv_decode_value_with_id`]. Bumping
	/// `#[revisioned(revision = N)]` on [`Record`] without adding a
	/// matching `decode_revN_with_id` arm below will trip this
	/// assertion at `cargo build` time.
	const _ASSERT_REVISION_DISPATCHER_COVERS_CURRENT: () =
		assert!(<Record>::REVISION <= 1, "Record revision exceeds the decoder's handled max");

	/// Decode a `Record` and ensure its `data` carries the canonical `id`
	/// reconstructed from the storage key.
	///
	/// For the common case — a current-revision `Value::Object` payload —
	/// the id is spliced into the right sorted slot **during** VecMap
	/// construction, avoiding an O(n) post-decode shift. For older
	/// revisions or non-Object payloads we fall back to the standard
	/// derived deserializer and then assign the id unconditionally.
	pub(crate) fn kv_decode_value_with_id(bytes: &[u8], rid: RecordId) -> Result<Record> {
		let mut reader: &[u8] = bytes;
		let record_rev = <u16 as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		match record_rev {
			1 => Self::decode_rev1_with_id(reader, rid),
			x => Err(anyhow!("Invalid revision `{x}` for type `Record`")),
		}
	}

	/// Decode a `Record` revision-1 body (i.e. after the Record revision
	/// tag has already been consumed), splicing `id` inline when the
	/// payload is a current-revision `Value::Object`.
	fn decode_rev1_with_id(mut reader: &[u8], rid: RecordId) -> Result<Record> {
		// Decode the metadata.
		let metadata =
			<Option<Metadata> as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		// Decode the data.
		let data = if reader.starts_with(VALUE_OBJECT_PREFIX) {
			// Fast path: current-revision Value::Object. Advance past
			// the framing bytes for Value and Object.
			let mut body_reader: &[u8] = &reader[VALUE_OBJECT_PREFIX.len()..];
			// Deserialize the VecMap and splice the canonical `id` into the
			// VecMap at its sorted position during decode.
			let map = VecMap::deserialize_revisioned_with_extra(
				&mut body_reader,
				(ID_KEY, Value::RecordId(rid)),
			)?;
			// Return the Object with the `id`.
			Value::Object(Object(map))
		} else {
			// Slow path: older `Value`/`Object` revision which is not a
			// Value::Object will default to standard derived deserialisation.
			// We should never hit this path, but it's here to be defensive.
			<Value as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?
		};
		// Return the Record
		Ok(Record {
			metadata,
			data,
		})
	}

	/// Creates a new record with the given data and no metadata
	pub(crate) fn new(data: Value) -> Self {
		Self {
			metadata: None,
			data,
		}
	}

	/// Checks if this record represents an edge in a graph
	pub const fn is_edge(&self) -> bool {
		matches!(
			&self.metadata,
			Some(Metadata {
				record_type: RecordType::Edge,
				..
			})
		)
	}

	/// Wraps this record in an `Arc` for shared ownership.
	pub(crate) fn into_read_only(self) -> Arc<Self> {
		Arc::new(self)
	}

	/// Sets the record type in the metadata
	pub(crate) fn set_record_type(&mut self, rtype: RecordType) {
		match &mut self.metadata {
			Some(metadata) => {
				metadata.record_type = rtype;
			}
			metadata => {
				*metadata = Some(Metadata {
					record_type: rtype,
					aggregation_stats: Vec::new(),
				});
			}
		}
	}
}

/// Types of records that can be stored in the database
///
/// This enum defines the different types of records that can be stored.
/// Currently, only Edge is supported, but this can be extended to support
/// other record types in the future.
#[revisioned(revision = 1)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Hash)]
pub(crate) enum RecordType {
	/// Represents a normal table record
	#[default]
	Table,
	/// Represents an edge in a graph
	Edge,
}

/// Metadata associated with a record
///
/// This struct contains optional metadata about a record, such as its type and
/// aggregation statistics for materialized view records.
/// The metadata is revisioned to ensure compatibility across different versions
/// of the database.
#[revisioned(revision = 1)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Metadata {
	/// The type of the record (e.g., Edge for graph edges)
	pub(crate) record_type: RecordType,
	/// Statistics related to running aggregations for this record.
	/// These do not directly correspond to a field but must be used in conjunction with the table
	/// definition to calculate the final value for this record.
	pub(crate) aggregation_stats: Vec<AggregationStat>,
}

#[cfg(test)]
mod tests {
	use surrealdb_strand::Strand;

	use super::*;
	use crate::val::{Array, Object, RecordIdKey, TableName};

	fn make_rid(table: &str, key: &str) -> RecordId {
		RecordId {
			table: TableName::new(table),
			key: RecordIdKey::String(Strand::new(key)),
		}
	}

	#[test]
	fn custom_encode_matches_derive_encode_of_stripped_record() {
		// The custom `KVValue` encoder is hand-built on top of the
		// hard-coded `VALUE_OBJECT_PREFIX` bytes and must remain
		// byte-identical to what the auto-derived `revisioned` encoder
		// would emit for the same record with its top-level `id` field
		// removed. If the `revision` crate ever changes its wire format
		// (variant tag width, varint encoding, etc.) or the `Value`
		// enum is reordered, this test will fail and signal that
		// `VALUE_OBJECT_PREFIX` and the surrounding splice logic need
		// to be revisited.
		//
		// TODO: extend the `revision` crate with first-class helpers
		// for writing a variant's framing (type revision + variant
		// discriminant) and for obtaining the prefix bytes of a
		// specific variant. With those in place, `VALUE_OBJECT_PREFIX`
		// and the manual splice in `kv_encode_value` can be replaced
		// by `Value::write_variant_object(..)` / a derived
		// `Value::variant_object_prefix_bytes()` call, removing the
		// need to hard-code the wire format of `Value::Object` here.
		let rid = make_rid("user", "alice");
		// Record as stored at rest in memory, with `id` present.
		let mut with_id = Object::default();
		with_id.0.insert(Strand::new("id"), Value::RecordId(rid));
		with_id.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		with_id.0.insert(Strand::new("age"), Value::from(30i64));
		let with_id = Record::new(Value::Object(with_id));
		// Same record with `id` stripped — what the derived encoder would
		// see if our custom encoder did its job correctly.
		let mut without_id = Object::default();
		without_id.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		without_id.0.insert(Strand::new("age"), Value::from(30i64));
		let without_id = Record::new(Value::Object(without_id));
		// Custom encode of the record-with-id must equal the derived
		// encode of the record-without-id, byte for byte.
		assert_eq!(with_id.kv_encode_value().unwrap(), revision::to_vec(&without_id).unwrap());
	}

	#[test]
	fn value_object_prefix_matches_derive_payload() {
		// Sanity-check the hard-coded prefix: a serialized
		// `Value::Object(Object::default())` must start with
		// `VALUE_OBJECT_PREFIX` and contain exactly one more byte (the
		// encoded `usize(0)` for the empty VecMap, in variable-length
		// encoding). If `Value` is reordered, `Object`'s revision is
		// bumped, or the underlying varint encoding changes, this test
		// trips and signals that `VALUE_OBJECT_PREFIX` needs updating.
		let mut bytes = Vec::new();
		SerializeRevisioned::serialize_revisioned(&Value::Object(Object::default()), &mut bytes)
			.unwrap();
		assert!(
			bytes.starts_with(VALUE_OBJECT_PREFIX),
			"empty Object payload must start with VALUE_OBJECT_PREFIX, got {:02x?}",
			bytes,
		);
		// Compare against the encoded length(0) to be encoding-agnostic.
		let mut zero_len = Vec::new();
		SerializeRevisioned::serialize_revisioned(&0usize, &mut zero_len).unwrap();
		assert_eq!(bytes.len(), VALUE_OBJECT_PREFIX.len() + zero_len.len());
	}

	#[test]
	fn encode_skips_top_level_id() {
		// Encoding a record with an `id` in `data` must produce the same
		// bytes as encoding the same record without `id` in `data`.
		let rid = make_rid("user", "alice");
		let mut with_id = Object::default();
		with_id.0.insert(Strand::new("id"), Value::RecordId(rid));
		with_id.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		with_id.0.insert(Strand::new("age"), Value::from(30i64));
		let with_id = Record::new(Value::Object(with_id));

		let mut without_id = Object::default();
		without_id.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		without_id.0.insert(Strand::new("age"), Value::from(30i64));
		let without_id = Record::new(Value::Object(without_id));

		assert_eq!(with_id.kv_encode_value().unwrap(), without_id.kv_encode_value().unwrap());
	}

	#[test]
	fn decode_with_id_injects_when_absent() {
		let rid = make_rid("user", "alice");
		let mut obj = Object::default();
		obj.0.insert(Strand::new("id"), Value::RecordId(rid.clone()));
		obj.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		let original = Record::new(Value::Object(obj));

		let bytes = original.kv_encode_value().unwrap();
		let decoded = Record::kv_decode_value_with_id(&bytes, rid.clone()).unwrap();
		assert_eq!(decoded, original);
		// And id must be present at the top level.
		match &decoded.data {
			Value::Object(o) => {
				assert_eq!(o.0.get("id"), Some(&Value::RecordId(rid)));
			}
			_ => panic!("expected Value::Object"),
		}
	}

	#[test]
	fn decode_with_id_preserves_legacy_id() {
		// If on-disk bytes still carry an `id` (defensive case: no current
		// writer emits this, but the decode wrapper must tolerate it),
		// the payload's id is preserved and our pending injection is
		// dropped.
		let rid = make_rid("user", "alice");
		let mut obj = Object::default();
		obj.0.insert(Strand::new("id"), Value::RecordId(rid.clone()));
		obj.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		let record = Record::new(Value::Object(obj));

		// Use the standard revision encoder (matches the pre-refactor
		// on-disk format produced *before* the runtime strip ran).
		let bytes = revision::to_vec(&record).unwrap();
		let decoded = Record::kv_decode_value_with_id(&bytes, rid).unwrap();
		assert_eq!(decoded, record);
	}

	#[test]
	fn decode_splices_id_at_sorted_position() {
		// Construct a record with keys that bracket "id" lexicographically:
		// "age" < "id" < "name". After encode (which strips id) + decode
		// the entries should be `[age, id, name]`, with id spliced in at
		// the correct sorted slot rather than appended and re-sorted.
		let rid = make_rid("user", "alice");
		let mut obj = Object::default();
		obj.0.insert(Strand::new("age"), Value::from(30i64));
		obj.0.insert(Strand::new("id"), Value::RecordId(rid.clone()));
		obj.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		let original = Record::new(Value::Object(obj));

		let bytes = original.kv_encode_value().unwrap();
		let decoded = Record::kv_decode_value_with_id(&bytes, rid.clone()).unwrap();

		match &decoded.data {
			Value::Object(o) => {
				let keys: Vec<&str> = o.0.iter().map(|(k, _)| k.as_str()).collect();
				assert_eq!(keys, vec!["age", "id", "name"]);
				assert_eq!(o.0.get("id"), Some(&Value::RecordId(rid)));
			}
			_ => panic!("expected Value::Object"),
		}
	}

	#[test]
	fn decode_appends_id_when_no_greater_key() {
		// All payload keys sort before "id" → id is appended at the end.
		let rid = make_rid("user", "alice");
		let mut obj = Object::default();
		obj.0.insert(Strand::new("age"), Value::from(30i64));
		obj.0.insert(Strand::new("address"), Value::String(Strand::new("123 main")));
		obj.0.insert(Strand::new("id"), Value::RecordId(rid.clone()));
		let original = Record::new(Value::Object(obj));

		let bytes = original.kv_encode_value().unwrap();
		let decoded = Record::kv_decode_value_with_id(&bytes, rid).unwrap();
		match &decoded.data {
			Value::Object(o) => {
				let keys: Vec<&str> = o.0.iter().map(|(k, _)| k.as_str()).collect();
				assert_eq!(keys, vec!["address", "age", "id"]);
			}
			_ => panic!("expected Value::Object"),
		}
	}

	#[test]
	fn decode_prepends_id_when_no_lesser_key() {
		// All payload keys sort after "id" → id is spliced in at the front.
		let rid = make_rid("user", "alice");
		let mut obj = Object::default();
		obj.0.insert(Strand::new("id"), Value::RecordId(rid.clone()));
		obj.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		obj.0.insert(Strand::new("zip"), Value::from(12345i64));
		let original = Record::new(Value::Object(obj));

		let bytes = original.kv_encode_value().unwrap();
		let decoded = Record::kv_decode_value_with_id(&bytes, rid).unwrap();
		match &decoded.data {
			Value::Object(o) => {
				let keys: Vec<&str> = o.0.iter().map(|(k, _)| k.as_str()).collect();
				assert_eq!(keys, vec!["id", "name", "zip"]);
			}
			_ => panic!("expected Value::Object"),
		}
	}

	#[test]
	fn nested_id_is_preserved() {
		// The id skip applies only to the top-level object of `data`.
		// Nested objects with their own `id` field must round-trip intact.
		let rid = make_rid("user", "alice");

		let mut profile = Object::default();
		profile.0.insert(Strand::new("id"), Value::String(Strand::new("profile:7")));
		profile.0.insert(Strand::new("bio"), Value::String(Strand::new("hello")));

		let mut friend1 = Object::default();
		friend1.0.insert(Strand::new("id"), Value::String(Strand::new("user:bob")));
		let mut friend2 = Object::default();
		friend2.0.insert(Strand::new("id"), Value::String(Strand::new("user:carol")));

		let friends = Array(vec![Value::Object(friend1.clone()), Value::Object(friend2.clone())]);

		let mut top = Object::default();
		top.0.insert(Strand::new("id"), Value::RecordId(rid.clone()));
		top.0.insert(Strand::new("profile"), Value::Object(profile.clone()));
		top.0.insert(Strand::new("friends"), Value::Array(friends));

		let record = Record::new(Value::Object(top));

		let bytes = record.kv_encode_value().unwrap();
		let decoded = Record::kv_decode_value_with_id(&bytes, rid.clone()).unwrap();

		match &decoded.data {
			Value::Object(o) => {
				assert_eq!(o.0.get("id"), Some(&Value::RecordId(rid)));
				match o.0.get("profile") {
					Some(Value::Object(p)) => {
						assert_eq!(p.0.get("id"), Some(&Value::String(Strand::new("profile:7"))));
					}
					_ => panic!("expected nested profile object"),
				}
				match o.0.get("friends") {
					Some(Value::Array(arr)) => {
						let v: Vec<_> = arr.iter().collect();
						match v[0] {
							Value::Object(f) => {
								assert_eq!(
									f.0.get("id"),
									Some(&Value::String(Strand::new("user:bob")))
								);
							}
							_ => panic!("expected nested friend object"),
						}
						match v[1] {
							Value::Object(f) => {
								assert_eq!(
									f.0.get("id"),
									Some(&Value::String(Strand::new("user:carol")))
								);
							}
							_ => panic!("expected nested friend object"),
						}
					}
					_ => panic!("expected friends array"),
				}
			}
			_ => panic!("expected Value::Object"),
		}
	}

	#[test]
	fn encode_without_id_matches_standard() {
		// When the record has no top-level id, the custom encoder takes
		// the fast path (delegates to the derived `Value` encoder),
		// producing bytes byte-identical to `revision::to_vec`.
		let mut obj = Object::default();
		obj.0.insert(Strand::new("name"), Value::String(Strand::new("Alice")));
		obj.0.insert(Strand::new("age"), Value::from(30i64));
		let record = Record::new(Value::Object(obj));

		let custom = record.kv_encode_value().unwrap();
		let standard = revision::to_vec(&record).unwrap();
		assert_eq!(custom, standard);
	}
}
