//! Record module for SurrealDB
//!
//! This module provides the `Record` type which represents a database record with metadata.
//! Records can contain both data and metadata about the record type (e.g., whether it's an edge).

use std::sync::Arc;

use anyhow::{Result, anyhow};
use revision::{DeserializeRevisioned, revisioned};
use surrealdb_strand::Strand;

use crate::catalog::aggregation::AggregationStat;
use crate::kvs::KVValue;
use crate::val::{RecordId, Value};

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

/// Strand value for the `"id"` field name. Used by the post-decode id
/// splicer so we don't allocate a fresh `Strand` per record.
const ID_KEY: Strand = Strand::new_static("id");

impl KVValue for Record {
	/// The storage key carries the canonical `RecordId`, which the value
	/// encoder strips from `data` and the value decoder splices back in.
	type KeyContext = RecordId;

	/// Encode a `Record` for storage, skipping the top-level `id` field of
	/// `data` if present. The id is reconstructed from the storage key on
	/// read (see [`Record::kv_decode_value`]), so storing it in the
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
	/// When `Object` adopted `revision(2, optimised)` the
	/// previous inline-splice optimisation broke: the rev-2 envelope
	/// wraps the body in a `u32_le payload_length`, so we can no longer
	/// write a stripped body byte-by-byte without knowing the length up
	/// front. Instead, clone the top-level `Object`, remove `"id"`, and
	/// hand the cleaned record to the derived serializer. The clone is
	/// O(n) over the immediate keys of the top-level object; nested
	/// structure is moved, not cloned.
	fn kv_encode_value(&self) -> Result<Vec<u8>> {
		match &self.data {
			Value::Object(obj) if obj.0.contains_key("id") => {
				let mut cleaned = obj.clone();
				cleaned.0.remove("id");
				let stripped = Record {
					metadata: self.metadata.clone(),
					data: Value::Object(cleaned),
				};
				Ok(revision::to_vec(&stripped)?)
			}
			_ => Ok(revision::to_vec(self)?),
		}
	}

	/// Decode a `Record` and ensure its `data` carries the canonical `id`
	/// reconstructed from the storage key.
	///
	/// Uses the derived deserialiser for the whole record, then splices
	/// `id` into the top-level `Object` if the payload is an object that
	/// doesn't already carry one.
	fn kv_decode_value(bytes: &[u8], rid: RecordId) -> Result<Record> {
		let mut reader: &[u8] = bytes;
		let record_rev = <u16 as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		match record_rev {
			1 => Self::decode_rev1_with_id(reader, rid),
			x => Err(anyhow!("Invalid revision `{x}` for type `Record`")),
		}
	}
}

impl Record {
	/// Compile-time guard: every revision of [`Record`] supported on
	/// disk must have a corresponding arm in [`Record::kv_decode_value`].
	/// Bumping `#[revisioned(revision = N)]` on [`Record`] without adding
	/// a matching `decode_revN_with_id` arm will trip this assertion at
	/// `cargo build` time.
	const _ASSERT_REVISION_DISPATCHER_COVERS_CURRENT: () =
		assert!(<Record>::REVISION <= 1, "Record revision exceeds the decoder's handled max");

	/// Decode a `Record` revision-1 body (i.e. after the Record revision
	/// tag has already been consumed), splicing the canonical `id` into
	/// the top-level `Object` after the fact.
	fn decode_rev1_with_id(mut reader: &[u8], rid: RecordId) -> Result<Record> {
		let metadata =
			<Option<Metadata> as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		let mut data = <Value as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		// Splice the canonical record id into the top-level `Object` (if
		// the payload is one). VecMap's `Entry` API maintains the
		// sorted-key invariant; `Vacant` inserts in O(log n), `Occupied`
		// preserves whatever the payload already carried (defensive — no
		// current writer emits an `id` field, but legacy bytes might).
		if let Value::Object(obj) = &mut data {
			obj.0.entry(ID_KEY).or_insert_with(|| Value::RecordId(rid));
		}
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
	fn bool_record_encoded_size_is_stable() {
		// Pin the encoded byte length for a minimal `Record { data: Bool(true) }`
		// so accidental changes to the revisioned wire format (e.g. extra
		// metadata bytes, a Bool encoding change) trip a test. Previously
		// covered by the generic `test_serialize_deserialize` rstest, which
		// dropped its Record case when the `KeyContext = ()` bound was added.
		assert_eq!(Record::new(Value::Bool(true)).kv_encode_value().unwrap().len(), 5);
	}

	#[test]
	fn custom_encode_matches_derive_encode_of_stripped_record() {
		// The custom `KVValue` encoder clones the top-level Object, removes
		// `"id"`, then hands the cleaned record to the derived serializer.
		// Result must be byte-identical to the derived encode of a record
		// that never had an id to begin with.
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
		let decoded = Record::kv_decode_value(&bytes, rid.clone()).unwrap();
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
		let decoded = Record::kv_decode_value(&bytes, rid).unwrap();
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
		let decoded = Record::kv_decode_value(&bytes, rid.clone()).unwrap();

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
		let decoded = Record::kv_decode_value(&bytes, rid).unwrap();
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
		let decoded = Record::kv_decode_value(&bytes, rid).unwrap();
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
		let decoded = Record::kv_decode_value(&bytes, rid.clone()).unwrap();

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
