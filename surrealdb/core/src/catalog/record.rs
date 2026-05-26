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
/// - **Rev 1** — sequential fields (`u16 revision || metadata || data`). Skipping past `metadata`
///   requires walking its inner structure with `SkipRevisioned`.
/// - **Rev 2** — optimised envelope + `indexed_struct` prologue: `u16 revision || u32_le
///   payload_length || [u32_le metadata_off, u32_le data_off] || metadata bytes || data bytes`. The
///   two `u32_le` offsets are relative to the start of the prologue, so the data field's bytes are
///   `payload[data_off..]` — O(1) to locate regardless of how big the metadata was.
///
/// The pre-decode filter consumes this via the macro-emitted accessor:
/// `Record::walk_revisioned(...)?.into_data_bytes()?` returns the `data`
/// field's bytes as `Cow<'_, [u8]>` in O(1) on rev-2 (offset-table slice) and
/// via a sequential `metadata` skip on rev-1, without decoding the field's
/// inner value. The caller then opens `Value::walk_revisioned` over the
/// returned bytes for streaming descent — see
/// [`crate::val::object_extract::extract_field_from_record_bytes`].
#[revisioned(revision(1), revision(2, optimised, indexed_struct))]
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
			2 => Self::decode_rev2_with_id(bytes, rid),
			x => Err(anyhow!("Invalid revision `{x}` for type `Record`")),
		}
	}
}

impl Record {
	/// Compile-time guard: every revision of [`Record`] supported on
	/// disk must have a corresponding arm in [`Record::kv_decode_value`].
	/// Bumping `#[revisioned(revision = N)]` on [`Record`] without adding
	/// a matching `decode_revN_with_id` arm trips this assertion at
	/// `cargo build` time.
	///
	/// The strict equality (rather than `<=`) is deliberate: each revision
	/// bump must be paired with a deliberate update here. Loosening to a
	/// `<=` bound would let someone add `revision(3, …)` to the annotation
	/// without writing a `decode_rev3_with_id` arm — `kv_decode_value`
	/// would silently start erroring at runtime for rev-3 records, rather
	/// than failing the build. Catching this at compile time is cheap.
	const _ASSERT_REVISION_DISPATCHER_COVERS_CURRENT: () = assert!(
		<Record>::REVISION == 2,
		"Record revision changed: add the matching `decode_revN_with_id` arm in `kv_decode_value` and bump this assert",
	);

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

	/// Decode a `Record` revision-2 (`optimised, indexed_struct`) value
	/// from `bytes` starting at the `u16` revision tag. Defers the
	/// envelope decode to the macro-generated
	/// `<Record as DeserializeRevisioned>::deserialize_revisioned` and
	/// then splices the canonical `id` into the top-level `Object` if the
	/// payload is one.
	///
	/// Rev-1's hand-rolled decoder reads `metadata` and `data` sequentially
	/// from the post-rev reader; the rev-2 envelope wraps the body in
	/// `u32_le payload_length` plus an indexed-struct offset prologue, so
	/// hand-rolling would duplicate the macro's envelope parsing. The
	/// macro path is `O(field_count)` for skip-bound offsets plus the
	/// actual field decodes, identical asymptotically to the rev-1 path.
	///
	/// **Why not splice-during-decode like rev-1?** Rev-1's hand-rolled
	/// path reads `metadata` and `data` as locals then constructs the
	/// `Record` from them, so it can mutate `data` between decoding fields
	/// at zero cost. Rev-2 goes through the macro's full deserialiser,
	/// which materialises a complete `Record` struct before returning —
	/// we can't borrow `record.data` mutably mid-decode without forking
	/// the macro's codegen. Splicing post-hoc costs one `VecMap::entry`
	/// lookup against the (typically empty) top-level Object's key set;
	/// rev-2 records also originate from the read side of KV, not the
	/// scan hot loop, so this isn't on the critical descent path.
	fn decode_rev2_with_id(bytes: &[u8], rid: RecordId) -> Result<Record> {
		let mut reader: &[u8] = bytes;
		let mut record = <Record as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		if let Value::Object(obj) = &mut record.data {
			obj.0.entry(ID_KEY).or_insert_with(|| Value::RecordId(rid));
		}
		Ok(record)
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
				record_type: RecordType::Edge { .. },
				..
			})
		)
	}

	/// Returns the adjacency-key format variant of this edge record, if
	/// any. Returns `None` for non-edge records. Callers that need to
	/// preserve an existing edge's variant on UPDATE (rather than
	/// downgrading it to a different write-time default) should source
	/// the variant from this helper on the prior document.
	pub const fn edge_variant(&self) -> Option<u16> {
		match &self.metadata {
			Some(Metadata {
				record_type: RecordType::Edge {
					variant,
				},
				..
			}) => Some(*variant),
			_ => None,
		}
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

/// The adjacency-key layout generation used when writing brand-new edges.
///
/// Existing edges keep whatever variant they were originally stamped with
/// so their on-disk keys stay valid — only first-write picks this value.
/// Bump when the on-disk adjacency-key layout for new edges advances; add
/// a matching dispatch arm in `doc/edges.rs::store_edges_data` (write) and
/// `doc/purge.rs::purge_pointers` (delete) at the same time.
pub(crate) const LATEST_EDGE_VARIANT: u16 = 2;

/// Types of records that can be stored in the database
///
/// This enum defines the different types of records that can be stored.
/// Edge records carry a `variant` discriminator so format-aware paths
/// (adjacency-key writes, edge purge) know which on-disk layout the
/// record was created against and can dispatch accordingly.
#[revisioned(revision = 2)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Hash)]
pub(crate) enum RecordType {
	/// Represents a normal table record
	/// From 3.0.0
	#[default]
	Table,
	/// Revision-1 unit form of `Edge`. Records persisted before the
	/// variant marker existed deserialize through this variant and are
	/// upgraded to `Edge { variant: 1 }`, which corresponds to the
	/// original adjacency-key layout (no embedded target vertex).
	/// From v3.0.0 to 3.1.0
	#[revision(end = 2, convert_fn = "upgrade_edge_v1", fields_name = "EdgeV1")]
	Edge,
	/// Represents an edge in a graph. `variant` identifies which
	/// adjacency-key layout was used when the edge was written, so the
	/// purge path knows exactly which keys to delete without probing
	/// multiple formats. New edges get the current format generation;
	/// older edges keep whatever variant they were written with.
	/// From v3.1.0
	#[revision(start = 2)]
	Edge {
		variant: u16,
	},
}

impl RecordType {
	/// Legacy unit `Edge` records predate the variant marker and were
	/// always written with the original adjacency-key layout. Stamp
	/// them as variant 1 on decode so format-aware code paths can treat
	/// them uniformly with explicitly-stamped records going forward.
	fn upgrade_edge_v1(_fields: EdgeV1, _revision: u16) -> Result<Self, revision::Error> {
		Ok(Self::Edge {
			variant: 1,
		})
	}
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
	fn legacy_unit_edge_decodes_to_variant_one() {
		// Records persisted before the variant marker existed wrote
		// `RecordType::Edge` as a rev-1 unit variant. The rev-1 → rev-2
		// upgrade path must map them to `Edge { variant: 1 }` so the
		// purge layer (which dispatches on the variant) treats them as
		// the original adjacency-key layout.
		use revision::{DeserializeRevisioned, SerializeRevisioned, revisioned};

		#[revisioned(revision = 1)]
		#[derive(Debug, PartialEq)]
		enum LegacyRecordType {
			Table,
			Edge,
		}

		let mut bytes = Vec::new();
		LegacyRecordType::Edge.serialize_revisioned(&mut bytes).unwrap();

		let decoded =
			<RecordType as DeserializeRevisioned>::deserialize_revisioned(&mut bytes.as_slice())
				.unwrap();
		assert_eq!(
			decoded,
			RecordType::Edge {
				variant: 1,
			}
		);
	}

	#[test]
	fn current_edge_round_trips_through_metadata() {
		// A `Metadata` containing `Edge { variant: N }` must round-trip
		// through the revisioned encoder/decoder without losing the
		// variant marker. This guards against accidental regressions
		// where Metadata's encoding inadvertently strips struct-variant
		// fields on the RecordType field.
		use revision::{DeserializeRevisioned, SerializeRevisioned};

		let original = Metadata {
			record_type: RecordType::Edge {
				variant: 7,
			},
			aggregation_stats: Vec::new(),
		};
		let mut bytes = Vec::new();
		original.serialize_revisioned(&mut bytes).unwrap();
		let decoded =
			<Metadata as DeserializeRevisioned>::deserialize_revisioned(&mut bytes.as_slice())
				.unwrap();
		assert_eq!(decoded, original);
	}

	#[test]
	fn bool_record_encoded_size_is_stable() {
		// Pin the encoded byte length for a minimal `Record { data: Bool(true) }`
		// so accidental changes to the revisioned wire format (e.g. extra
		// metadata bytes, a Bool encoding change) trip a test. Previously
		// covered by the generic `test_serialize_deserialize` rstest, which
		// dropped its Record case when the `KeyContext = ()` bound was added.
		//
		// Wire breakdown under rev-2 `optimised, indexed_struct`:
		//   1 byte  u16 rev=2 (varint)
		//   4 bytes u32_le payload_length = 12
		//  12 bytes payload:
		//      8 bytes prologue (`u32_le metadata_off=8, u32_le data_off=9`)
		//      1 byte  metadata = Option::None tag
		//      3 bytes data = Value::Bool(true) (rev=2 || tag=0x22 || 0x01)
		//  ─────────
		//  17 bytes total.
		assert_eq!(Record::new(Value::Bool(true)).kv_encode_value().unwrap().len(), 17);
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
