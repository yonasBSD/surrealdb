use std::cmp::Ordering;
use std::ops::Bound;

use rand::seq::IndexedRandom;
use reblessive::tree::Stk;
use revision::revisioned;
use rust_decimal::Decimal;
use rust_decimal::prelude::ToPrimitive;
use storekey::{BorrowDecode, Encode};
use surrealdb_types::{SqlFormat, ToSql, write_sql};
use ulid::Ulid;

use crate::cnf::ID_CHARS;
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::CursorDoc;
use crate::expr::{self, Expr, Field, Fields, Literal, SelectStatement};
use crate::fmt::EscapeRidKey;
use crate::kvs::impl_kv_value_revisioned;
use crate::val::number::NumberKind;
use crate::val::{Array, IndexFormat, Number, Object, Range, Strand, TableName, Uuid, Value};

#[revisioned(revision = 1)]
#[derive(Clone, Debug, Eq, PartialEq, Hash, Encode, BorrowDecode)]
#[storekey(format = "()")]
#[storekey(format = "IndexFormat")]
pub(crate) struct RecordIdKeyRange {
	pub start: Bound<RecordIdKey>,
	pub end: Bound<RecordIdKey>,
}

impl PartialOrd for RecordIdKeyRange {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for RecordIdKeyRange {
	fn cmp(&self, other: &Self) -> Ordering {
		fn compare_bounds(a: &Bound<RecordIdKey>, b: &Bound<RecordIdKey>) -> Ordering {
			match a {
				Bound::Unbounded => match b {
					Bound::Unbounded => Ordering::Equal,
					_ => Ordering::Less,
				},
				Bound::Included(a) => match b {
					Bound::Unbounded => Ordering::Greater,
					Bound::Included(b) => a.cmp(b),
					Bound::Excluded(_) => Ordering::Less,
				},
				Bound::Excluded(a) => match b {
					Bound::Excluded(b) => a.cmp(b),
					_ => Ordering::Greater,
				},
			}
		}
		match compare_bounds(&self.start, &other.end) {
			Ordering::Equal => compare_bounds(&self.end, &other.end),
			x => x,
		}
	}
}

impl ToSql for RecordIdKeyRange {
	fn fmt_sql(&self, f: &mut String, sql_fmt: SqlFormat) {
		match self.start {
			Bound::Unbounded => {}
			Bound::Included(ref x) => write_sql!(f, sql_fmt, "{x}"),
			Bound::Excluded(ref x) => write_sql!(f, sql_fmt, "{x}>"),
		}
		write_sql!(f, sql_fmt, "..");
		match self.end {
			Bound::Unbounded => {}
			Bound::Included(ref x) => write_sql!(f, sql_fmt, "={x}"),
			Bound::Excluded(ref x) => write_sql!(f, sql_fmt, "{x}"),
		}
	}
}

impl TryFrom<RecordIdKeyRange> for crate::types::PublicRecordIdKeyRange {
	type Error = anyhow::Error;

	fn try_from(value: RecordIdKeyRange) -> Result<Self, Self::Error> {
		Ok(crate::types::PublicRecordIdKeyRange {
			start: match value.start {
				Bound::Included(x) => Bound::Included(x.try_into()?),
				Bound::Excluded(x) => Bound::Excluded(x.try_into()?),
				Bound::Unbounded => Bound::Unbounded,
			},
			end: match value.end {
				Bound::Included(x) => Bound::Included(x.try_into()?),
				Bound::Excluded(x) => Bound::Excluded(x.try_into()?),
				Bound::Unbounded => Bound::Unbounded,
			},
		})
	}
}

impl From<crate::types::PublicRecordIdKeyRange> for RecordIdKeyRange {
	fn from(value: crate::types::PublicRecordIdKeyRange) -> Self {
		RecordIdKeyRange {
			start: value.start.map(|x| x.into()),
			end: value.end.map(|x| x.into()),
		}
	}
}

impl RecordIdKeyRange {
	pub(crate) fn into_literal(self) -> expr::RecordIdKeyRangeLit {
		let start = self.start.map(|x| x.into_literal());
		let end = self.end.map(|x| x.into_literal());
		expr::RecordIdKeyRangeLit {
			start,
			end,
		}
	}

	/// Convertes a record id key range into the range from a normal value.
	pub(crate) fn into_value_range(self) -> Range {
		Range {
			start: self.start.map(|x| x.into_value()),
			end: self.end.map(|x| x.into_value()),
		}
	}

	/// Convertes a record id key range into the range from a normal value.
	pub(crate) fn from_value_range(range: Range) -> Option<Self> {
		let start = match range.start {
			Bound::Included(x) => Bound::Included(RecordIdKey::from_value(x)?),
			Bound::Excluded(x) => Bound::Excluded(RecordIdKey::from_value(x)?),
			Bound::Unbounded => Bound::Unbounded,
		};
		let end = match range.end {
			Bound::Included(x) => Bound::Included(RecordIdKey::from_value(x)?),
			Bound::Excluded(x) => Bound::Excluded(RecordIdKey::from_value(x)?),
			Bound::Unbounded => Bound::Unbounded,
		};

		Some(RecordIdKeyRange {
			start,
			end,
		})
	}
}

impl PartialEq<Range> for RecordIdKeyRange {
	fn eq(&self, other: &Range) -> bool {
		(match self.start {
			Bound::Included(ref a) => {
				if let Bound::Included(ref b) = other.start {
					a == b
				} else {
					false
				}
			}
			Bound::Excluded(ref a) => {
				if let Bound::Excluded(ref b) = other.start {
					a == b
				} else {
					false
				}
			}
			Bound::Unbounded => matches!(other.start, Bound::Unbounded),
		}) && (match self.end {
			Bound::Included(ref a) => {
				if let Bound::Included(ref b) = other.end {
					a == b
				} else {
					false
				}
			}
			Bound::Excluded(ref a) => {
				if let Bound::Excluded(ref b) = other.end {
					a == b
				} else {
					false
				}
			}
			Bound::Unbounded => matches!(other.end, Bound::Unbounded),
		})
	}
}

/// A key component of a [`RecordId`].
///
/// Numeric record IDs use a single [`Number`] variant. `Number`'s manual
/// `Eq`/`Hash`/`Ord` impls give cross-variant numeric equality at the Rust
/// level (`Number::Int(1) == Number::Float(1.0) == Number::Decimal(1.0dec)`),
/// so the outer derives transparently inherit that behaviour. The custom
/// storekey [`Encode`]/[`BorrowDecode`] impls below canonicalize at encode
/// time so the same record ID always produces the same on-disk bytes
/// regardless of which numeric sub-variant the caller used.
///
/// On-disk discriminants for the storekey (KV-key) format:
///
/// | byte | variant                                  |
/// |------|------------------------------------------|
/// | 2    | *(legacy 3.0.x / 3.1.0-beta `Number(Number::Int(_))` — decode-only; rewritten under disc 10 by [`crate::kvs::Datastore::migrate_record_ids`])* |
/// | 3    | `String`                                 |
/// | 4    | `Uuid`                                   |
/// | 5    | `Array`                                  |
/// | 6    | `Object`                                 |
/// | 7    | `Range`                                  |
/// | 8    | *(reserved, never shipped: legacy float slot)* — decode-only |
/// | 9    | *(reserved, never shipped: legacy decimal slot)* — decode-only |
/// | 10   | `Number(Number::*)` — unified lex layout (`as_decimal_buf` + [`NumberKind`] marker). Byte order matches `Number::cmp` numeric order. |
///
/// Discriminants 3..=7 are inherited from the previous storekey-derived
/// layout. The encoder always emits disc 10 for `Number(_)`; discs 2, 8,
/// and 9 are accepted by the decoder so the migration tool can read
/// every shipped layout, but no new writes ever produce them.
///
/// On the revisioned (value-side) wire format, rev-1 used a single
/// `Number(i64)` variant. The `OldNumber` phantom variant below carries that
/// legacy shape; the revision macro turns it into the rev-2 `Number(Number)`
/// form via [`Self::convert_old_number_to_number`] at deserialisation time
/// and excludes it from the runtime enum.
#[revisioned(revision = 2)]
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) enum RecordIdKey {
	#[revision(end = 2, convert_fn = "convert_old_number_to_number")]
	OldNumber(i64),
	String(Strand),
	Uuid(Uuid),
	Array(Array),
	Object(Object),
	Range(Box<RecordIdKeyRange>),
	#[revision(start = 2)]
	Number(Number),
}

impl_kv_value_revisioned!(RecordIdKey);

impl RecordIdKey {
	/// Migration from rev-1 `Number(i64)` to rev-2 `Number(Number::Int(_))`.
	///
	/// Called by the `#[revisioned]` macro when deserialising rev-1 bytes.
	#[allow(clippy::needless_pass_by_value)]
	fn convert_old_number_to_number(
		fields: RecordIdKeyOldNumberFields,
		_revision: u16,
	) -> Result<Self, revision::Error> {
		Ok(Self::Number(Number::Int(fields.0)))
	}
}

// ---------------------------------------------------------------------------
// Encode-time canonicalization — collapses numerically-equivalent numeric
// values to the narrowest representation so equivalent `Number(Number::*)`
// inputs always produce the same on-disk bytes.
// ---------------------------------------------------------------------------

/// Canonical numeric form selected at encode time.
enum CanonicalNumber {
	Int(i64),
	Float(f64),
	Decimal(Decimal),
}

/// Collapse a `Number` to its narrowest canonical representation, or return
/// `None` for NaN / ±∞ (never valid as a record-id key).
fn canonicalize_number(n: &Number) -> Option<CanonicalNumber> {
	match n {
		Number::Int(i) => Some(CanonicalNumber::Int(*i)),
		Number::Float(f) => {
			if !f.is_finite() {
				None
			} else if f.fract() == 0.0
				&& *f >= i64::MIN as f64
				// Strict less-than: `i64::MAX = 2^63 − 1` is NOT exactly
				// representable in f64 (it rounds up to `2^63`), so
				// `i64::MAX as f64 == 2^63 as f64`. With a non-strict bound
				// `f = 2^63` would pass, saturate-cast to `i64::MAX = 2^63 − 1`
				// and silently lose 1 — and worse, alias with a real
				// `Int(i64::MAX)` row on disk. The strict bound at `2^63`
				// keeps `Float(2^63)` in the Float slot (disc 8), symmetric
				// with `Decimal(2^63)`'s canonical form, and the cast inside
				// the branch becomes lossless: every integer-valued f64 in
				// `[i64::MIN, 2^63)` round-trips through `as i64`.
				&& *f < i64::MAX as f64
			{
				Some(CanonicalNumber::Int(*f as i64))
			} else {
				Some(CanonicalNumber::Float(*f))
			}
		}
		Number::Decimal(d) => {
			// Integer-valued decimal that fits in i64
			if let Some(i) = d.to_i64()
				&& Decimal::from(i) == *d
			{
				return Some(CanonicalNumber::Int(i));
			}
			// Float-representable decimal that round-trips bit-exactly
			if let Some(f) = d.to_f64()
				&& f.is_finite()
				&& let Some(d2) = Decimal::from_f64_retain(f)
				&& d2 == *d
			{
				return Some(CanonicalNumber::Float(f));
			}
			Some(CanonicalNumber::Decimal(*d))
		}
	}
}

// ---------------------------------------------------------------------------
// Custom storekey Encode / BorrowDecode — replaces the derive.
//
// `Number` records are always emitted under disc 10 with an
// `as_decimal_buf` lex payload + a `NumberKind` variant marker, so byte
// order matches `Number::cmp` numeric order across `Int` / `Float` /
// `Decimal`.
//
// The decoder additionally accepts the legacy discs 2/8/9 so the
// [`crate::kvs::Datastore::migrate_record_ids`] tool can read every
// shipped layout. Discs 8 and 9 are decode-only — main-branch databases
// between `bd332d882` (introduction of the Float/Decimal slots) and the
// disc-10 unification remain readable, but no new writes ever produce
// them. Disc 2 is the 3.0.x / 3.1.0-beta canonical-Int layout (`[disc=2,
// raw_i64]`). Anyone opening such a database without first running
// `surreal migrate-record-ids` will see id-based lookups fail because
// the encoder emits disc-10 byte sequences that don't match the legacy
// disc-2 keys on disk.
// ---------------------------------------------------------------------------

const DISC_NUMBER_INT: u8 = 2;
const DISC_STRING: u8 = 3;
const DISC_UUID: u8 = 4;
const DISC_ARRAY: u8 = 5;
const DISC_OBJECT: u8 = 6;
const DISC_RANGE: u8 = 7;
/// Legacy float slot (decode-only — never shipped in a release tag).
const DISC_NUMBER_FLOAT: u8 = 8;
/// Legacy decimal slot (decode-only — never shipped in a release tag).
const DISC_NUMBER_DECIMAL: u8 = 9;
/// Unified numeric record-id slot.
///
/// Layout: `[10, as_decimal_buf(canonical), NumberKind]`. The
/// `as_decimal_buf` payload is lex-sortable across canonical Int / Float /
/// Decimal so byte order matches `Number::cmp`. The trailing
/// [`NumberKind`] marker preserves the original canonical variant for
/// decode round-trip.
const DISC_NUMBER_LEX: u8 = 10;

fn encode_record_id_key<F, W>(
	key: &RecordIdKey,
	w: &mut storekey::Writer<W>,
) -> Result<(), storekey::EncodeError>
where
	W: std::io::Write,
	Strand: Encode<F>,
	Uuid: Encode<F>,
	Array: Encode<F>,
	Object: Encode<F>,
	RecordIdKeyRange: Encode<F>,
	NumberKind: Encode<F>,
{
	match key {
		RecordIdKey::Number(n) => {
			let canonical = canonicalize_number(n).ok_or_else(|| {
				storekey::EncodeError::Custom(
					anyhow::anyhow!("NaN or ±∞ is not a valid RecordIdKey").into(),
				)
			})?;
			let (number, kind) = match canonical {
				CanonicalNumber::Int(i) => (Number::Int(i), NumberKind::Int),
				CanonicalNumber::Float(f) => (Number::Float(f), NumberKind::Float),
				CanonicalNumber::Decimal(d) => (Number::Decimal(d), NumberKind::Decimal),
			};
			w.write_u8(DISC_NUMBER_LEX)?;
			w.write_slice(&number.as_decimal_buf())?;
			Encode::<F>::encode(&kind, w)
		}
		RecordIdKey::String(s) => {
			w.write_u8(DISC_STRING)?;
			Encode::<F>::encode(s, w)
		}
		RecordIdKey::Uuid(u) => {
			w.write_u8(DISC_UUID)?;
			Encode::<F>::encode(u, w)
		}
		RecordIdKey::Array(a) => {
			w.write_u8(DISC_ARRAY)?;
			Encode::<F>::encode(a, w)
		}
		RecordIdKey::Object(o) => {
			w.write_u8(DISC_OBJECT)?;
			Encode::<F>::encode(o, w)
		}
		RecordIdKey::Range(r) => {
			w.write_u8(DISC_RANGE)?;
			Encode::<F>::encode(r.as_ref(), w)
		}
	}
}

fn borrow_decode_record_id_key<'de, F>(
	r: &mut storekey::BorrowReader<'de>,
) -> Result<RecordIdKey, storekey::DecodeError>
where
	Strand: BorrowDecode<'de, F>,
	Uuid: BorrowDecode<'de, F>,
	Array: BorrowDecode<'de, F>,
	Object: BorrowDecode<'de, F>,
	RecordIdKeyRange: BorrowDecode<'de, F>,
	NumberKind: BorrowDecode<'de, F>,
{
	let disc = r.read_u8()?;
	match disc {
		DISC_NUMBER_INT => Ok(RecordIdKey::Number(Number::Int(r.read_i64()?))),
		DISC_STRING => Ok(RecordIdKey::String(<Strand as BorrowDecode<'de, F>>::borrow_decode(r)?)),
		DISC_UUID => Ok(RecordIdKey::Uuid(<Uuid as BorrowDecode<'de, F>>::borrow_decode(r)?)),
		DISC_ARRAY => Ok(RecordIdKey::Array(<Array as BorrowDecode<'de, F>>::borrow_decode(r)?)),
		DISC_OBJECT => Ok(RecordIdKey::Object(<Object as BorrowDecode<'de, F>>::borrow_decode(r)?)),
		DISC_RANGE => Ok(RecordIdKey::Range(Box::new(<RecordIdKeyRange as BorrowDecode<
			'de,
			F,
		>>::borrow_decode(r)?))),
		// Legacy float / decimal slots — decode-only, never emitted.
		DISC_NUMBER_FLOAT => Ok(RecordIdKey::Number(Number::Float(r.read_f64()?))),
		DISC_NUMBER_DECIMAL => {
			let bytes = r.read_array::<16>()?;
			Ok(RecordIdKey::Number(Number::Decimal(Decimal::deserialize(bytes))))
		}
		DISC_NUMBER_LEX => {
			let slice = r.read_cow()?;
			let kind: NumberKind = <NumberKind as BorrowDecode<'de, F>>::borrow_decode(r)?;
			let n = Number::from_decimal_buf_kind(slice.as_ref(), kind)
				.map_err(|_| storekey::DecodeError::InvalidFormat)?;
			Ok(RecordIdKey::Number(n))
		}
		_ => Err(storekey::DecodeError::InvalidFormat),
	}
}

impl Encode<()> for RecordIdKey {
	fn encode<W: std::io::Write>(
		&self,
		w: &mut storekey::Writer<W>,
	) -> Result<(), storekey::EncodeError> {
		encode_record_id_key::<(), W>(self, w)
	}
}

impl<'de> BorrowDecode<'de, ()> for RecordIdKey {
	fn borrow_decode(r: &mut storekey::BorrowReader<'de>) -> Result<Self, storekey::DecodeError> {
		borrow_decode_record_id_key::<()>(r)
	}
}

impl Encode<IndexFormat> for RecordIdKey {
	fn encode<W: std::io::Write>(
		&self,
		w: &mut storekey::Writer<W>,
	) -> Result<(), storekey::EncodeError> {
		encode_record_id_key::<IndexFormat, W>(self, w)
	}
}

impl<'de> BorrowDecode<'de, IndexFormat> for RecordIdKey {
	fn borrow_decode(r: &mut storekey::BorrowReader<'de>) -> Result<Self, storekey::DecodeError> {
		borrow_decode_record_id_key::<IndexFormat>(r)
	}
}

impl RecordIdKey {
	/// Generate a new random ID
	pub fn rand() -> Self {
		let mut rng = rand::rng();
		let id: String = (0..20).map(|_| *ID_CHARS[..].choose(&mut rng).unwrap_or(&'0')).collect();
		Self::String(id.into())
	}
	/// Generate a new random ULID
	pub fn ulid() -> Self {
		Self::String(Ulid::new().to_string().into())
	}
	/// Generate a new random UUID
	pub fn uuid() -> Self {
		Self::Uuid(Uuid::new_v7())
	}

	/// Returns if this key is a range.
	pub fn is_range(&self) -> bool {
		matches!(self, RecordIdKey::Range(_))
	}

	/// Returns surrealql value of this key.
	pub(crate) fn into_value(self) -> Value {
		match self {
			RecordIdKey::Number(n) => Value::Number(n),
			RecordIdKey::String(s) => Value::String(s),
			RecordIdKey::Uuid(u) => Value::Uuid(u),
			RecordIdKey::Object(object) => Value::Object(object),
			RecordIdKey::Array(array) => Value::Array(array),
			RecordIdKey::Range(range) => Value::Range(Box::new(Range {
				start: range.start.map(RecordIdKey::into_value),
				end: range.end.map(RecordIdKey::into_value),
			})),
		}
	}

	/// Tries to convert a value into a record id key,
	///
	/// Returns None if the value cannot be converted. NaN and ±∞ are rejected
	/// for numeric inputs.
	pub(crate) fn from_value(value: Value) -> Option<Self> {
		match value {
			Value::Number(n) => Self::from_number(n),
			Value::String(strand) => Some(RecordIdKey::String(strand)),
			Value::Uuid(uuid) => Some(RecordIdKey::Uuid(uuid)),
			Value::Array(array) => Some(RecordIdKey::Array(array)),
			Value::Object(object) => Some(RecordIdKey::Object(object)),
			Value::Range(range) => {
				RecordIdKeyRange::from_value_range(*range).map(|x| RecordIdKey::Range(Box::new(x)))
			}
			_ => None,
		}
	}

	/// Build a record-id key from a SurrealQL [`Number`]. Returns `None` if
	/// the input is NaN or ±∞ (not valid as a record-id).
	///
	/// This is the canonicalizing entry point for converting numeric Values
	/// into record-id keys. The variant is preserved in memory; encode-time
	/// canonicalization (see [`canonicalize_number`]) collapses equivalent
	/// numeric forms to identical on-disk bytes.
	pub(crate) fn from_number(n: Number) -> Option<Self> {
		match n {
			Number::Float(f) if !f.is_finite() => None,
			_ => Some(RecordIdKey::Number(n)),
		}
	}

	/// Returns the expression which evaluates to the same value
	pub fn into_literal(self) -> expr::RecordIdKeyLit {
		match self {
			RecordIdKey::Number(n) => expr::RecordIdKeyLit::Number(n),
			RecordIdKey::String(s) => expr::RecordIdKeyLit::String(s),
			RecordIdKey::Uuid(uuid) => expr::RecordIdKeyLit::Uuid(uuid),
			RecordIdKey::Object(object) => expr::RecordIdKeyLit::Object(object.into_literal()),
			RecordIdKey::Array(array) => expr::RecordIdKeyLit::Array(array.into_literal()),
			RecordIdKey::Range(range) => {
				expr::RecordIdKeyLit::Range(Box::new(range.into_literal()))
			}
		}
	}
}

impl From<i64> for RecordIdKey {
	fn from(value: i64) -> Self {
		RecordIdKey::Number(Number::Int(value))
	}
}

// No `From<Number>` impl is provided on purpose: an unfiltered `From<Number>`
// would let callers smuggle `Number::Float(NaN)` / `±Infinity` into a record
// id, bypassing the finite-value invariant the storekey encoder enforces.
// Use `RecordIdKey::from_number(Number) -> Option<Self>` instead.

impl From<String> for RecordIdKey {
	fn from(value: String) -> Self {
		RecordIdKey::String(value.into())
	}
}

impl From<Strand> for RecordIdKey {
	fn from(value: Strand) -> Self {
		RecordIdKey::String(value)
	}
}

impl From<Uuid> for RecordIdKey {
	fn from(value: Uuid) -> Self {
		RecordIdKey::Uuid(value)
	}
}
impl From<Object> for RecordIdKey {
	fn from(value: Object) -> Self {
		RecordIdKey::Object(value)
	}
}
impl From<Array> for RecordIdKey {
	fn from(value: Array) -> Self {
		RecordIdKey::Array(value)
	}
}
impl From<Box<RecordIdKeyRange>> for RecordIdKey {
	fn from(value: Box<RecordIdKeyRange>) -> Self {
		RecordIdKey::Range(value)
	}
}

impl From<crate::types::PublicRecordIdKey> for RecordIdKey {
	fn from(value: crate::types::PublicRecordIdKey) -> Self {
		match value {
			crate::types::PublicRecordIdKey::Number(x) => Self::Number(Number::Int(x)),
			// NaN/±∞ are blocked at the construction boundary: every wire
			// format flows through `PublicRecordIdKey`'s manual `Deserialize`
			// impl (which rejects non-finite Float), and the in-crate
			// constructor `from_number` returns `None` for NaN/Inf. Reaching
			// this arm would mean someone constructed `Float(NaN)` directly
			// in Rust — a programmer error worth a clear panic.
			crate::types::PublicRecordIdKey::Float(x) if x.is_finite() => {
				Self::Number(Number::Float(x))
			}
			crate::types::PublicRecordIdKey::Float(_) => unreachable!(
				"PublicRecordIdKey::Float must be finite; construct via RecordIdKey::from_number"
			),
			crate::types::PublicRecordIdKey::Decimal(x) => Self::Number(Number::Decimal(x)),
			crate::types::PublicRecordIdKey::String(x) => Self::String(x.into()),
			crate::types::PublicRecordIdKey::Uuid(x) => Self::Uuid(x.into()),
			crate::types::PublicRecordIdKey::Array(x) => Self::Array(x.into()),
			crate::types::PublicRecordIdKey::Object(x) => Self::Object(x.into()),
			crate::types::PublicRecordIdKey::Range(x) => Self::Range(Box::new((*x).into())),
			// The public type is `#[non_exhaustive]`. Silently aliasing an
			// unknown future variant to a fixed key would be a data-corruption
			// risk (every new variant would collide on the same target key),
			// so we panic instead — a clear, controlled failure that surfaces
			// the missed update during dev rather than at runtime.
			_ => unreachable!(
				"unknown PublicRecordIdKey variant; surrealdb-core needs updating to handle the new variant"
			),
		}
	}
}

impl TryFrom<RecordIdKey> for crate::types::PublicRecordIdKey {
	type Error = anyhow::Error;

	fn try_from(value: RecordIdKey) -> Result<Self, Self::Error> {
		Ok(match value {
			RecordIdKey::Number(Number::Int(i)) => Self::Number(i),
			// Reject non-finite floats at the boundary, mirroring the
			// invariant enforced by `from_number`, the SQL parser, the
			// storekey encoder, and the CBOR decoder. Without this guard a
			// stray in-memory `Number::Float(NaN)` would surface in
			// downstream SDK payloads (CBOR/serde) — the receiving decoder
			// would then reject it, producing a confusing asymmetric
			// round-trip failure.
			RecordIdKey::Number(Number::Float(f)) if f.is_finite() => Self::Float(f),
			RecordIdKey::Number(Number::Float(_)) => {
				anyhow::bail!("NaN and ±Infinity are not valid record-id keys")
			}
			RecordIdKey::Number(Number::Decimal(d)) => Self::Decimal(d),
			RecordIdKey::String(x) => Self::String(x.into()),
			RecordIdKey::Uuid(x) => Self::Uuid(x.into()),
			RecordIdKey::Array(x) => Self::Array(x.try_into()?),
			RecordIdKey::Object(x) => Self::Object(x.try_into()?),
			RecordIdKey::Range(x) => Self::Range(Box::new((*x).try_into()?)),
		})
	}
}

impl PartialEq<Value> for RecordIdKey {
	fn eq(&self, other: &Value) -> bool {
		match self {
			RecordIdKey::Number(a) => Value::Number(*a) == *other,
			RecordIdKey::String(a) => {
				if let Value::String(b) = other {
					a.as_str() == b.as_str()
				} else {
					false
				}
			}
			RecordIdKey::Uuid(a) => {
				if let Value::Uuid(b) = other {
					a == b
				} else {
					false
				}
			}
			RecordIdKey::Object(a) => {
				if let Value::Object(b) = other {
					a == b
				} else {
					false
				}
			}
			RecordIdKey::Array(a) => {
				if let Value::Array(b) = other {
					a == b
				} else {
					false
				}
			}
			RecordIdKey::Range(a) => {
				if let Value::Range(b) = other {
					**a == **b
				} else {
					false
				}
			}
		}
	}
}

impl ToSql for RecordIdKey {
	fn fmt_sql(&self, f: &mut String, sql_fmt: SqlFormat) {
		match self {
			RecordIdKey::Number(n) => write_sql!(f, sql_fmt, "{n}"),
			RecordIdKey::String(v) => write_sql!(f, sql_fmt, "{}", EscapeRidKey(v.as_str())),
			RecordIdKey::Uuid(uuid) => write_sql!(f, sql_fmt, "{}", uuid),
			RecordIdKey::Object(object) => write_sql!(f, sql_fmt, "{}", object),
			RecordIdKey::Array(array) => write_sql!(f, sql_fmt, "{}", array),
			RecordIdKey::Range(rid) => write_sql!(f, sql_fmt, "{}", rid),
		}
	}
}

#[revisioned(revision = 1)]
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, BorrowDecode)]
#[storekey(format = "()")]
#[storekey(format = "IndexFormat")]
pub(crate) struct RecordId {
	pub table: TableName,
	pub key: RecordIdKey,
}

impl_kv_value_revisioned!(RecordId);

impl RecordId {
	/// Creates a new record id from the given table and key
	pub(crate) fn new<K>(table: TableName, key: K) -> Self
	where
		RecordIdKey: From<K>,
	{
		RecordId {
			table,
			key: key.into(),
		}
	}

	pub fn random_for_table(table: TableName) -> Self {
		RecordId {
			table,
			key: RecordIdKey::rand(),
		}
	}

	/// Turns the record id into a literal which resolves to the same value.
	pub(crate) fn into_literal(self) -> expr::RecordIdLit {
		expr::RecordIdLit {
			table: self.table,
			key: self.key.into_literal(),
		}
	}

	pub fn is_table_type(&self, tables: &[TableName]) -> bool {
		tables.is_empty() || tables.contains(&self.table)
	}

	pub(crate) async fn select_document(
		self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		doc: Option<&CursorDoc>,
	) -> anyhow::Result<Option<Object>> {
		// Fetch the record id's contents
		let stm = SelectStatement {
			fields: Fields::Select(vec![Field::All]),
			what: vec![Expr::Literal(Literal::RecordId(self.clone().into_literal()))],
			omit: vec![],
			only: false,
			with: None,
			cond: None,
			split: None,
			group: None,
			order: None,
			limit: None,
			start: None,
			fetch: None,
			version: Expr::Literal(Literal::None),
			timeout: Expr::Literal(Literal::None),
			explain: None,
			tempfiles: false,
		};

		Ok(stk.run(|stk| stm.compute(stk, ctx, opt, doc)).await?.first().into_object())
	}
}

impl TryFrom<RecordId> for crate::types::PublicRecordId {
	type Error = anyhow::Error;

	fn try_from(value: RecordId) -> Result<Self, Self::Error> {
		Ok(crate::types::PublicRecordId {
			table: value.table.into(),
			key: value.key.try_into()?,
		})
	}
}

impl From<crate::types::PublicRecordId> for RecordId {
	fn from(value: crate::types::PublicRecordId) -> Self {
		RecordId {
			table: value.table.into(),
			key: RecordIdKey::from(value.key),
		}
	}
}

impl ToSql for RecordId {
	fn fmt_sql(&self, f: &mut String, sql_fmt: SqlFormat) {
		write_sql!(f, sql_fmt, "{}:{}", EscapeRidKey(&self.table), self.key)
	}
}

#[cfg(test)]
mod tests {
	use rust_decimal::Decimal;
	use rust_decimal::prelude::FromPrimitive;
	use storekey::{decode_borrow, encode_vec};

	use super::*;
	use crate::val::DecimalExt;

	// ------------------------------------------------------------------
	// Encode-time canonicalization in FullNew mode (the default):
	// numerically-equal Int / Float / Decimal inputs collapse to
	// identical on-disk bytes under the unified disc 10 layout.
	// ------------------------------------------------------------------

	/// NumberKind storekey discriminant bytes. Storekey biases enum
	/// variants by +2 (variant 0 → byte 2, etc.) to leave the low byte
	/// values free for Option-style markers; see `storekey::Writer::Enum`.
	const KIND_INT_BYTE: u8 = 2;
	const KIND_FLOAT_BYTE: u8 = 3;
	const KIND_DECIMAL_BYTE: u8 = 4;

	#[test]
	fn encode_int_one_full_new() {
		let key = RecordIdKey::Number(Number::Int(1));
		let bytes = encode_vec(&key).unwrap();
		// disc 10 (unified lex slot) + lex bytes of 1 + Int kind marker.
		// We assert structure rather than every byte: the lex bytes come from
		// `Number::as_decimal_buf()` which is verified independently.
		assert_eq!(bytes[0], DISC_NUMBER_LEX);
		// Last byte is the NumberKind marker — Int.
		assert_eq!(*bytes.last().unwrap(), KIND_INT_BYTE);
	}

	#[test]
	fn encode_int_float_decimal_one_canonicalize_to_same_bytes() {
		let int = encode_vec(&RecordIdKey::Number(Number::Int(1))).unwrap();
		let float = encode_vec(&RecordIdKey::Number(Number::Float(1.0))).unwrap();
		let dec = encode_vec(&RecordIdKey::Number(Number::Decimal(Decimal::from(1)))).unwrap();
		assert_eq!(int, float, "Int(1) and Float(1.0) must canonicalize identically");
		assert_eq!(int, dec, "Int(1) and Decimal(1) must canonicalize identically");
	}

	#[test]
	fn encode_float_two_pow_63_stays_float_not_int_max() {
		// `i64::MAX = 2^63 − 1` is NOT exactly representable in f64; it rounds
		// up to `2^63`, so `i64::MAX as f64` equals `2^63 as f64` exactly.
		// `Float(2^63)` exceeds the i64 range and must therefore NOT silently
		// canonicalize to `Int(i64::MAX)` — that would both lose 1 of
		// precision and alias with a real `Int(i64::MAX)` row on disk.
		let two_pow_63 = i64::MAX as f64; // == 2^63 due to f64 rounding
		let bytes = encode_vec(&RecordIdKey::Number(Number::Float(two_pow_63))).unwrap();
		let int_max_bytes = encode_vec(&RecordIdKey::Number(Number::Int(i64::MAX))).unwrap();
		// Both go under disc 10 now, so the discriminant is the same.
		assert_eq!(bytes[0], DISC_NUMBER_LEX);
		assert_eq!(int_max_bytes[0], DISC_NUMBER_LEX);
		// But the lex payload + variant marker differ — they must NOT alias.
		assert_ne!(
			bytes, int_max_bytes,
			"Float(2^63) must NOT collapse to the same on-disk bytes as Int(i64::MAX)"
		);
	}

	#[test]
	fn encode_float_one_half_stays_float() {
		let bytes = encode_vec(&RecordIdKey::Number(Number::Float(1.5))).unwrap();
		assert_eq!(bytes[0], DISC_NUMBER_LEX);
		// Last byte is the NumberKind marker — Float.
		assert_eq!(*bytes.last().unwrap(), KIND_FLOAT_BYTE);
	}

	#[test]
	fn encode_decimal_one_point_seven_dec_stays_decimal() {
		// 1.7 is not exactly representable as f64, so the canonical form is Decimal.
		let d = Decimal::from_str_normalized("1.7").unwrap();
		let bytes = encode_vec(&RecordIdKey::Number(Number::Decimal(d))).unwrap();
		assert_eq!(bytes[0], DISC_NUMBER_LEX);
		// Last byte is the NumberKind marker — Decimal.
		assert_eq!(*bytes.last().unwrap(), KIND_DECIMAL_BYTE);
	}

	#[test]
	fn encode_decimal_one_point_five_canonicalizes_to_float() {
		// 1.5 IS exactly representable as f64, so Decimal(1.5dec) canonicalizes to Float.
		let d = Decimal::from_str_normalized("1.5").unwrap();
		let dec_bytes = encode_vec(&RecordIdKey::Number(Number::Decimal(d))).unwrap();
		let float_bytes = encode_vec(&RecordIdKey::Number(Number::Float(1.5))).unwrap();
		assert_eq!(dec_bytes, float_bytes);
	}

	// ------------------------------------------------------------------
	// Byte order in FullNew mode matches `Number::cmp` numeric order
	// across canonical Int / Float / Decimal variants — this is the
	// core property fixed by the disc-10 unification.
	// ------------------------------------------------------------------

	#[test]
	fn byte_order_matches_numeric_order_in_full_new_mode() {
		use rust_decimal::prelude::FromStr;
		// Mixed canonical variants spanning numeric values; sorted ascending
		// by `Number::cmp`.
		let inputs = [
			RecordIdKey::Number(Number::Int(-3)),
			RecordIdKey::Number(Number::Decimal(Decimal::from_str("-0.5").unwrap())),
			RecordIdKey::Number(Number::Int(0)),
			RecordIdKey::Number(Number::Float(0.5)),
			RecordIdKey::Number(Number::Int(1)),
			RecordIdKey::Number(Number::Float(1.5)),
			RecordIdKey::Number(Number::Int(2)),
			RecordIdKey::Number(Number::Int(3)),
			RecordIdKey::Number(Number::Decimal(Decimal::from_str("3.1").unwrap())),
			RecordIdKey::Number(Number::Int(4)),
		];

		let encoded: Vec<Vec<u8>> = inputs.iter().map(|k| encode_vec(k).unwrap()).collect();
		for w in encoded.windows(2) {
			assert!(w[0] < w[1], "byte order must match numeric order: {:?} < {:?}", w[0], w[1]);
		}
	}

	// ------------------------------------------------------------------
	// Backward-compat decode: hand-crafted legacy byte vectors for disc
	// 2, 8, 9 must still decode to the correct `Number` variant. The
	// migration tool relies on these arms to read every shipped layout.
	// ------------------------------------------------------------------

	#[test]
	fn legacy_decode_disc_2_int() {
		// Hand-crafted 3.0.x layout: disc 2 + storekey i64 encoding of 42.
		// write_i64(42) = ((42 ^ i64::MIN).to_be_bytes()) = 0x80 ... 0x2A.
		let bytes = vec![DISC_NUMBER_INT, 0x80, 0, 0, 0, 0, 0, 0, 0x2A];
		let decoded: RecordIdKey = decode_borrow(&bytes).unwrap();
		assert_eq!(decoded, RecordIdKey::Number(Number::Int(42)));
	}

	#[test]
	fn legacy_decode_disc_8_float() {
		// Hand-crafted main-branch layout: disc 8 + storekey f64 encoding of
		// 1.5.
		let mut bytes = vec![DISC_NUMBER_FLOAT];
		let mut writer = storekey::Writer::new(&mut bytes);
		storekey::Writer::write_f64(&mut writer, 1.5).unwrap();
		let decoded: RecordIdKey = decode_borrow(&bytes).unwrap();
		assert_eq!(decoded, RecordIdKey::Number(Number::Float(1.5)));
	}

	#[test]
	fn legacy_decode_disc_9_decimal() {
		// Hand-crafted main-branch layout: disc 9 + 16 raw Decimal::serialize() bytes.
		let d = Decimal::from_str_normalized("1.7").unwrap();
		let mut bytes = vec![DISC_NUMBER_DECIMAL];
		bytes.extend_from_slice(&d.serialize());
		let decoded: RecordIdKey = decode_borrow(&bytes).unwrap();
		assert_eq!(decoded, RecordIdKey::Number(Number::Decimal(d)));
	}

	#[test]
	fn encode_nan_fails() {
		let key = RecordIdKey::Number(Number::Float(f64::NAN));
		assert!(encode_vec(&key).is_err());
	}

	#[test]
	fn encode_infinity_fails() {
		let key = RecordIdKey::Number(Number::Float(f64::INFINITY));
		assert!(encode_vec(&key).is_err());
		let key = RecordIdKey::Number(Number::Float(f64::NEG_INFINITY));
		assert!(encode_vec(&key).is_err());
	}

	// ------------------------------------------------------------------
	// Round-trip: encode then decode reproduces the input (for canonical
	// inputs that survive canonicalization).
	// ------------------------------------------------------------------

	#[test]
	fn round_trip_int() {
		for &i in &[0i64, 1, -1, 42, -42, i64::MIN, i64::MAX] {
			let key = RecordIdKey::Number(Number::Int(i));
			let bytes = encode_vec(&key).unwrap();
			let decoded: RecordIdKey = decode_borrow(&bytes).unwrap();
			assert_eq!(decoded, key, "round-trip failed for Int({i})");
		}
	}

	#[test]
	fn round_trip_float() {
		for &f in &[1.5_f64, -2.25, 0.1 + 0.2, std::f64::consts::PI] {
			let key = RecordIdKey::Number(Number::Float(f));
			let bytes = encode_vec(&key).unwrap();
			let decoded: RecordIdKey = decode_borrow(&bytes).unwrap();
			let RecordIdKey::Number(Number::Float(g)) = decoded else {
				panic!("expected Float, got {:?}", decoded);
			};
			assert_eq!(f.to_bits(), g.to_bits(), "round-trip failed for Float({f})");
		}
	}

	#[test]
	fn round_trip_decimal() {
		let d = Decimal::from_str_normalized("1.7").unwrap();
		let key = RecordIdKey::Number(Number::Decimal(d));
		let bytes = encode_vec(&key).unwrap();
		let decoded: RecordIdKey = decode_borrow(&bytes).unwrap();
		assert_eq!(decoded, key);
	}

	// ------------------------------------------------------------------
	// Cross-variant equality: `Int(1) == Float(1.0) == Decimal(1.0dec)`
	// at the Rust level via `Number`'s manual impls.
	// ------------------------------------------------------------------

	#[test]
	fn cross_variant_eq() {
		let a = RecordIdKey::Number(Number::Int(1));
		let b = RecordIdKey::Number(Number::Float(1.0));
		let c = RecordIdKey::Number(Number::Decimal(Decimal::from_i64(1).unwrap()));
		assert_eq!(a, b);
		assert_eq!(b, c);
		assert_eq!(a, c);
	}

	#[test]
	fn cross_variant_hash_match() {
		use std::collections::HashSet;
		let mut set: HashSet<RecordIdKey> = HashSet::new();
		set.insert(RecordIdKey::Number(Number::Int(1)));
		// Float(1.0) should already be in the set (cross-variant Hash from Number).
		assert!(set.contains(&RecordIdKey::Number(Number::Float(1.0))));
		assert!(set.contains(&RecordIdKey::Number(Number::Decimal(Decimal::from_i64(1).unwrap()))));
	}

	// ------------------------------------------------------------------
	// Legacy compatibility: rev-1 macro-derived storekey bytes for a
	// `Number(i64)` decode to the same value with the new layout.
	// ------------------------------------------------------------------

	#[test]
	fn legacy_int_bytes_decode_unchanged() {
		// Bytes that a pre-change `Number(i64)` would have produced.
		let legacy_bytes = vec![2u8, 0x80, 0, 0, 0, 0, 0, 0, 0x2A];
		let decoded: RecordIdKey = decode_borrow(&legacy_bytes).unwrap();
		assert_eq!(decoded, RecordIdKey::Number(Number::Int(42)));
	}

	// ------------------------------------------------------------------
	// from_number factory rejects NaN/Inf.
	// ------------------------------------------------------------------

	#[test]
	fn from_number_rejects_nan_inf() {
		assert!(RecordIdKey::from_number(Number::Float(f64::NAN)).is_none());
		assert!(RecordIdKey::from_number(Number::Float(f64::INFINITY)).is_none());
		assert!(RecordIdKey::from_number(Number::Float(f64::NEG_INFINITY)).is_none());

		// Finite floats / ints / decimals are accepted.
		assert!(RecordIdKey::from_number(Number::Int(42)).is_some());
		assert!(RecordIdKey::from_number(Number::Float(1.5)).is_some());
		assert!(RecordIdKey::from_number(Number::Decimal(Decimal::from(1))).is_some());
	}

	// ------------------------------------------------------------------
	// Rev-1 → rev-2 revisioned migration: a legacy revisioned-encoded
	// `RecordIdKey::Number(i64)` decodes correctly with the new manual
	// `Revisioned` impl.
	// ------------------------------------------------------------------

	#[test]
	fn revisioned_rev1_int_migration() {
		use revision::DeserializeRevisioned;
		// Rev-1 wire format for `Number(42i64)`:
		//   u16 rev = 1 → variable-length encode = [0x01]
		//   u32 variant = 0 (Number) → [0x00]
		//   i64 payload = 42 → zigzag(42)=84 → [0x54]
		let legacy_bytes = vec![0x01u8, 0x00, 0x54];
		let mut reader = std::io::Cursor::new(legacy_bytes);
		let decoded = <RecordIdKey as DeserializeRevisioned>::deserialize_revisioned(&mut reader)
			.expect("rev-1 migration should succeed");
		assert_eq!(decoded, RecordIdKey::Number(Number::Int(42)));
	}

	#[test]
	fn revisioned_rev2_round_trip() {
		use revision::{DeserializeRevisioned, SerializeRevisioned};
		for key in [
			RecordIdKey::Number(Number::Int(7)),
			RecordIdKey::Number(Number::Float(1.5)),
			RecordIdKey::Number(Number::Decimal(Decimal::from_str_normalized("1.7").unwrap())),
			RecordIdKey::String("hello".into()),
		] {
			let mut buf = Vec::new();
			key.serialize_revisioned(&mut buf).unwrap();
			let mut reader = std::io::Cursor::new(&buf);
			let decoded =
				<RecordIdKey as DeserializeRevisioned>::deserialize_revisioned(&mut reader)
					.unwrap();
			assert_eq!(decoded, key);
		}
	}
}
