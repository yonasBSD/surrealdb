use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use rand::seq::IndexedRandom;
use serde::{Deserialize, Deserializer, Serialize};

use crate as surrealdb_types;
use crate::sql::{SqlFormat, ToSql};
use crate::{Array, Number, Object, RecordIdKeyRange, SurrealValue, Uuid, Value, kind};

/// The characters which are supported in server record IDs
pub const ID_CHARS: [char; 36] = [
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

/// Represents a key component of a record identifier in SurrealDB
///
/// Record identifiers can have various types of keys including numbers, strings, UUIDs,
/// arrays, objects, or ranges. This enum provides type-safe representation for all key types.
///
/// `Number(i64)` preserves the historical shape of integer record IDs — old
/// pattern matches like `match k { RecordIdKey::Number(i) => ... }` and the
/// existing serde wire format (`{"Number": 42}` for integers) keep working
/// unchanged. Non-integer numeric IDs use the new [`RecordIdKey::Float`] and
/// [`RecordIdKey::Decimal`] variants.
///
/// The enum is `#[non_exhaustive]` so adding further variants in the future
/// is non-breaking; downstream consumers matching on `RecordIdKey` must
/// include a wildcard arm.
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub enum RecordIdKey {
	/// A 64-bit integer key.
	Number(i64),
	/// A string key.
	String(String),
	/// A UUID key.
	Uuid(Uuid),
	/// An array key.
	Array(Array),
	/// An object key.
	Object(Object),
	/// A range key.
	Range(Box<RecordIdKeyRange>),
	/// A 64-bit float key (added in 3.1.0-beta). NaN and ±∞ are not valid.
	Float(f64),
	/// An arbitrary-precision decimal key (added in 3.1.0-beta).
	Decimal(rust_decimal::Decimal),
}

// Manual `Eq`/`Hash`/`Ord` impls — `f64` doesn't derive any of them. NaN is
// rejected at construction so total ordering / bit-equality are sound.

impl PartialEq for RecordIdKey {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::Number(a), Self::Number(b)) => a == b,
			(Self::Float(a), Self::Float(b)) => a.to_bits() == b.to_bits(),
			(Self::Decimal(a), Self::Decimal(b)) => a == b,
			(Self::String(a), Self::String(b)) => a == b,
			(Self::Uuid(a), Self::Uuid(b)) => a == b,
			(Self::Array(a), Self::Array(b)) => a == b,
			(Self::Object(a), Self::Object(b)) => a == b,
			(Self::Range(a), Self::Range(b)) => a == b,
			_ => false,
		}
	}
}

impl Eq for RecordIdKey {}

impl Hash for RecordIdKey {
	fn hash<H: Hasher>(&self, state: &mut H) {
		std::mem::discriminant(self).hash(state);
		match self {
			Self::Number(v) => v.hash(state),
			Self::Float(v) => v.to_bits().hash(state),
			Self::Decimal(v) => v.hash(state),
			Self::String(v) => v.hash(state),
			Self::Uuid(v) => v.hash(state),
			Self::Array(v) => v.hash(state),
			Self::Object(v) => v.hash(state),
			Self::Range(v) => v.hash(state),
		}
	}
}

impl Ord for RecordIdKey {
	fn cmp(&self, other: &Self) -> Ordering {
		fn rank(k: &RecordIdKey) -> u8 {
			match k {
				RecordIdKey::Number(_) => 0,
				RecordIdKey::String(_) => 1,
				RecordIdKey::Uuid(_) => 2,
				RecordIdKey::Array(_) => 3,
				RecordIdKey::Object(_) => 4,
				RecordIdKey::Range(_) => 5,
				RecordIdKey::Float(_) => 6,
				RecordIdKey::Decimal(_) => 7,
			}
		}
		match (self, other) {
			(Self::Number(a), Self::Number(b)) => a.cmp(b),
			(Self::Float(a), Self::Float(b)) => a.total_cmp(b),
			(Self::Decimal(a), Self::Decimal(b)) => a.cmp(b),
			(Self::String(a), Self::String(b)) => a.cmp(b),
			(Self::Uuid(a), Self::Uuid(b)) => a.cmp(b),
			(Self::Array(a), Self::Array(b)) => a.cmp(b),
			(Self::Object(a), Self::Object(b)) => a.cmp(b),
			(Self::Range(a), Self::Range(b)) => a.cmp(b),
			_ => rank(self).cmp(&rank(other)),
		}
	}
}

impl PartialOrd for RecordIdKey {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

// Manual `Deserialize` impl that rejects non-finite `Float` payloads at the
// serde boundary. Closes the matching gap for any serde format (JSON, bincode,
// MessagePack, …) — the CBOR rpc path already validates `is_finite()` above
// serde at `rpc/format/cbor/convert.rs:to_record_id_key`. Without this guard,
// `{"Float": NaN}` would deserialize into a `Number::Float(NaN)` that the
// `Eq`/`Hash`/`Ord` impls above assume cannot exist.
impl<'de> Deserialize<'de> for RecordIdKey {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		// Shadow enum mirroring `RecordIdKey` exactly — when adding a new
		// variant, mirror it here too.
		#[derive(Deserialize)]
		enum Repr {
			Number(i64),
			String(String),
			Uuid(Uuid),
			Array(Array),
			Object(Object),
			Range(Box<RecordIdKeyRange>),
			Float(f64),
			Decimal(rust_decimal::Decimal),
		}
		match Repr::deserialize(deserializer)? {
			Repr::Number(n) => Ok(RecordIdKey::Number(n)),
			Repr::String(s) => Ok(RecordIdKey::String(s)),
			Repr::Uuid(u) => Ok(RecordIdKey::Uuid(u)),
			Repr::Array(a) => Ok(RecordIdKey::Array(a)),
			Repr::Object(o) => Ok(RecordIdKey::Object(o)),
			Repr::Range(r) => Ok(RecordIdKey::Range(r)),
			Repr::Float(f) if f.is_finite() => Ok(RecordIdKey::Float(f)),
			Repr::Float(_) => {
				Err(serde::de::Error::custom("NaN and ±Infinity are not valid record-id keys"))
			}
			Repr::Decimal(d) => Ok(RecordIdKey::Decimal(d)),
		}
	}
}

impl RecordIdKey {
	/// Generate a new random ID
	pub fn rand() -> Self {
		let mut rng = rand::rng();
		let id: String = (0..20).map(|_| *ID_CHARS[..].choose(&mut rng).unwrap_or(&'0')).collect();
		Self::String(id)
	}
	/// Generate a new random ULID
	pub fn ulid() -> Self {
		Self::String(ulid::Ulid::new().to_string())
	}
	/// Generate a new random UUID
	pub fn uuid() -> Self {
		Self::Uuid(Uuid::new_v7())
	}

	/// Returns if this key is a range.
	pub fn is_range(&self) -> bool {
		matches!(self, RecordIdKey::Range(_))
	}

	/// Build a record-id key from a [`Number`], dispatching to the matching
	/// variant. Returns `None` for NaN / ±∞.
	pub fn from_number(n: Number) -> Option<Self> {
		match n {
			Number::Int(i) => Some(RecordIdKey::Number(i)),
			Number::Float(f) if !f.is_finite() => None,
			Number::Float(f) => Some(RecordIdKey::Float(f)),
			Number::Decimal(d) => Some(RecordIdKey::Decimal(d)),
		}
	}

	/// Build a record-id key from an `f64`. Returns `None` for NaN / ±∞.
	pub fn try_from_float(f: f64) -> Option<Self> {
		Self::from_number(Number::Float(f))
	}
}

impl From<i64> for RecordIdKey {
	fn from(value: i64) -> Self {
		RecordIdKey::Number(value)
	}
}

impl From<rust_decimal::Decimal> for RecordIdKey {
	fn from(value: rust_decimal::Decimal) -> Self {
		RecordIdKey::Decimal(value)
	}
}

impl From<String> for RecordIdKey {
	fn from(value: String) -> Self {
		RecordIdKey::String(value)
	}
}

impl From<&str> for RecordIdKey {
	fn from(value: &str) -> Self {
		RecordIdKey::String(value.to_string())
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

impl From<RecordIdKeyRange> for RecordIdKey {
	fn from(value: RecordIdKeyRange) -> Self {
		RecordIdKey::Range(Box::new(value))
	}
}

impl From<Box<RecordIdKeyRange>> for RecordIdKey {
	fn from(value: Box<RecordIdKeyRange>) -> Self {
		RecordIdKey::Range(value)
	}
}

impl PartialEq<Value> for RecordIdKey {
	fn eq(&self, other: &Value) -> bool {
		match self {
			RecordIdKey::Number(a) => Value::Number(Number::Int(*a)) == *other,
			RecordIdKey::Float(a) => Value::Number(Number::Float(*a)) == *other,
			RecordIdKey::Decimal(a) => Value::Number(Number::Decimal(*a)) == *other,
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
	fn fmt_sql(&self, f: &mut String, fmt: SqlFormat) {
		use crate::utils::escape::EscapeRecordKey;

		match self {
			RecordIdKey::Number(n) => n.fmt_sql(f, fmt),
			RecordIdKey::Float(v) => Number::Float(*v).fmt_sql(f, fmt),
			RecordIdKey::Decimal(v) => Number::Decimal(*v).fmt_sql(f, fmt),
			RecordIdKey::String(v) => EscapeRecordKey(v).fmt_sql(f, fmt),
			RecordIdKey::Uuid(uuid) => uuid.fmt_sql(f, fmt),
			RecordIdKey::Object(object) => object.fmt_sql(f, fmt),
			RecordIdKey::Array(array) => array.fmt_sql(f, fmt),
			RecordIdKey::Range(rid) => rid.fmt_sql(f, fmt),
		}
	}
}

impl SurrealValue for RecordIdKey {
	fn kind_of() -> crate::Kind {
		// RecordIdKey can be multiple kinds
		kind!(number | string | uuid | array | object | range)
	}

	fn is_value(value: &Value) -> bool {
		match value {
			Value::Number(Number::Float(f)) => f.is_finite(),
			Value::Number(_)
			| Value::String(_)
			| Value::Uuid(_)
			| Value::Array(_)
			| Value::Object(_)
			| Value::Range(_) => true,
			_ => false,
		}
	}

	fn into_value(self) -> Value {
		match self {
			RecordIdKey::Number(n) => Value::Number(Number::Int(n)),
			RecordIdKey::Float(f) => Value::Number(Number::Float(f)),
			RecordIdKey::Decimal(d) => Value::Number(Number::Decimal(d)),
			RecordIdKey::String(s) => Value::String(s),
			RecordIdKey::Uuid(u) => Value::Uuid(u),
			RecordIdKey::Array(a) => Value::Array(a),
			RecordIdKey::Object(o) => Value::Object(o),
			RecordIdKey::Range(r) => (*r).into_value(),
		}
	}

	fn from_value(value: Value) -> Result<Self, crate::Error> {
		match value {
			Value::Number(n) => RecordIdKey::from_number(n).ok_or_else(|| {
				crate::Error::internal(format!("Cannot convert {:?} to RecordIdKey", n))
			}),
			Value::String(s) => Ok(RecordIdKey::String(s)),
			Value::Uuid(u) => Ok(RecordIdKey::Uuid(u)),
			Value::Array(a) => Ok(RecordIdKey::Array(a)),
			Value::Object(o) => Ok(RecordIdKey::Object(o)),
			Value::Range(_) => {
				let range = RecordIdKeyRange::from_value(value)?;
				Ok(RecordIdKey::Range(Box::new(range)))
			}
			_ => Err(crate::Error::internal(format!("Cannot convert {:?} to RecordIdKey", value))),
		}
	}
}

#[cfg(test)]
mod tests {
	use serde::Deserialize;
	use serde::de::value::{Error, F64Deserializer, StrDeserializer};
	use serde::de::{DeserializeSeed, Deserializer, EnumAccess, VariantAccess, Visitor};

	use super::RecordIdKey;

	// JSON has no NaN, so we test the manual `Deserialize` impl with a tiny
	// hand-rolled `Deserializer` that emits the externally-tagged enum
	// payload `Float(<f64>)` for an arbitrary f64. This stands in for any
	// real serde format (CBOR, bincode, MessagePack, …) that *can* carry a
	// non-finite float.
	struct FloatVariantDeserializer(f64);

	impl<'de> Deserializer<'de> for FloatVariantDeserializer {
		type Error = Error;

		fn deserialize_enum<V: Visitor<'de>>(
			self,
			_name: &'static str,
			_variants: &'static [&'static str],
			visitor: V,
		) -> Result<V::Value, Self::Error> {
			visitor.visit_enum(FloatVariantAccess(self.0))
		}

		serde::forward_to_deserialize_any! {
			bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
			bytes byte_buf option unit unit_struct newtype_struct seq tuple
			tuple_struct map struct identifier ignored_any
		}

		fn deserialize_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value, Self::Error> {
			Err(serde::de::Error::custom("expected enum"))
		}
	}

	struct FloatVariantAccess(f64);

	impl<'de> EnumAccess<'de> for FloatVariantAccess {
		type Error = Error;
		type Variant = FloatNewtypeAccess;

		fn variant_seed<V: DeserializeSeed<'de>>(
			self,
			seed: V,
		) -> Result<(V::Value, Self::Variant), Self::Error> {
			let v = seed.deserialize(StrDeserializer::<Error>::new("Float"))?;
			Ok((v, FloatNewtypeAccess(self.0)))
		}
	}

	struct FloatNewtypeAccess(f64);

	impl<'de> VariantAccess<'de> for FloatNewtypeAccess {
		type Error = Error;

		fn unit_variant(self) -> Result<(), Self::Error> {
			Err(serde::de::Error::custom("expected newtype variant"))
		}

		fn newtype_variant_seed<T: DeserializeSeed<'de>>(
			self,
			seed: T,
		) -> Result<T::Value, Self::Error> {
			seed.deserialize(F64Deserializer::<Error>::new(self.0))
		}

		fn tuple_variant<V: Visitor<'de>>(
			self,
			_len: usize,
			_visitor: V,
		) -> Result<V::Value, Self::Error> {
			Err(serde::de::Error::custom("expected newtype variant"))
		}

		fn struct_variant<V: Visitor<'de>>(
			self,
			_fields: &'static [&'static str],
			_visitor: V,
		) -> Result<V::Value, Self::Error> {
			Err(serde::de::Error::custom("expected newtype variant"))
		}
	}

	#[test]
	fn deserialize_finite_float_succeeds() {
		let key = RecordIdKey::deserialize(FloatVariantDeserializer(1.5)).unwrap();
		assert_eq!(key, RecordIdKey::Float(1.5));
	}

	#[test]
	fn deserialize_nan_float_is_rejected() {
		let err = RecordIdKey::deserialize(FloatVariantDeserializer(f64::NAN)).unwrap_err();
		assert!(
			err.to_string().contains("NaN and ±Infinity are not valid record-id keys"),
			"unexpected error: {err}",
		);
	}

	#[test]
	fn deserialize_positive_infinity_float_is_rejected() {
		let err = RecordIdKey::deserialize(FloatVariantDeserializer(f64::INFINITY)).unwrap_err();
		assert!(
			err.to_string().contains("NaN and ±Infinity are not valid record-id keys"),
			"unexpected error: {err}",
		);
	}

	#[test]
	fn deserialize_negative_infinity_float_is_rejected() {
		let err =
			RecordIdKey::deserialize(FloatVariantDeserializer(f64::NEG_INFINITY)).unwrap_err();
		assert!(
			err.to_string().contains("NaN and ±Infinity are not valid record-id keys"),
			"unexpected error: {err}",
		);
	}

	#[test]
	fn deserialize_integer_number_succeeds() {
		// Sanity check the un-modified Number variant via JSON (JSON can
		// carry integers fine, just not NaN).
		let key: RecordIdKey = serde_json::from_str(r#"{"Number": 42}"#).unwrap();
		assert_eq!(key, RecordIdKey::Number(42));
	}
}
