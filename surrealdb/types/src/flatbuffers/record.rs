use std::ops::Bound;
use std::str::FromStr;

use surrealdb_protocol::fb::v1::{self as proto_fb, RecordIdKeyBound};

use super::{FromFlatbuffers, ToFlatbuffers};
use crate::{RecordId, RecordIdKey, RecordIdKeyRange, Table};

impl ToFlatbuffers for RecordId {
	type Output<'bldr> = flatbuffers::WIPOffset<proto_fb::RecordId<'bldr>>;

	#[inline]
	fn to_fb<'bldr>(
		&self,
		builder: &mut flatbuffers::FlatBufferBuilder<'bldr>,
	) -> anyhow::Result<Self::Output<'bldr>> {
		let table = builder.create_string(&self.table);
		let id = self.key.to_fb(builder)?;
		Ok(proto_fb::RecordId::create(
			builder,
			&proto_fb::RecordIdArgs {
				table: Some(table),
				id: Some(id),
			},
		))
	}
}

impl FromFlatbuffers for RecordId {
	type Input<'a> = proto_fb::RecordId<'a>;

	#[inline]
	fn from_fb(input: Self::Input<'_>) -> anyhow::Result<Self> {
		let table = input.table().ok_or_else(|| anyhow::anyhow!("Missing table in RecordId"))?;
		let key = RecordIdKey::from_fb(
			input.id().ok_or_else(|| anyhow::anyhow!("Missing id in RecordId"))?,
		)?;
		Ok(RecordId {
			table: Table::new(table.to_string()),
			key,
		})
	}
}

impl ToFlatbuffers for RecordIdKey {
	type Output<'bldr> = flatbuffers::WIPOffset<proto_fb::RecordIdKey<'bldr>>;

	#[inline]
	fn to_fb<'bldr>(
		&self,
		builder: &mut flatbuffers::FlatBufferBuilder<'bldr>,
	) -> anyhow::Result<Self::Output<'bldr>> {
		match self {
			RecordIdKey::Number(n) => {
				let id = n.to_fb(builder)?.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Int64,
						id: Some(id),
					},
				))
			}
			RecordIdKey::Float(f) => {
				// Defense-in-depth: the same `is_finite()` guard is enforced
				// by `RecordIdKey::from_number`, the SurrealQL parser, the
				// storekey encoder, the CBOR encoder, and the serde
				// `Deserialize` impl on `PublicRecordIdKey`. A non-finite
				// float should not be constructible here in practice, but
				// the encoder mirrors the matching decoder guard below so
				// any future regression surfaces as a clear error rather
				// than a wire payload the receiver will reject.
				if !f.is_finite() {
					anyhow::bail!("NaN and ±Infinity are not valid record-id keys");
				}
				let id = proto_fb::Float64Value::create(
					builder,
					&proto_fb::Float64ValueArgs {
						value: *f,
					},
				)
				.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Float64,
						id: Some(id),
					},
				))
			}
			RecordIdKey::Decimal(d) => {
				let value = builder.create_string(&d.to_string());
				let id = proto_fb::Decimal::create(
					builder,
					&proto_fb::DecimalArgs {
						value: Some(value),
					},
				)
				.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Decimal,
						id: Some(id),
					},
				))
			}
			RecordIdKey::String(s) => {
				let id = s.to_fb(builder)?.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::String,
						id: Some(id),
					},
				))
			}
			RecordIdKey::Uuid(uuid) => {
				let id = uuid.to_fb(builder)?.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Uuid,
						id: Some(id),
					},
				))
			}
			RecordIdKey::Array(arr) => {
				let id = arr.to_fb(builder)?.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Array,
						id: Some(id),
					},
				))
			}
			RecordIdKey::Range(range) => {
				let id = range.to_fb(builder)?.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Range,
						id: Some(id),
					},
				))
			}
			RecordIdKey::Object(object) => {
				let id = object.to_fb(builder)?.as_union_value();
				Ok(proto_fb::RecordIdKey::create(
					builder,
					&proto_fb::RecordIdKeyArgs {
						id_type: proto_fb::RecordIdKeyType::Object,
						id: Some(id),
					},
				))
			}
		}
	}
}

impl FromFlatbuffers for RecordIdKey {
	type Input<'a> = proto_fb::RecordIdKey<'a>;

	#[inline]
	fn from_fb(input: Self::Input<'_>) -> anyhow::Result<Self> {
		match input.id_type() {
			proto_fb::RecordIdKeyType::Int64 => {
				let key_value =
					input.id_as_int_64().ok_or_else(|| anyhow::anyhow!("Expected Int64 Id"))?;
				Ok(RecordIdKey::Number(key_value.value()))
			}
			proto_fb::RecordIdKeyType::String => {
				let key_value =
					input.id_as_string().ok_or_else(|| anyhow::anyhow!("Expected String Id"))?;
				Ok(RecordIdKey::String(
					key_value
						.value()
						.ok_or_else(|| anyhow::anyhow!("Missing String value"))?
						.to_string(),
				))
			}
			proto_fb::RecordIdKeyType::Uuid => {
				let key_value =
					input.id_as_uuid().ok_or_else(|| anyhow::anyhow!("Expected Uuid Id"))?;
				let uuid = crate::Uuid::from_fb(key_value)?;
				Ok(RecordIdKey::Uuid(uuid))
			}
			proto_fb::RecordIdKeyType::Array => {
				let key_value =
					input.id_as_array().ok_or_else(|| anyhow::anyhow!("Expected Array Id"))?;
				let array = crate::Array::from_fb(key_value)?;
				Ok(RecordIdKey::Array(array))
			}
			proto_fb::RecordIdKeyType::Range => {
				let key_value =
					input.id_as_range().ok_or_else(|| anyhow::anyhow!("Expected Range Id"))?;
				let range = RecordIdKeyRange::from_fb(key_value)?;
				Ok(RecordIdKey::Range(Box::new(range)))
			}
			proto_fb::RecordIdKeyType::Object => {
				let key_value =
					input.id_as_object().ok_or_else(|| anyhow::anyhow!("Expected Object Id"))?;
				let object = crate::Object::from_fb(key_value)?;
				Ok(RecordIdKey::Object(object))
			}
			proto_fb::RecordIdKeyType::Float64 => {
				let key_value =
					input.id_as_float_64().ok_or_else(|| anyhow::anyhow!("Expected Float64 Id"))?;
				let value = key_value.value();
				// Mirror the guard at the encoder: reject NaN / ±∞ at the wire
				// boundary so a malformed payload from an upstream regression
				// can't smuggle a non-finite float into a record-id key.
				if !value.is_finite() {
					return Err(anyhow::anyhow!("NaN and ±Infinity are not valid record-id keys"));
				}
				Ok(RecordIdKey::Float(value))
			}
			proto_fb::RecordIdKeyType::Decimal => {
				let key_value =
					input.id_as_decimal().ok_or_else(|| anyhow::anyhow!("Expected Decimal Id"))?;
				let value =
					key_value.value().ok_or_else(|| anyhow::anyhow!("Missing Decimal value"))?;
				let decimal = rust_decimal::Decimal::from_str(value)
					.map_err(|e| anyhow::anyhow!("Failed to parse Decimal record-id key: {e}"))?;
				Ok(RecordIdKey::Decimal(decimal))
			}
			_ => Err(anyhow::anyhow!(
				"Unsupported RecordIdKey type for FlatBuffers deserialization: {:?}",
				input.id_type()
			)),
		}
	}
}

impl ToFlatbuffers for RecordIdKeyRange {
	type Output<'bldr> = flatbuffers::WIPOffset<proto_fb::RecordIdKeyRange<'bldr>>;

	#[inline]
	fn to_fb<'bldr>(
		&self,
		builder: &mut flatbuffers::FlatBufferBuilder<'bldr>,
	) -> anyhow::Result<Self::Output<'bldr>> {
		let (start_type, start) = self.start.to_fb(builder)?;
		let (end_type, end) = self.end.to_fb(builder)?;
		Ok(proto_fb::RecordIdKeyRange::create(
			builder,
			&proto_fb::RecordIdKeyRangeArgs {
				start_type,
				start,
				end_type,
				end,
			},
		))
	}
}

impl FromFlatbuffers for RecordIdKeyRange {
	type Input<'bldr> = proto_fb::RecordIdKeyRange<'bldr>;

	#[inline]
	fn from_fb(input: Self::Input<'_>) -> anyhow::Result<Self> {
		let start = match input.start_type() {
			RecordIdKeyBound::Unbounded => {
				input
					.start_as_unbounded()
					.ok_or_else(|| anyhow::anyhow!("Missing start in IdRange"))?;
				Bound::Unbounded
			}
			RecordIdKeyBound::Inclusive => {
				let start = input
					.start_as_inclusive()
					.ok_or_else(|| anyhow::anyhow!("Missing start in IdRange"))?;
				Bound::Included(RecordIdKey::from_fb(start)?)
			}
			RecordIdKeyBound::Exclusive => {
				let start = input
					.start_as_exclusive()
					.ok_or_else(|| anyhow::anyhow!("Missing start in IdRange"))?;
				Bound::Excluded(RecordIdKey::from_fb(start)?)
			}
			_ => return Err(anyhow::anyhow!("Invalid start type in IdRange")),
		};

		let end = match input.end_type() {
			RecordIdKeyBound::Unbounded => {
				input
					.end_as_unbounded()
					.ok_or_else(|| anyhow::anyhow!("Missing end in IdRange"))?;
				Bound::Unbounded
			}
			RecordIdKeyBound::Inclusive => {
				let end = input
					.end_as_inclusive()
					.ok_or_else(|| anyhow::anyhow!("Missing end in IdRange"))?;
				Bound::Included(RecordIdKey::from_fb(end)?)
			}
			RecordIdKeyBound::Exclusive => {
				let end = input
					.end_as_exclusive()
					.ok_or_else(|| anyhow::anyhow!("Missing end in IdRange"))?;
				Bound::Excluded(RecordIdKey::from_fb(end)?)
			}
			_ => return Err(anyhow::anyhow!("Invalid end type in IdRange")),
		};

		Ok(RecordIdKeyRange {
			start,
			end,
		})
	}
}

impl ToFlatbuffers for Bound<RecordIdKey> {
	type Output<'bldr> =
		(proto_fb::RecordIdKeyBound, Option<flatbuffers::WIPOffset<flatbuffers::UnionWIPOffset>>);

	#[inline]
	fn to_fb<'bldr>(
		&self,
		builder: &mut flatbuffers::FlatBufferBuilder<'bldr>,
	) -> anyhow::Result<Self::Output<'bldr>> {
		Ok(match self {
			Bound::Included(id) => {
				let id_value = id.to_fb(builder)?.as_union_value();
				(proto_fb::RecordIdKeyBound::Inclusive, Some(id_value))
			}
			Bound::Excluded(id) => {
				let id_value = id.to_fb(builder)?.as_union_value();
				(proto_fb::RecordIdKeyBound::Exclusive, Some(id_value))
			}
			Bound::Unbounded => {
				let null_value = proto_fb::NullValue::create(builder, &proto_fb::NullValueArgs {});
				(proto_fb::RecordIdKeyBound::Unbounded, Some(null_value.as_union_value()))
			}
		})
	}
}

#[cfg(test)]
mod tests {
	//! Boundary tests for the Float64 / Decimal record-id-key arms added in
	//! protocol v0.10.2. The parameterised `test_encode_decode` table in
	//! `flatbuffers/mod.rs` already covers the happy round-trip; these tests
	//! exercise the explicit error paths that the round-trip table can't:
	//! - encoding a non-finite `Float` is rejected at the boundary
	//! - a payload carrying `Float64(NaN)` synthesised by a hypothetical upstream regression is
	//!   rejected at decode time
	//! - the discriminant on the wire matches what `RecordIdKey::from_fb` reads back (guards
	//!   against a silent mis-wiring of the new union slot)
	use std::str::FromStr;

	use flatbuffers::FlatBufferBuilder;
	use rust_decimal::Decimal;
	use surrealdb_protocol::fb::v1 as proto_fb;

	use super::*;

	fn round_trip(key: &RecordIdKey) -> RecordIdKey {
		let mut builder = FlatBufferBuilder::new();
		let offset = key.to_fb(&mut builder).expect("encode");
		builder.finish(offset, None);
		let buf = builder.finished_data();
		let decoded = flatbuffers::root::<proto_fb::RecordIdKey<'_>>(buf).expect("verify");
		RecordIdKey::from_fb(decoded).expect("decode")
	}

	#[test]
	fn float_record_id_round_trip_preserves_value() {
		assert_eq!(round_trip(&RecordIdKey::Float(1.5)), RecordIdKey::Float(1.5));
		assert_eq!(round_trip(&RecordIdKey::Float(-2.25)), RecordIdKey::Float(-2.25));
		assert_eq!(round_trip(&RecordIdKey::Float(f64::MIN)), RecordIdKey::Float(f64::MIN));
	}

	#[test]
	fn decimal_record_id_round_trip_preserves_precision() {
		// `0.1` is not bit-exact in f64 — the round-trip must keep it in the
		// Decimal slot rather than canonicalising through Float.
		let zero_one = Decimal::from_str("0.1").unwrap();
		assert_eq!(round_trip(&RecordIdKey::Decimal(zero_one)), RecordIdKey::Decimal(zero_one));

		let large = Decimal::from_str("123456789.987654321").unwrap();
		assert_eq!(round_trip(&RecordIdKey::Decimal(large)), RecordIdKey::Decimal(large));
	}

	#[test]
	fn encoding_non_finite_float_record_id_is_rejected() {
		let mut builder = FlatBufferBuilder::new();
		for f in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
			let err = RecordIdKey::Float(f).to_fb(&mut builder).expect_err("encode should fail");
			assert!(
				err.to_string().contains("NaN and ±Infinity are not valid record-id keys"),
				"unexpected error for {f}: {err}",
			);
		}
	}

	#[test]
	fn decoding_non_finite_float_record_id_is_rejected() {
		// Hand-craft a payload carrying `Float64(NaN)` to simulate what an
		// upstream regression that bypasses the encoder guard could put on
		// the wire. The decoder must reject it with the same message.
		let mut builder = FlatBufferBuilder::new();
		let id = proto_fb::Float64Value::create(
			&mut builder,
			&proto_fb::Float64ValueArgs {
				value: f64::NAN,
			},
		)
		.as_union_value();
		let offset = proto_fb::RecordIdKey::create(
			&mut builder,
			&proto_fb::RecordIdKeyArgs {
				id_type: proto_fb::RecordIdKeyType::Float64,
				id: Some(id),
			},
		);
		builder.finish(offset, None);
		let buf = builder.finished_data();
		let payload = flatbuffers::root::<proto_fb::RecordIdKey<'_>>(buf).expect("verify");
		let err = RecordIdKey::from_fb(payload).expect_err("decode should fail");
		assert!(
			err.to_string().contains("NaN and ±Infinity are not valid record-id keys"),
			"unexpected error: {err}",
		);
	}

	#[test]
	fn encoder_emits_expected_union_discriminants() {
		// Lock the discriminant choices so a future mis-wiring of the union
		// slot (e.g. swapping Float64 with Decimal during a refactor) fails
		// loudly here rather than as a silent on-wire format change.
		fn discriminant(key: &RecordIdKey) -> proto_fb::RecordIdKeyType {
			let mut builder = FlatBufferBuilder::new();
			let offset = key.to_fb(&mut builder).expect("encode");
			builder.finish(offset, None);
			let buf = builder.finished_data();
			let payload = flatbuffers::root::<proto_fb::RecordIdKey<'_>>(buf).expect("verify");
			payload.id_type()
		}

		assert_eq!(discriminant(&RecordIdKey::Float(1.0)), proto_fb::RecordIdKeyType::Float64);
		assert_eq!(
			discriminant(&RecordIdKey::Decimal(Decimal::from(3))),
			proto_fb::RecordIdKeyType::Decimal
		);
	}
}
