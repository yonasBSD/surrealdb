//! [`revision`] integration: wire format matches `BTreeMap` / `BTreeSet` (length-prefixed items).

use revision::{DeserializeRevisioned, Error, Revisioned, SerializeRevisioned};

use crate::{VecMap, VecSet};

impl<K: SerializeRevisioned + Ord, V: SerializeRevisioned> SerializeRevisioned for VecMap<K, V> {
	#[inline]
	fn serialize_revisioned<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
		let len = self.len();
		len.serialize_revisioned(writer)?;
		if len == 0 {
			return Ok(());
		}
		for (k, v) in self.iter() {
			k.serialize_revisioned(writer)?;
			v.serialize_revisioned(writer)?;
		}
		Ok(())
	}
}

impl<K: DeserializeRevisioned + Ord, V: DeserializeRevisioned> DeserializeRevisioned
	for VecMap<K, V>
{
	#[inline]
	fn deserialize_revisioned<R: std::io::Read>(reader: &mut R) -> Result<Self, Error> {
		let len = usize::deserialize_revisioned(reader)?;
		let mut items = Vec::with_capacity(len);
		for _ in 0..len {
			let k = K::deserialize_revisioned(reader)?;
			if let Some((prev_k, _)) = items.last()
				&& k <= *prev_k
			{
				return Err(Error::Deserialize(
					"VecMap revision payload: keys not strictly ascending".into(),
				));
			}
			let v = V::deserialize_revisioned(reader)?;
			items.push((k, v));
		}
		Ok(VecMap::from_sorted_vec_unchecked(items))
	}
}

impl<K: Revisioned + Ord, V: Revisioned> Revisioned for VecMap<K, V> {
	#[inline]
	fn revision() -> u16 {
		1
	}
}

impl<T: SerializeRevisioned + Ord> SerializeRevisioned for VecSet<T> {
	#[inline]
	fn serialize_revisioned<W: std::io::Write>(&self, writer: &mut W) -> Result<(), Error> {
		let len = self.len();
		len.serialize_revisioned(writer)?;
		if len == 0 {
			return Ok(());
		}
		for v in self.iter() {
			v.serialize_revisioned(writer)?;
		}
		Ok(())
	}
}

impl<T: DeserializeRevisioned + Ord> DeserializeRevisioned for VecSet<T> {
	#[inline]
	fn deserialize_revisioned<R: std::io::Read>(reader: &mut R) -> Result<Self, Error> {
		let len = usize::deserialize_revisioned(reader)?;
		let mut items = Vec::with_capacity(len);
		for _ in 0..len {
			let v = T::deserialize_revisioned(reader)?;
			if let Some(prev) = items.last()
				&& v <= *prev
			{
				return Err(Error::Deserialize(
					"VecSet revision payload: elements not strictly ascending".into(),
				));
			}
			items.push(v);
		}
		Ok(VecSet::from_sorted_vec_unchecked(items))
	}
}

impl<T: Revisioned + Eq + Ord> Revisioned for VecSet<T> {
	#[inline]
	fn revision() -> u16 {
		1
	}
}

#[cfg(test)]
mod tests {
	//! Wire-format equivalence tests with [`BTreeMap`] / [`BTreeSet`].
	//!
	//! These are the load-bearing assertions for the module-level invariant: the
	//! revisioned encoding of a [`VecMap`] / [`VecSet`] is **byte-for-byte
	//! identical** to that of a [`BTreeMap`] / [`BTreeSet`] containing the same
	//! entries. Cross-type decode tests verify the inverse direction so payloads
	//! produced by one type can be consumed by the other without re-encoding.

	use std::collections::{BTreeMap, BTreeSet};

	use revision::{DeserializeRevisioned, Error, Revisioned, SerializeRevisioned};

	use crate::{VecMap, VecSet};

	fn revision_bytes<T: SerializeRevisioned>(value: &T) -> Vec<u8> {
		let mut w = Vec::new();
		value.serialize_revisioned(&mut w).expect("serialize_revisioned");
		w
	}

	// ---- VecMap byte-equality with BTreeMap ----

	#[test]
	fn vec_map_revision_bytes_match_btree_map_empty() {
		let vm: VecMap<String, u32> = VecMap::new();
		let bt: BTreeMap<String, u32> = BTreeMap::new();
		assert_eq!(revision_bytes(&vm), revision_bytes(&bt));
	}

	#[test]
	fn vec_map_revision_bytes_match_btree_map_string_keys() {
		let pairs: Vec<(String, String)> = [("a", "1"), ("b", "2"), ("c", "3")]
			.into_iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect();
		let vm: VecMap<_, _> = pairs.iter().cloned().collect();
		let bt: BTreeMap<_, _> = pairs.iter().cloned().collect();
		assert_eq!(revision_bytes(&vm), revision_bytes(&bt));
	}

	#[test]
	fn vec_map_revision_bytes_match_btree_map_int_keys() {
		let pairs: Vec<(i64, String)> = vec![
			(-3, "neg".into()),
			(0, "zero".into()),
			(42, "answer".into()),
			(i64::MAX, "max".into()),
		];
		let vm: VecMap<_, _> = pairs.iter().cloned().collect();
		let bt: BTreeMap<_, _> = pairs.iter().cloned().collect();
		assert_eq!(revision_bytes(&vm), revision_bytes(&bt));
	}

	#[test]
	fn vec_map_revision_bytes_match_btree_map_single_entry() {
		let vm: VecMap<u32, u32> = [(7, 14)].into_iter().collect();
		let bt: BTreeMap<u32, u32> = [(7, 14)].into_iter().collect();
		assert_eq!(revision_bytes(&vm), revision_bytes(&bt));
	}

	/// Cross the `LINEAR_SEARCH_THRESHOLD` (64) so the binary-search path is
	/// exercised during `from_iter`; the wire format must still match
	/// `BTreeMap` byte-for-byte.
	#[test]
	fn vec_map_revision_bytes_match_btree_map_above_linear_threshold() {
		let pairs: Vec<(u32, u32)> = (0..256u32).map(|i| (i, i.wrapping_mul(7))).collect();
		let vm: VecMap<_, _> = pairs.iter().copied().collect();
		let bt: BTreeMap<_, _> = pairs.iter().copied().collect();
		assert_eq!(revision_bytes(&vm), revision_bytes(&bt));
	}

	// ---- VecMap cross-type decode ----

	#[test]
	fn vec_map_revision_bytes_decode_to_btree_map() {
		let vm: VecMap<String, u32> =
			[("a".into(), 1u32), ("b".into(), 2), ("c".into(), 3)].into_iter().collect();
		let bytes = revision_bytes(&vm);
		let bt =
			BTreeMap::<String, u32>::deserialize_revisioned(&mut bytes.as_slice()).expect("decode");
		let expected: BTreeMap<String, u32> =
			[("a".into(), 1u32), ("b".into(), 2), ("c".into(), 3)].into_iter().collect();
		assert_eq!(bt, expected);
	}

	#[test]
	fn btree_map_revision_bytes_decode_to_vec_map() {
		let bt: BTreeMap<String, u32> =
			[("a".into(), 1u32), ("b".into(), 2), ("c".into(), 3)].into_iter().collect();
		let bytes = revision_bytes(&bt);
		let vm =
			VecMap::<String, u32>::deserialize_revisioned(&mut bytes.as_slice()).expect("decode");
		let expected: VecMap<String, u32> =
			[("a".into(), 1u32), ("b".into(), 2), ("c".into(), 3)].into_iter().collect();
		assert_eq!(vm, expected);
	}

	#[test]
	fn vec_map_revision_roundtrip_preserves_entries() {
		let vm: VecMap<String, u32> =
			[("x".into(), 10u32), ("y".into(), 20), ("z".into(), 30)].into_iter().collect();
		let bytes = revision_bytes(&vm);
		let decoded =
			VecMap::<String, u32>::deserialize_revisioned(&mut bytes.as_slice()).expect("decode");
		assert_eq!(decoded, vm);
	}

	// ---- VecSet byte-equality with BTreeSet ----

	#[test]
	fn vec_set_revision_bytes_match_btree_set_empty() {
		let vs: VecSet<u32> = VecSet::new();
		let bt: BTreeSet<u32> = BTreeSet::new();
		assert_eq!(revision_bytes(&vs), revision_bytes(&bt));
	}

	#[test]
	fn vec_set_revision_bytes_match_btree_set_int() {
		let elems: &[u32] = &[1, 2, 3, 4];
		let vs: VecSet<_> = elems.iter().copied().collect();
		let bt: BTreeSet<_> = elems.iter().copied().collect();
		assert_eq!(revision_bytes(&vs), revision_bytes(&bt));
	}

	#[test]
	fn vec_set_revision_bytes_match_btree_set_string() {
		let elems: Vec<String> = ["alpha", "beta", "gamma"].into_iter().map(String::from).collect();
		let vs: VecSet<_> = elems.iter().cloned().collect();
		let bt: BTreeSet<_> = elems.iter().cloned().collect();
		assert_eq!(revision_bytes(&vs), revision_bytes(&bt));
	}

	#[test]
	fn vec_set_revision_bytes_match_btree_set_single_entry() {
		let vs: VecSet<u32> = [99u32].into_iter().collect();
		let bt: BTreeSet<u32> = [99u32].into_iter().collect();
		assert_eq!(revision_bytes(&vs), revision_bytes(&bt));
	}

	#[test]
	fn vec_set_revision_bytes_match_btree_set_above_linear_threshold() {
		let elems: Vec<u32> = (0..256u32).collect();
		let vs: VecSet<_> = elems.iter().copied().collect();
		let bt: BTreeSet<_> = elems.iter().copied().collect();
		assert_eq!(revision_bytes(&vs), revision_bytes(&bt));
	}

	// ---- VecSet cross-type decode ----

	#[test]
	fn vec_set_revision_bytes_decode_to_btree_set() {
		let vs: VecSet<u32> = [5u32, 1, 9, 3].into_iter().collect();
		let bytes = revision_bytes(&vs);
		let bt = BTreeSet::<u32>::deserialize_revisioned(&mut bytes.as_slice()).expect("decode");
		let expected: BTreeSet<u32> = [5u32, 1, 9, 3].into_iter().collect();
		assert_eq!(bt, expected);
	}

	#[test]
	fn btree_set_revision_bytes_decode_to_vec_set() {
		let bt: BTreeSet<u32> = [5u32, 1, 9, 3].into_iter().collect();
		let bytes = revision_bytes(&bt);
		let vs = VecSet::<u32>::deserialize_revisioned(&mut bytes.as_slice()).expect("decode");
		let expected: VecSet<u32> = [5u32, 1, 9, 3].into_iter().collect();
		assert_eq!(vs, expected);
	}

	#[test]
	fn vec_set_revision_roundtrip_preserves_entries() {
		let vs: VecSet<u32> = [42u32, 7, 100, 1].into_iter().collect();
		let bytes = revision_bytes(&vs);
		let decoded = VecSet::<u32>::deserialize_revisioned(&mut bytes.as_slice()).expect("decode");
		assert_eq!(decoded, vs);
	}

	#[test]
	fn vec_map_and_vec_set_revision_numbers_match_btree_counterparts() {
		assert_eq!(
			<VecMap<String, u32> as Revisioned>::revision(),
			<BTreeMap<String, u32> as Revisioned>::revision(),
		);
		assert_eq!(
			<VecSet<u32> as Revisioned>::revision(),
			<BTreeSet<u32> as Revisioned>::revision(),
		);
	}

	#[test]
	fn vec_map_revision_decode_rejects_descending_keys() {
		let mut w = Vec::new();
		2usize.serialize_revisioned(&mut w).unwrap();
		2u32.serialize_revisioned(&mut w).unwrap();
		0u32.serialize_revisioned(&mut w).unwrap();
		1u32.serialize_revisioned(&mut w).unwrap();
		0u32.serialize_revisioned(&mut w).unwrap();
		let err = VecMap::<u32, u32>::deserialize_revisioned(&mut w.as_slice()).unwrap_err();
		assert!(matches!(err, Error::Deserialize(_)));
	}

	#[test]
	fn vec_map_revision_decode_rejects_duplicate_keys() {
		let mut w = Vec::new();
		2usize.serialize_revisioned(&mut w).unwrap();
		1u32.serialize_revisioned(&mut w).unwrap();
		0u32.serialize_revisioned(&mut w).unwrap();
		1u32.serialize_revisioned(&mut w).unwrap();
		0u32.serialize_revisioned(&mut w).unwrap();
		let err = VecMap::<u32, u32>::deserialize_revisioned(&mut w.as_slice()).unwrap_err();
		assert!(matches!(err, Error::Deserialize(_)));
	}

	#[test]
	fn vec_set_revision_decode_rejects_descending_elements() {
		let mut w = Vec::new();
		2usize.serialize_revisioned(&mut w).unwrap();
		2u32.serialize_revisioned(&mut w).unwrap();
		1u32.serialize_revisioned(&mut w).unwrap();
		let err = VecSet::<u32>::deserialize_revisioned(&mut w.as_slice()).unwrap_err();
		assert!(matches!(err, Error::Deserialize(_)));
	}

	#[test]
	fn vec_set_revision_decode_rejects_duplicate_elements() {
		let mut w = Vec::new();
		2usize.serialize_revisioned(&mut w).unwrap();
		1u32.serialize_revisioned(&mut w).unwrap();
		1u32.serialize_revisioned(&mut w).unwrap();
		let err = VecSet::<u32>::deserialize_revisioned(&mut w.as_slice()).unwrap_err();
		assert!(matches!(err, Error::Deserialize(_)));
	}
}
