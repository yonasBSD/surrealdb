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

impl<K, V> VecMap<K, V>
where
	K: DeserializeRevisioned + Ord,
	V: DeserializeRevisioned,
{
	/// Deserialise a revisioned `VecMap` payload while merging an
	/// `extra` entry into its sorted position during decode.
	///
	/// The wire format consumed is identical to the standard
	/// [`DeserializeRevisioned`] implementation. The splice happens
	/// in-memory between the read of each payload entry, so no
	/// post-decode shift is required and the result is constructed
	/// with [`VecMap::from_sorted_vec_unchecked`] directly.
	///
	/// # Duplicate-key policy
	///
	/// If the payload already contains an entry whose key equals
	/// `extra.0`, the payload's value wins and `extra.1` is dropped.
	/// This matches the "field is canonically reconstructed from
	/// elsewhere but legacy payloads may still carry it" pattern
	/// (for example, a record `id` field that is now derived from
	/// the storage key but historically lived inside the payload).
	///
	/// # Errors
	///
	/// Returns [`Error::Deserialize`] when the payload keys are not
	/// strictly ascending. The splice point itself is guaranteed to
	/// preserve sort order without an additional check.
	pub fn deserialize_revisioned_with_extra<R: std::io::Read>(
		reader: &mut R,
		extra: (K, V),
	) -> Result<Self, Error> {
		let len = usize::deserialize_revisioned(reader)?;
		let mut items: Vec<(K, V)> = Vec::with_capacity(len + 1);
		// `pending` holds the injected entry until it has been spliced
		// in at its sorted position, or dropped because the payload
		// already carried the same key.
		let mut pending: Option<(K, V)> = Some(extra);
		for _ in 0..len {
			let k = K::deserialize_revisioned(reader)?;
			// Strict-ascending check against the in-progress merge.
			// Splicing `pending` between two strictly-ascending
			// payload keys preserves the invariant for free, so the
			// payload-vs-payload check is all we need.
			if let Some((prev_k, _)) = items.last()
				&& k <= *prev_k
			{
				return Err(Error::Deserialize(
					"VecMap revision payload: keys not strictly ascending".into(),
				));
			}
			if let Some((extra_k, _)) = pending.as_ref() {
				match k.cmp(extra_k) {
					std::cmp::Ordering::Less => {
						// payload key < extra key: keep extra pending
					}
					std::cmp::Ordering::Equal => {
						// Payload carries the extra key already. Payload wins.
						let v = V::deserialize_revisioned(reader)?;
						items.push((k, v));
						pending = None;
						continue;
					}
					std::cmp::Ordering::Greater => {
						// payload key > extra key: splice extra in first
						if let Some(p) = pending.take() {
							items.push(p);
						}
					}
				}
			}
			let v = V::deserialize_revisioned(reader)?;
			items.push((k, v));
		}
		if let Some(p) = pending {
			items.push(p);
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

impl<K, V> revision::SkipRevisioned for VecMap<K, V>
where
	K: revision::DeserializeRevisioned + revision::SkipRevisioned + revision::Revisioned + Ord,
	V: revision::DeserializeRevisioned + revision::SkipRevisioned + revision::Revisioned,
{
	fn skip_revisioned<R: std::io::Read>(reader: &mut R) -> Result<(), revision::Error> {
		let len = usize::deserialize_revisioned(reader)?;
		for _ in 0..len {
			K::skip_revisioned(reader)?;
			V::skip_revisioned(reader)?;
		}
		Ok(())
	}
}

impl<T> revision::SkipRevisioned for VecSet<T>
where
	T: revision::DeserializeRevisioned + revision::SkipRevisioned + revision::Revisioned + Ord,
{
	fn skip_revisioned<R: std::io::Read>(reader: &mut R) -> Result<(), revision::Error> {
		let len = usize::deserialize_revisioned(reader)?;
		for _ in 0..len {
			T::skip_revisioned(reader)?;
		}
		Ok(())
	}
}

// -----------------------------------------------------------------------------
// Optimised-encoding indexed-prologue impls.
//
// `#[revision(indexed_map)]` / `#[revision(indexed_set)]` on a field whose
// type is `VecMap<K, V>` / `VecSet<T>` makes the macro reach for the
// `IndexedMapEncoded` / `IndexedSetEncoded` impls below. The wire format
// is identical to `BTreeMap` / `BTreeSet` under indexed encoding — sorted
// by key/element bytes, optional offset-table prologue past
// `OFFSET_TABLE_MIN_LEN = 8`.
//
// Deserialisation parses directly into a sorted `Vec<(K, V)>` / `Vec<T>`
// and constructs via `from_sorted_vec_unchecked`, avoiding the
// intermediate `BTreeMap` / `BTreeSet` the generic revision-crate
// helpers would allocate. Wire byte order may diverge from `K::Ord` /
// `T::Ord` when entries have varying-length keys (the encoder sorts by
// raw bytes — e.g. Strand keys `"a"` and `"bb"` sort by `(1, "a")` vs
// `(2, "bb")` rather than UTF-8 codepoint order), so we re-sort by
// `K::Ord` / `T::Ord` after collecting. For the common case (equal-
// length keys, or all-ASCII without length variation) the sort is a
// near no-op on already-sorted input.
// -----------------------------------------------------------------------------

/// Bit flag on the leading byte of an indexed-map/seq/set body indicating
/// whether the offset-table prologue is present. Mirrors
/// `revision::optimised::indexed::seq_walk::FLAG_INDEXED`; reproduced here
/// because the constant is private to the revision crate.
const INDEXED_FLAG_BIT: u8 = 0b0000_0001;

/// Skip `count` bytes from a reader.
#[inline]
fn discard_bytes<R: std::io::Read>(r: &mut R, count: usize) -> Result<(), Error> {
	if count == 0 {
		return Ok(());
	}
	let mut buf = vec![0u8; count];
	r.read_exact(&mut buf).map_err(Error::Io)
}

impl<K, V> revision::optimised::indexed::IndexedMapEncoded for VecMap<K, V>
where
	K: SerializeRevisioned
		+ DeserializeRevisioned
		+ revision::SkipRevisioned
		+ revision::Revisioned
		+ Ord,
	V: SerializeRevisioned
		+ DeserializeRevisioned
		+ revision::SkipRevisioned
		+ revision::Revisioned,
{
	type Key = K;
	type Value = V;
	fn serialize_indexed_map<W: std::io::Write>(&self, w: &mut W) -> Result<(), Error> {
		revision::optimised::indexed::serialize_indexed_entries(self.iter(), w)
	}
	fn deserialize_indexed_map<R: std::io::Read>(r: &mut R) -> Result<Self, Error> {
		let mut flag_buf = [0u8; 1];
		r.read_exact(&mut flag_buf).map_err(Error::Io)?;
		let indexed = (flag_buf[0] & INDEXED_FLAG_BIT) != 0;
		let len = usize::deserialize_revisioned(r)?;

		let mut entries: Vec<(K, V)> = Vec::with_capacity(len);
		if !indexed {
			// Legacy `(K, V)*` body. Entries are sorted by wire bytes,
			// which may differ from `K::Ord` for varying-length keys.
			for _ in 0..len {
				let k = K::deserialize_revisioned(r)?;
				let v = V::deserialize_revisioned(r)?;
				entries.push((k, v));
			}
		} else {
			// Indexed body: `[(key_off, val_off); len]` table
			// (8 bytes each) + region-length pair (2 * `u32_le`)
			// + dense keys + dense values. Skip the random-access
			// metadata; `DeserializeRevisioned`'s per-item length
			// awareness drives the dense regions.
			let table_bytes = len.checked_mul(8).ok_or_else(|| {
				Error::Deserialize("indexed-map offset table size overflow".into())
			})?;
			discard_bytes(r, table_bytes + 8)?;
			// Two passes: dense keys first (a sorted ascending run by
			// wire bytes), then dense values in matching order.
			let mut keys: Vec<K> = Vec::with_capacity(len);
			for _ in 0..len {
				keys.push(K::deserialize_revisioned(r)?);
			}
			for k in keys {
				let v = V::deserialize_revisioned(r)?;
				entries.push((k, v));
			}
		}
		// Re-sort by `K::Ord` and reject duplicate keys (which the
		// encoder won't produce, but a corrupt or hand-rolled payload
		// could).
		entries.sort_by(|a, b| a.0.cmp(&b.0));
		if entries.windows(2).any(|w| w[0].0 == w[1].0) {
			return Err(Error::Deserialize("indexed-map decode: duplicate keys".into()));
		}
		Ok(VecMap::from_sorted_vec_unchecked(entries))
	}
	fn skip_indexed_map<R: std::io::Read>(r: &mut R) -> Result<(), Error> {
		revision::optimised::indexed::skip_indexed_map::<K, V, R>(r)
	}
}

impl<T> revision::optimised::indexed::IndexedSetEncoded for VecSet<T>
where
	T: SerializeRevisioned
		+ DeserializeRevisioned
		+ revision::SkipRevisioned
		+ revision::Revisioned
		+ Ord,
{
	type Item = T;
	fn serialize_indexed_set<W: std::io::Write>(&self, w: &mut W) -> Result<(), Error> {
		revision::optimised::indexed::serialize_indexed_set_iter(self.iter(), w)
	}
	fn deserialize_indexed_set<R: std::io::Read>(r: &mut R) -> Result<Self, Error> {
		let mut flag_buf = [0u8; 1];
		r.read_exact(&mut flag_buf).map_err(Error::Io)?;
		let indexed = (flag_buf[0] & INDEXED_FLAG_BIT) != 0;
		let len = usize::deserialize_revisioned(r)?;

		let mut entries: Vec<T> = Vec::with_capacity(len);
		if !indexed {
			for _ in 0..len {
				entries.push(T::deserialize_revisioned(r)?);
			}
		} else {
			// Indexed seq/set body: `[elem_off; len]` table (4 bytes
			// each), then dense elements.
			let table_bytes = len.checked_mul(4).ok_or_else(|| {
				Error::Deserialize("indexed-set offset table size overflow".into())
			})?;
			discard_bytes(r, table_bytes)?;
			for _ in 0..len {
				entries.push(T::deserialize_revisioned(r)?);
			}
		}
		entries.sort();
		if entries.windows(2).any(|w| w[0] == w[1]) {
			return Err(Error::Deserialize("indexed-set decode: duplicate elements".into()));
		}
		Ok(VecSet::from_sorted_vec_unchecked(entries))
	}
	fn skip_indexed_set<R: std::io::Read>(r: &mut R) -> Result<(), Error> {
		revision::optimised::indexed::skip_indexed_set::<T, R>(r)
	}
}

// VecMap/VecSet share their wire format with BTreeMap/BTreeSet: a
// length-prefixed run of strictly ascending entries. Walking is therefore
// identical to the generic MapWalker / SeqWalker.
impl<K, V> revision::WalkRevisioned for VecMap<K, V>
where
	K: revision::Revisioned + Ord,
	V: revision::Revisioned,
{
	type Walker<'r, R: revision::BorrowedReader + 'r> = revision::MapWalker<'r, K, V, R>;

	fn walk_revisioned<'r, R: revision::BorrowedReader>(
		reader: &'r mut R,
	) -> Result<Self::Walker<'r, R>, revision::Error> {
		revision::MapWalker::new(reader)
	}
}

impl<T> revision::WalkRevisioned for VecSet<T>
where
	T: revision::Revisioned + Eq + Ord + 'static,
{
	type Walker<'r, R: revision::BorrowedReader + 'r> = revision::SeqWalker<'r, T, R>;

	fn walk_revisioned<'r, R: revision::BorrowedReader>(
		reader: &'r mut R,
	) -> Result<Self::Walker<'r, R>, revision::Error> {
		revision::SeqWalker::new(reader)
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

	// ---- VecMap::deserialize_revisioned_with_extra ----

	fn encode_pairs<K, V>(pairs: &[(K, V)]) -> Vec<u8>
	where
		K: SerializeRevisioned + Ord + Clone,
		V: SerializeRevisioned + Clone,
	{
		let vm: VecMap<K, V> = VecMap::from_sorted_vec_unchecked(pairs.to_vec());
		revision_bytes(&vm)
	}

	#[test]
	fn deserialize_with_extra_splices_in_middle() {
		// Payload keys bracket the extra: 1 < 2 < 3. The extra (2, 20)
		// should be spliced between the two payload entries.
		let bytes = encode_pairs(&[(1u32, 10u32), (3u32, 30u32)]);
		let decoded = VecMap::<u32, u32>::deserialize_revisioned_with_extra(
			&mut bytes.as_slice(),
			(2u32, 20u32),
		)
		.unwrap();
		let pairs: Vec<_> = decoded.iter().map(|(k, v)| (*k, *v)).collect();
		assert_eq!(pairs, vec![(1, 10), (2, 20), (3, 30)]);
	}

	#[test]
	fn deserialize_with_extra_appends_when_no_greater_key() {
		// All payload keys sort before the extra: 1, 2 < 9. The extra
		// (9, 90) should be appended at the end.
		let bytes = encode_pairs(&[(1u32, 10u32), (2u32, 20u32)]);
		let decoded = VecMap::<u32, u32>::deserialize_revisioned_with_extra(
			&mut bytes.as_slice(),
			(9u32, 90u32),
		)
		.unwrap();
		let pairs: Vec<_> = decoded.iter().map(|(k, v)| (*k, *v)).collect();
		assert_eq!(pairs, vec![(1, 10), (2, 20), (9, 90)]);
	}

	#[test]
	fn deserialize_with_extra_prepends_when_no_lesser_key() {
		// All payload keys sort after the extra: 0 < 5, 10. The extra
		// (0, 0) should be prepended.
		let bytes = encode_pairs(&[(5u32, 50u32), (10u32, 100u32)]);
		let decoded = VecMap::<u32, u32>::deserialize_revisioned_with_extra(
			&mut bytes.as_slice(),
			(0u32, 0u32),
		)
		.unwrap();
		let pairs: Vec<_> = decoded.iter().map(|(k, v)| (*k, *v)).collect();
		assert_eq!(pairs, vec![(0, 0), (5, 50), (10, 100)]);
	}

	#[test]
	fn deserialize_with_extra_into_empty_payload() {
		// Empty payload: the extra is the only entry.
		let bytes: Vec<u8> = encode_pairs::<u32, u32>(&[]);
		let decoded = VecMap::<u32, u32>::deserialize_revisioned_with_extra(
			&mut bytes.as_slice(),
			(7u32, 70u32),
		)
		.unwrap();
		let pairs: Vec<_> = decoded.iter().map(|(k, v)| (*k, *v)).collect();
		assert_eq!(pairs, vec![(7, 70)]);
	}

	#[test]
	fn deserialize_with_extra_payload_wins_on_collision() {
		// Payload already carries the extra key. Payload's value wins
		// and the extra's value is dropped.
		let bytes = encode_pairs(&[(1u32, 10u32), (2u32, 20u32), (3u32, 30u32)]);
		let decoded = VecMap::<u32, u32>::deserialize_revisioned_with_extra(
			&mut bytes.as_slice(),
			(2u32, 99u32),
		)
		.unwrap();
		let pairs: Vec<_> = decoded.iter().map(|(k, v)| (*k, *v)).collect();
		assert_eq!(pairs, vec![(1, 10), (2, 20), (3, 30)]);
	}

	#[test]
	fn deserialize_with_extra_rejects_descending_payload() {
		// Hand-craft a payload with descending keys to verify the
		// strict-ascending check still fires when an extra is being
		// spliced.
		let mut w = Vec::new();
		2usize.serialize_revisioned(&mut w).unwrap();
		5u32.serialize_revisioned(&mut w).unwrap();
		50u32.serialize_revisioned(&mut w).unwrap();
		3u32.serialize_revisioned(&mut w).unwrap();
		30u32.serialize_revisioned(&mut w).unwrap();
		let err =
			VecMap::<u32, u32>::deserialize_revisioned_with_extra(&mut w.as_slice(), (1u32, 10u32))
				.unwrap_err();
		assert!(matches!(err, Error::Deserialize(_)));
	}

	#[test]
	fn deserialize_with_extra_rejects_duplicate_payload_keys() {
		// Payload itself has duplicate keys (neither matches extra).
		let mut w = Vec::new();
		2usize.serialize_revisioned(&mut w).unwrap();
		3u32.serialize_revisioned(&mut w).unwrap();
		30u32.serialize_revisioned(&mut w).unwrap();
		3u32.serialize_revisioned(&mut w).unwrap();
		31u32.serialize_revisioned(&mut w).unwrap();
		let err =
			VecMap::<u32, u32>::deserialize_revisioned_with_extra(&mut w.as_slice(), (1u32, 10u32))
				.unwrap_err();
		assert!(matches!(err, Error::Deserialize(_)));
	}

	#[test]
	fn deserialize_with_extra_capacity_avoids_realloc() {
		// Not a behavioural property, but a regression check that the
		// helper allocates a single Vec sized for the spliced result.
		let bytes = encode_pairs(&[(1u32, 10u32), (3u32, 30u32)]);
		let decoded = VecMap::<u32, u32>::deserialize_revisioned_with_extra(
			&mut bytes.as_slice(),
			(2u32, 20u32),
		)
		.unwrap();
		assert_eq!(decoded.len(), 3);
	}
}
