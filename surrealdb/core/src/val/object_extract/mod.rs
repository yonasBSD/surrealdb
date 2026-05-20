//! Walker-based field extraction for revision-encoded
//! [`Record`](crate::catalog::Record) bytes.
//!
//! Table rows are encoded as revisioned [`crate::catalog::Record`] values
//! whose payload is typically a [`Value::Object`] with sorted [`Strand`] keys
//! backed by [`surrealdb_collections::VecMap`]. The pre-decode filter walks
//! into nested fields without materialising the entire `Value` tree by using
//! the per-type walkers emitted by `revision`'s `#[revisioned(...)]` derive.

use revision::optimised::IndexedMapWalker;
use revision::{
	BorrowedReader, DeserializeRevisioned, Error as RevisionError, SerializeRevisioned,
	SkipRevisioned, WalkRevisioned,
};
use surrealdb_strand::Strand;

use crate::catalog::Record;
use crate::val::{Object, Value};

// Note: there is intentionally no bail on `metadata`. `metadata` flags the
// record type (plain vs. edge) and carries `aggregation_stats` for
// materialised-view rows, but in **all** cases the `data` field stores the
// user-visible value at the time of last write:
//
//   - plain table rows: `data` is the row's value;
//   - edge rows: `data` is the row's value (with `in` / `out` graph references plus user fields);
//   - materialised-view rows: `data` is populated by evaluating the view's `SELECT` expressions
//     against the aggregated internal document (see `doc::table::compute` setting `record.data =
//     data`), so it is exactly the value the engine returns to the user.
//
// The pre-decode filter therefore reads `data` for every record kind.

mod tests;

/// Missing path segment while walking to a leaf.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum WalkLeafErr {
	Missing,
	Bail,
}

/// Result of extracting a field from a revisioned record.
#[derive(Debug)]
pub(crate) enum Extracted {
	/// The field was reachable and decoded into a `Value`.
	Found(Value),
	/// At least one path segment was missing in the record's object tree;
	/// callers treat this as semantic [`Value::None`].
	Missing,
	/// The path could not be reached because an intermediate value was not
	/// an object, or a wire-level error occurred while decoding. Callers
	/// should fall back to a full decode.
	Bail,
}

/// Result of scanning a navigated object inside a revisioned record for a
/// fixed list of needle keys.
#[derive(Debug)]
pub(crate) enum ScanResult {
	/// Successfully descended to the navigated object and scanned its
	/// entries. Each result entry is the decoded `Value` for the
	/// corresponding needle (in input order), or `Value::None` when the
	/// needle is absent from the navigated object.
	Found(Vec<Value>),
	/// Some path segment was missing during descent. Callers treat every
	/// needle as resolving to `Value::None`.
	Missing,
	/// A wire-level error occurred or an intermediate value was not an
	/// object. Callers fall back to a full decode.
	Bail,
}

/// Walk the revisioned `record_bytes` along `path` and decode the leaf as a
/// [`Value`].
///
/// `depth_limit` bounds the number of path segments we descend through. The
/// pre-decode filter threads `ctx.config.idiom_recursion_limit` (default 256)
/// from the planner; paths longer than the limit return [`Extracted::Bail`],
/// causing the caller to fall back to full-record decode + post-decode
/// evaluation.
///
/// Returns:
/// - [`Extracted::Found`] when every segment is present in the record's nested object map and the
///   leaf decodes successfully.
/// - [`Extracted::Missing`] when an intermediate or leaf object key is absent at any level.
/// - [`Extracted::Bail`] for edge / view records, non-object intermediates, paths longer than
///   `depth_limit`, or any wire-level error.
pub(crate) fn extract_field_from_record_bytes(
	record_bytes: &[u8],
	path: &[String],
	depth_limit: u32,
) -> Extracted {
	extract_field_from_record_bytes_parts(record_bytes, &[], path, depth_limit)
}

/// Like [`extract_field_from_record_bytes`] but walks `prefix` segments
/// first, then `path`, without concatenating into a new [`Vec`].
///
/// Lets per-record evaluators in `pre_decode_filter` avoid allocating a
/// `Vec<String>` of `prefix ++ path` in their hot loops.
pub(crate) fn extract_field_from_record_bytes_parts(
	record_bytes: &[u8],
	prefix: &[String],
	path: &[String],
	depth_limit: u32,
) -> Extracted {
	if prefix.is_empty() && path.is_empty() {
		return Extracted::Bail;
	}
	let mut reader = record_bytes;
	// Skip past the Record's `metadata` field — see the module-level
	// comment for why metadata is irrelevant to filtering.
	let mut record_walker = match Record::walk_revisioned(&mut reader) {
		Ok(w) => w,
		Err(_) => return Extracted::Bail,
	};
	if record_walker.skip_metadata().is_err() {
		return Extracted::Bail;
	}
	// Hand the reader to a Value walker for the `data` field.
	let value_walker = match record_walker.into_walk_data() {
		Ok(w) => w,
		Err(_) => return Extracted::Bail,
	};
	descend_value_path_parts(value_walker, prefix, path, depth_limit)
}

/// Serialise a `&str` needle to its on-wire `Strand` representation
/// (`usize len || utf8`). The indexed-map walker compares full wire bytes,
/// so the needle must match the same shape.
fn strand_wire_bytes(needle: &str) -> Vec<u8> {
	let mut out = Vec::with_capacity(needle.len() + 4);
	<Strand as SerializeRevisioned>::serialize_revisioned(&Strand::new(needle), &mut out)
		.expect("Vec writer never errors");
	out
}

/// Look up a `needle` key in an indexed-map walker and return the matching value's
/// wire bytes. Handles both the indexed path (O(log n) binary search) and the
/// legacy sub-threshold path (`flags = 0`, no offset table — fall back to a
/// linear scan over the dense `(Strand, Value)*` body without allocating a `Strand`).
///
/// Wire-form note: `IndexedMapWalker::find_value_bytes`'s predicate compares
/// against the **full wire bytes** of each key (`usize len || utf8`), and the
/// keys are sorted by wire bytes (which means by `(length, utf8 bytes)`, not
/// by UTF-8 codepoint order). The caller passes `needle_str` as the raw UTF-8
/// path segment; we serialise it to wire form for the indexed compare, and on
/// the legacy path we strip each entry's length prefix to compare against
/// `needle_str.as_bytes()` directly. The legacy scan does not short-circuit
/// on a "greater" key because wire order is not UTF-8 order.
fn lookup_value_bytes_in_map<'p>(
	map_walker: &IndexedMapWalker<'p, Strand, Value>,
	needle_str: &str,
) -> Result<Option<&'p [u8]>, RevisionError> {
	let needle_utf8 = needle_str.as_bytes();
	if map_walker.is_indexed() {
		let needle_wire = strand_wire_bytes(needle_str);
		return map_walker.find_value_bytes(|kb: &[u8]| kb.cmp(needle_wire.as_slice()));
	}
	// Legacy sub-threshold body: `(Strand wire || Value wire)*` with `len`
	// known up front. Walk all entries, comparing UTF-8 bytes against the
	// needle — wire order may differ from UTF-8 order when entries have
	// varying lengths, so we can't short-circuit.
	let Some(body) = map_walker.legacy_body() else {
		return Ok(None);
	};
	let len = map_walker.len();
	let mut reader: &[u8] = body;
	for _ in 0..len {
		let key_len = <usize as DeserializeRevisioned>::deserialize_revisioned(&mut reader)?;
		if reader.len() < key_len {
			return Err(RevisionError::Deserialize(
				"legacy indexed-map body: key length exceeds remaining bytes".into(),
			));
		}
		let key_bytes = &reader[..key_len];
		reader = &reader[key_len..];
		if key_bytes == needle_utf8 {
			let v_start = body.len() - reader.len();
			let mut probe: &[u8] = reader;
			<Value as SkipRevisioned>::skip_revisioned(&mut probe)?;
			let v_end = body.len() - probe.len();
			return Ok(Some(&body[v_start..v_end]));
		}
		<Value as SkipRevisioned>::skip_revisioned(&mut reader)?;
	}
	Ok(None)
}

/// Borrowed cursor at any nested object inside a revision-encoded `Value`:
/// walks `prefix` segments first, then `path`, without concatenating into a
/// new [`Vec`]. The decoded leaf is the value at the end of `path` (or, when
/// `path` is empty, at the end of `prefix`).
///
/// `depth_limit` is the hard upper bound on path segment count; paths longer
/// than the limit return [`Extracted::Bail`]. Sourced from
/// `ctx.config.idiom_recursion_limit` at the planner-side construction of
/// [`crate::exec::pre_decode_filter::PreDecodeFilter`].
///
/// **Iterative form** — earlier revisions used recursion because each level
/// holds a `VariantView<Object>` and `IndexedMapView` from which the next
/// level's value bytes borrow; the recursive frame kept those views alive
/// for the duration of the descent. The current form copies each
/// intermediate object's wire bytes into a small owned `Vec<u8>` per level,
/// which breaks the borrow chain cleanly without sacrificing soundness on
/// the cross-revision `convert_fn` path (where the underlying `Cow` is
/// already `Owned`). For the leaf and the root we never copy; the per-level
/// allocation only fires for intermediate segments. With `depth_limit` of
/// 256, the worst case is 254 small `Vec<u8>` allocations per descent, all
/// freed at function return.
fn descend_value_path_parts<'r, R: BorrowedReader>(
	value_walker: <Value as WalkRevisioned>::Walker<'r, R>,
	prefix: &[String],
	path: &[String],
	depth_limit: u32,
) -> Extracted {
	let total = prefix.len() + path.len();
	if total == 0 || total > depth_limit as usize {
		return Extracted::Bail;
	}

	// The walker must be positioned at an `Object` for the first segment to
	// resolve. Pull the initial object body into an owned `Vec<u8>` so the
	// per-iteration borrow chain below has a self-owned source it can
	// re-borrow each time.
	if !value_walker.is_object() {
		return Extracted::Bail;
	}
	let mut current_bytes: Vec<u8> = match value_walker.object_view() {
		Ok(v) => v.as_bytes().to_vec(),
		Err(_) => return Extracted::Bail,
	};

	for i in 0..total {
		let needle = if i < prefix.len() {
			prefix[i].as_str()
		} else {
			path[i - prefix.len()].as_str()
		};
		// Run the per-level descent in a tight block so all intermediate
		// borrows into `current_bytes` end before we reassign it. The block
		// either short-circuits via `return` (leaf / missing / wire error)
		// or evaluates to the next iteration's owned bytes.
		let next_bytes: Vec<u8> = {
			let mut object_reader: &[u8] = &current_bytes;
			let object_walker =
				match <Object as WalkRevisioned>::walk_revisioned(&mut object_reader) {
					Ok(w) => w,
					Err(_) => return Extracted::Bail,
				};
			let map_view = match object_walker.into_walk_field_0() {
				Ok(v) => v,
				Err(_) => return Extracted::Bail,
			};
			let map_walker = match map_view.walker() {
				Ok(w) => w,
				Err(_) => return Extracted::Bail,
			};
			let value_bytes = match lookup_value_bytes_in_map(&map_walker, needle) {
				Ok(Some(b)) => b,
				Ok(None) => return Extracted::Missing,
				Err(_) => return Extracted::Bail,
			};
			if i + 1 == total {
				let mut leaf_reader: &[u8] = value_bytes;
				return match <Value as DeserializeRevisioned>::deserialize_revisioned(
					&mut leaf_reader,
				) {
					Ok(v) => Extracted::Found(v),
					Err(_) => Extracted::Bail,
				};
			}
			// Intermediate: open a fresh `Value` walker on `value_bytes`,
			// verify it's an object, and copy its variant body bytes into a
			// fresh owned buffer for the next iteration.
			let mut value_reader: &[u8] = value_bytes;
			let next_walker = match <Value as WalkRevisioned>::walk_revisioned(&mut value_reader) {
				Ok(w) => w,
				Err(_) => return Extracted::Bail,
			};
			if !next_walker.is_object() {
				return Extracted::Bail;
			}
			let next_view = match next_walker.object_view() {
				Ok(v) => v,
				Err(_) => return Extracted::Bail,
			};
			next_view.as_bytes().to_vec()
		};
		current_bytes = next_bytes;
	}
	// Unreachable: the leaf return inside the loop fires when `i + 1 == total`,
	// and `total > 0` is enforced at entry.
	Extracted::Bail
}

/// Multi-key scan over a record's outer object map: for each key in
/// `needles_sorted` (strictly increasing UTF-8 order), record either the
/// decoded [`Value`] or `Value::None` when the key is absent.
///
/// Returns [`None`] only for wire-level errors so callers fall back to a
/// full decode; the metadata field (plain row vs. edge vs. materialised
/// view) is intentionally irrelevant — see the module-level comment.
pub(crate) fn scan_record_root_object_for_keys_sorted<K: AsRef<[u8]>>(
	record_bytes: &[u8],
	needles_sorted: &[K],
) -> Option<Vec<Value>> {
	if needles_sorted.is_empty() {
		return Some(Vec::new());
	}
	debug_assert!(
		needles_sorted.windows(2).all(|w| w[0].as_ref() < w[1].as_ref()),
		"needles_sorted must be strictly increasing; the merge walk only advances",
	);
	let mut reader = record_bytes;
	let mut record_walker = Record::walk_revisioned(&mut reader).ok()?;
	record_walker.skip_metadata().ok()?;
	let value_walker = record_walker.into_walk_data().ok()?;
	scan_value_object_for_keys_sorted(value_walker, needles_sorted)
}

/// Multi-key scan that first walks `path` into the record's data tree and
/// then scans the resulting object for `needles_sorted`.
///
/// `path` is the navigation prefix from `PredNode::NavigatePrefix`; it may
/// be empty, in which case this delegates to
/// [`scan_record_root_object_for_keys_sorted`] (the unchanged root-level
/// hot path).
///
/// Unlike the previous `extract_field_from_record_bytes` +
/// `evaluate_fused_against_object` pipeline, this **never materialises the
/// navigated `Value::Object`** — the descent and the inner scan share a
/// single walker chain, and only matched values are decoded.
pub(crate) fn scan_record_object_at_path_for_keys_sorted<K: AsRef<[u8]>>(
	record_bytes: &[u8],
	path: &[String],
	needles_sorted: &[K],
	depth_limit: u32,
) -> ScanResult {
	if needles_sorted.is_empty() {
		return ScanResult::Found(Vec::new());
	}
	debug_assert!(
		needles_sorted.windows(2).all(|w| w[0].as_ref() < w[1].as_ref()),
		"needles_sorted must be strictly increasing; the merge walk only advances",
	);
	if path.is_empty() {
		return match scan_record_root_object_for_keys_sorted(record_bytes, needles_sorted) {
			Some(values) => ScanResult::Found(values),
			None => ScanResult::Bail,
		};
	}
	let mut reader = record_bytes;
	let mut record_walker = match Record::walk_revisioned(&mut reader) {
		Ok(w) => w,
		Err(_) => return ScanResult::Bail,
	};
	if record_walker.skip_metadata().is_err() {
		return ScanResult::Bail;
	}
	let value_walker = match record_walker.into_walk_data() {
		Ok(w) => w,
		Err(_) => return ScanResult::Bail,
	};
	let result = descend_to_value_walker(value_walker, path, depth_limit, |value_bytes| {
		let mut reader: &[u8] = value_bytes;
		let walker = <Value as WalkRevisioned>::walk_revisioned(&mut reader).ok()?;
		scan_value_object_for_keys_sorted(walker, needles_sorted)
	});
	match result {
		DescendResult::Found(Some(values)) => ScanResult::Found(values),
		DescendResult::Found(None) => ScanResult::Bail,
		DescendResult::Missing => ScanResult::Missing,
		DescendResult::Bail => ScanResult::Bail,
	}
}

/// Outcome of [`descend_to_value_walker`].
pub(crate) enum DescendResult<T> {
	/// Successfully consumed every path segment; the callback's return value
	/// is forwarded to the caller.
	Found(T),
	/// A path segment was missing during descent.
	Missing,
	/// Wire-level error or non-object intermediate.
	Bail,
}

/// Walk `path` segments inside the value tree and invoke `consume` with the
/// navigated [`Value`]'s wire bytes.
///
/// `depth_limit` bounds the descent length — see
/// [`descend_value_path_parts`] for the rationale. The callback shape lets
/// the most-recent owned bytes stay alive while the borrowed bytes are in
/// use — handing the bytes out by reference would let them outlive their
/// owning buffer. Callers open a fresh `Value::walk_revisioned` (or
/// similar) inside the closure.
pub(crate) fn descend_to_value_walker<T, F>(
	value_walker: <Value as WalkRevisioned>::Walker<'_, &[u8]>,
	path: &[String],
	depth_limit: u32,
	consume: F,
) -> DescendResult<T>
where
	F: FnOnce(&[u8]) -> T,
{
	descend_to_value_walker_parts(value_walker, &[], path, depth_limit, consume)
}

/// Like [`descend_to_value_walker`] but walks `prefix` segments first, then
/// `path`, without concatenating into a new [`Vec`].
///
/// Iterative implementation mirroring [`descend_value_path_parts`]; each
/// intermediate level's variant body is copied into a small owned `Vec<u8>`
/// so subsequent iterations have a self-owned source to re-borrow. The
/// terminal call passes the navigated value's wire bytes (still borrowed
/// from the current level's owned buffer) to `consume`.
pub(crate) fn descend_to_value_walker_parts<T, F>(
	walker: <Value as WalkRevisioned>::Walker<'_, &[u8]>,
	prefix: &[String],
	path: &[String],
	depth_limit: u32,
	consume: F,
) -> DescendResult<T>
where
	F: FnOnce(&[u8]) -> T,
{
	let total = prefix.len() + path.len();
	// Initial-step special case: when the descent has no segments, the
	// caller wants the walker's CURRENT position (a borrowed-from-record
	// Value). We re-encode that position into a fresh Vec<u8> via a peek,
	// but the cleaner path is to detect zero segments at the entry and
	// require callers to handle it themselves. For now, treat zero
	// segments as "bail" — no existing caller relies on it.
	if total == 0 || total > depth_limit as usize {
		return DescendResult::Bail;
	}
	if !walker.is_object() {
		return DescendResult::Bail;
	}
	let mut current_bytes: Vec<u8> = match walker.object_view() {
		Ok(v) => v.as_bytes().to_vec(),
		Err(_) => return DescendResult::Bail,
	};

	// `consume` is `FnOnce`, so it has to leave the block exactly once. We
	// thread it through the loop via `Option::take` at the terminal step.
	let mut consume_slot: Option<F> = Some(consume);

	for i in 0..total {
		let needle = if i < prefix.len() {
			prefix[i].as_str()
		} else {
			path[i - prefix.len()].as_str()
		};
		let next_bytes: Vec<u8> = {
			let mut object_reader: &[u8] = &current_bytes;
			let object_walker =
				match <Object as WalkRevisioned>::walk_revisioned(&mut object_reader) {
					Ok(w) => w,
					Err(_) => return DescendResult::Bail,
				};
			let map_view = match object_walker.into_walk_field_0() {
				Ok(v) => v,
				Err(_) => return DescendResult::Bail,
			};
			let map_walker = match map_view.walker() {
				Ok(w) => w,
				Err(_) => return DescendResult::Bail,
			};
			let value_bytes = match lookup_value_bytes_in_map(&map_walker, needle) {
				Ok(Some(b)) => b,
				Ok(None) => return DescendResult::Missing,
				Err(_) => return DescendResult::Bail,
			};
			if i + 1 == total {
				// Terminal: invoke the caller's closure with the navigated
				// value's wire bytes. `current_bytes` is alive in this
				// frame so the `&[u8]` slice (transitively borrowed from
				// it) remains valid for the closure call.
				let f = consume_slot.take().expect("consume_slot taken exactly once");
				return DescendResult::Found(f(value_bytes));
			}
			let mut value_reader: &[u8] = value_bytes;
			let next_walker = match <Value as WalkRevisioned>::walk_revisioned(&mut value_reader) {
				Ok(w) => w,
				Err(_) => return DescendResult::Bail,
			};
			if !next_walker.is_object() {
				return DescendResult::Bail;
			}
			let next_view = match next_walker.object_view() {
				Ok(v) => v,
				Err(_) => return DescendResult::Bail,
			};
			next_view.as_bytes().to_vec()
		};
		current_bytes = next_bytes;
	}
	// Unreachable: terminal `return` above fires when `i + 1 == total`, and
	// `total > 0` is enforced at entry.
	DescendResult::Bail
}

/// Multi-key scan over an object payload reached through a value walker.
///
/// `needles_sorted` is assumed sorted by UTF-8 bytes (the planner-side
/// callers pre-sort their queries that way). The indexed-map encoding,
/// however, sorts entries by **wire bytes** (`usize_len || utf8`), which
/// differs from UTF-8 order whenever the entries have varying lengths — so
/// we can't rely on a single linear merge walk in input order.
///
/// Instead, iterate every entry and binary-search the needle list for the
/// entry's UTF-8 key. Stops early once all needles have been matched. The
/// indexed path uses `IndexedMapWalker::entries()`; the legacy sub-threshold
/// path walks the `(Strand wire || Value wire)*` body manually.
pub(crate) fn scan_value_object_for_keys_sorted<'r, R: BorrowedReader, K: AsRef<[u8]>>(
	value_walker: <Value as WalkRevisioned>::Walker<'r, R>,
	needles_sorted: &[K],
) -> Option<Vec<Value>> {
	debug_assert!(
		needles_sorted.windows(2).all(|w| w[0].as_ref() < w[1].as_ref()),
		"needles_sorted must be strictly increasing in UTF-8 byte order",
	);
	if !value_walker.is_object() {
		return None;
	}
	let object_view = value_walker.object_view().ok()?;
	let object_bytes = object_view.as_bytes();
	let mut object_reader: &[u8] = object_bytes;
	let object_walker = <Object as WalkRevisioned>::walk_revisioned(&mut object_reader).ok()?;
	let map_view = object_walker.into_walk_field_0().ok()?;
	let map_walker = map_view.walker().ok()?;

	let mut out: Vec<Value> = Vec::with_capacity(needles_sorted.len());
	out.resize_with(needles_sorted.len(), || Value::None);
	let mut remaining = needles_sorted.len();

	if map_walker.is_indexed() {
		for (kb_wire, vb) in map_walker.entries()? {
			if remaining == 0 {
				break;
			}
			// Strip the length prefix off the wire-encoded key to get its
			// UTF-8 bytes — the indexed encoder writes full Strand wire
			// (`usize len || utf8`), but our needles are UTF-8 only.
			let mut kr: &[u8] = kb_wire;
			let key_len = <usize as DeserializeRevisioned>::deserialize_revisioned(&mut kr).ok()?;
			if kr.len() != key_len {
				return None;
			}
			if let Ok(idx) = needles_sorted.binary_search_by(|n| n.as_ref().cmp(kr)) {
				let mut vr: &[u8] = vb;
				out[idx] =
					<Value as DeserializeRevisioned>::deserialize_revisioned(&mut vr).ok()?;
				remaining -= 1;
			}
		}
	} else {
		let body = map_walker.legacy_body()?;
		let len = map_walker.len();
		let mut reader: &[u8] = body;
		for _ in 0..len {
			if remaining == 0 {
				break;
			}
			let key_len =
				<usize as DeserializeRevisioned>::deserialize_revisioned(&mut reader).ok()?;
			if reader.len() < key_len {
				return None;
			}
			let kb_utf8 = &reader[..key_len];
			reader = &reader[key_len..];
			if let Ok(idx) = needles_sorted.binary_search_by(|n| n.as_ref().cmp(kb_utf8)) {
				out[idx] =
					<Value as DeserializeRevisioned>::deserialize_revisioned(&mut reader).ok()?;
				remaining -= 1;
			} else {
				<Value as SkipRevisioned>::skip_revisioned(&mut reader).ok()?;
			}
		}
	}
	Some(out)
}

/// Depth limit used by test helpers and by test sites that construct a
/// `PreDecodeFilter` without going through the planner. Matches the default
/// `idiom_recursion_limit` (256) so test behaviour reflects production.
#[cfg(test)]
pub(crate) const TEST_DEPTH_LIMIT: u32 = 256;

#[cfg(test)]
pub(crate) fn descend_record_value_path(record_bytes: &[u8], path: &[String]) -> Extracted {
	extract_field_from_record_bytes(record_bytes, path, TEST_DEPTH_LIMIT)
}

#[cfg(test)]
pub(crate) fn descend_value_slice_path(value_wire: &[u8], path: &[String]) -> Extracted {
	if path.is_empty() {
		return Extracted::Bail;
	}
	let mut reader = value_wire;
	let walker = match Value::walk_revisioned(&mut reader) {
		Ok(w) => w,
		Err(_) => return Extracted::Bail,
	};
	descend_value_path_parts(walker, &[], path, TEST_DEPTH_LIMIT)
}
