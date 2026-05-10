//! Walker-based field extraction for revision-encoded
//! [`Record`](crate::catalog::Record) bytes.
//!
//! Table rows are encoded as revisioned [`crate::catalog::Record`] values
//! whose payload is typically a [`Value::Object`] with sorted [`Strand`] keys
//! backed by [`surrealdb_collections::VecMap`]. The pre-decode filter walks
//! into nested fields without materialising the entire `Value` tree by using
//! the per-type walkers emitted by `revision`'s `#[revisioned(...)]` derive.

use std::io::Read;

use revision::{MapWalker, WalkRevisioned};
use surrealdb_strand::Strand;

use crate::catalog::Record;
use crate::val::Value;

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
/// Returns:
/// - [`Extracted::Found`] when every segment is present in the record's nested object map and the
///   leaf decodes successfully.
/// - [`Extracted::Missing`] when an intermediate or leaf object key is absent at any level.
/// - [`Extracted::Bail`] for edge / view records, non-object intermediates, or any wire-level
///   error.
pub(crate) fn extract_field_from_record_bytes(record_bytes: &[u8], path: &[String]) -> Extracted {
	if path.is_empty() {
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
	descend_value_path(value_walker, path)
}

/// Borrowed cursor at any nested object inside a revision-encoded `Value`.
///
/// Tracks "currently positioned at a `Value` walker" semantics so the
/// pre-decode filter can descend through nested `Value::Object` payloads.
fn descend_value_path<'r, R: Read>(
	value_walker: <Value as WalkRevisioned>::Walker<'r, R>,
	path: &[String],
) -> Extracted {
	let mut walker = value_walker;
	let mut segments: &[String] = path;
	loop {
		// Each iteration starts with `walker` positioned right after a
		// Value's `u16 revision` and `u32 discriminant`. Verify the variant
		// is `Object` before descending.
		if !walker.is_object() {
			return Extracted::Bail;
		}
		// Descend into the Object's inner VecMap. Object is a tuple struct
		// over `VecMap<Strand, Value>`; `into_walk_field_0` consumes the
		// object walker and yields a `MapWalker` over the entries.
		let object_walker = match walker.into_object() {
			Ok(w) => w,
			Err(_) => return Extracted::Bail,
		};
		let map_walker: MapWalker<Strand, Value, _> = match object_walker.into_walk_field_0() {
			Ok(w) => w,
			Err(_) => return Extracted::Bail,
		};
		// Pull the next path segment to look up.
		let needle = segments[0].as_str();
		segments = &segments[1..];
		// `find` returns a value handle: the reader is positioned at the
		// value's encoding without the type-level prefix consumed.
		let handle = match map_walker.find(|k: &Strand| k.as_str().cmp(needle)) {
			Ok(v) => v,
			Err(_) => return Extracted::Bail,
		};
		let handle = match handle {
			Some(h) => h,
			None => return Extracted::Missing,
		};
		if segments.is_empty() {
			// Leaf: decode the entire Value (handle reader is positioned
			// before the Value's prefix).
			return match handle.decode() {
				Ok(v) => Extracted::Found(v),
				Err(_) => Extracted::Bail,
			};
		}
		// Intermediate: walk into the Value to keep descending. `walk`
		// consumes the prefix and yields a fresh value walker.
		walker = match handle.walk() {
			Ok(w) => w,
			Err(_) => return Extracted::Bail,
		};
	}
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
	match descend_to_value_walker(value_walker, path) {
		DescendResult::Found(walker) => {
			match scan_value_object_for_keys_sorted(walker, needles_sorted) {
				Some(values) => ScanResult::Found(values),
				None => ScanResult::Bail,
			}
		}
		DescendResult::Missing => ScanResult::Missing,
		DescendResult::Bail => ScanResult::Bail,
	}
}

/// Outcome of [`descend_to_value_walker`].
pub(crate) enum DescendResult<'r, R: Read + 'r> {
	/// Successfully consumed every path segment; the inner walker is
	/// positioned at the navigated [`Value`] (post type-level prefix).
	Found(<Value as WalkRevisioned>::Walker<'r, R>),
	/// A path segment was missing during descent.
	Missing,
	/// Wire-level error or non-object intermediate.
	Bail,
}

/// Walk `path` segments inside the value tree, returning a walker
/// positioned at the navigated [`Value`].
///
/// Mirrors the loop in [`descend_value_path`] but consumes **every** path
/// segment (including the last) and returns the resulting walker rather
/// than decoding the leaf — that lets callers stream the navigated value's
/// contents instead of materialising it.
pub(crate) fn descend_to_value_walker<'r, R: Read>(
	value_walker: <Value as WalkRevisioned>::Walker<'r, R>,
	path: &[String],
) -> DescendResult<'r, R> {
	descend_to_value_walker_parts(value_walker, &[], path)
}

/// Like [`descend_to_value_walker`] but walks `prefix` segments first, then
/// `path`, without concatenating into a new [`Vec`].
pub(crate) fn descend_to_value_walker_parts<'r, R: Read>(
	mut walker: <Value as WalkRevisioned>::Walker<'r, R>,
	prefix: &[String],
	path: &[String],
) -> DescendResult<'r, R> {
	for needle in prefix.iter().chain(path.iter()) {
		// The current walker must be an `Object` for the next segment to
		// resolve.
		if !walker.is_object() {
			return DescendResult::Bail;
		}
		let object_walker = match walker.into_object() {
			Ok(w) => w,
			Err(_) => return DescendResult::Bail,
		};
		let map_walker: MapWalker<Strand, Value, _> = match object_walker.into_walk_field_0() {
			Ok(w) => w,
			Err(_) => return DescendResult::Bail,
		};
		let needle_str = needle.as_str();
		let handle = match map_walker.find(|k: &Strand| k.as_str().cmp(needle_str)) {
			Ok(v) => v,
			Err(_) => return DescendResult::Bail,
		};
		let handle = match handle {
			Some(h) => h,
			None => return DescendResult::Missing,
		};
		walker = match handle.walk() {
			Ok(w) => w,
			Err(_) => return DescendResult::Bail,
		};
	}
	DescendResult::Found(walker)
}

/// Multi-key scan over an object payload reached through a value walker.
pub(crate) fn scan_value_object_for_keys_sorted<'r, R: Read, K: AsRef<[u8]>>(
	value_walker: <Value as WalkRevisioned>::Walker<'r, R>,
	needles_sorted: &[K],
) -> Option<Vec<Value>> {
	debug_assert!(
		needles_sorted.windows(2).all(|w| w[0].as_ref() < w[1].as_ref()),
		"needles_sorted must be strictly increasing; the merge walk only advances",
	);
	if !value_walker.is_object() {
		return None;
	}
	let mut map_walker: MapWalker<Strand, Value, _> =
		value_walker.into_object().ok()?.into_walk_field_0().ok()?;

	let mut out: Vec<Value> = Vec::with_capacity(needles_sorted.len());
	out.resize_with(needles_sorted.len(), || Value::None);

	let mut qi = 0usize;
	while qi < needles_sorted.len()
		&& let Some(mut entry) = map_walker.next_entry()
	{
		let key = entry.decode_key().ok()?;
		// Advance past consumed needles that are strictly less than this key.
		while qi < needles_sorted.len() && needles_sorted[qi].as_ref() < key.as_str().as_bytes() {
			qi += 1;
		}
		if qi < needles_sorted.len() && needles_sorted[qi].as_ref() == key.as_str().as_bytes() {
			let v = entry.decode_value().ok()?;
			out[qi] = v;
			qi += 1;
		} else {
			entry.skip_value().ok()?;
		}
	}
	// Remaining entries don't match any further needle; let the walker be
	// dropped without explicitly skipping. The caller treats unmatched
	// needles as `Value::None` (already populated).
	Some(out)
}

#[cfg(test)]
pub(crate) fn descend_record_value_path(record_bytes: &[u8], path: &[String]) -> Extracted {
	extract_field_from_record_bytes(record_bytes, path)
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
	descend_value_path(walker, path)
}
