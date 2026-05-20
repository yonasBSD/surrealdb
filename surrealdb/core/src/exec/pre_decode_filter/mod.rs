//! Pre-decode filter ([`PreDecodeFilter`]) — **reject-only** optimisation during KV scans.
//!
//! Before paying full [`crate::catalog::Record`] deserialization, the scan may prove from
//! **revision-encoded KV bytes alone** that the pushed-down WHERE cannot hold for this row. Only
//! [`PreDecodeFilterOutcome::Reject`] drops the row without decode; every other outcome falls
//! through to the normal path.
//!
//! ## Timing (vs `scan_predicate`)
//!
//! This runs synchronously inside [`crate::exec::operators::scan::pipeline::kv_scan_stream`]
//! **before** [`crate::exec::operators::scan::pipeline::decode_record`]. The scan's pushed-down
//! [`crate::exec::PhysicalExpr`] predicate (`scan_predicate` on table / dynamic / record-id range
//! scans) still runs **after** decode in
//! [`crate::exec::operators::scan::pipeline::filter_and_process_batch`], together with table-level
//! permission filtering, computed fields, and field-level SELECT permissions — that evaluation is
//! **authoritative** for inclusion.
//!
//! | | Pre-decode filter | `scan_predicate` pushdown |
//! |--|-------------------|---------------------------|
//! | Input | Raw KV bytes | Decoded [`crate::val::Value`] |
//! | Semantics | Conservative; reject-only | Exact (must match `Filter`) |
//! | Async / params | Literal RHS baked at compile; sync only | Full [`PhysicalExpr`] |
//!
//! ## Eligibility
//!
//! Predicate shape is compiled by [`compile::compile_predicate_shape`] (AND/OR/NOT, comparison and
//! collection containment ops with literal RHS where the field path is static, excluding geometry
//! and list-equality shorthands). Referenced root fields must not be computed
//! (`DEFINE FIELD … VALUE …`), and field-level SELECT permissions must be `Allow` when permission
//! checks apply — otherwise raw-byte reads would diverge from engine-visible values or bypass
//! authorisation.
//!
//! ## Relation to `ExpressionRegistry`
//!
//! ORDER BY / SELECT expression deduplication uses
//! [`crate::exec::expression_registry::ExpressionRegistry`] and runs **post-WHERE** on decoded
//! values. This module does not participate in that path.

mod compile;
mod streaming;

use std::collections::HashSet;
use std::sync::Arc;

pub(crate) use compile::{pre_decode_filter_for_execute, pre_decode_filter_status_at_plan_time};
use revision::WalkRevisioned;
pub(crate) use streaming::StreamingLeafEvaluator;

use crate::catalog::Record;
use crate::expr::operator::BinaryOperator;
use crate::fnc::operate;
use crate::key::record::RecordKey;
use crate::val::object_extract::{
	DescendResult, Extracted, ScanResult, WalkLeafErr, descend_to_value_walker_parts,
	extract_field_from_record_bytes, extract_field_from_record_bytes_parts,
	scan_record_object_at_path_for_keys_sorted,
};
use crate::val::{RecordId, Value};

/// When a streaming leaf walk bails or misses, re-apply this op against a decoded leaf or
/// [`Value::None`] to preserve parity with the ordinary [`PredNode::Leaf`] path.
#[derive(Debug, Clone)]
pub(crate) struct LeafFallback {
	pub(crate) op: BinaryOperator,
	pub(crate) literal: Value,
	pub(crate) reversed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreDecodeFilterOutcome {
	Reject,
	NeedFullDecode,
}

#[derive(Debug, Clone)]
pub(crate) struct FusedFlatClause {
	pub(crate) key_utf8: Vec<u8>,
	pub(crate) op: BinaryOperator,
	pub(crate) literal: Value,
	pub(crate) reversed: bool,
}

/// Lookup-key view used by
/// [`scan_record_root_object_for_keys_sorted`]: returns the clause's
/// `key_utf8` bytes. Lets fused-map evaluation pass `&[FusedFlatClause]`
/// directly without projecting into a `Vec<&[u8]>` per row.
impl AsRef<[u8]> for FusedFlatClause {
	fn as_ref(&self) -> &[u8] {
		&self.key_utf8
	}
}

/// A sorted, deduplicated set of [`FusedFlatClause`] for one
/// [`PredNode::FusedFlatMapAnd`].
///
/// Wraps a private [`Vec<FusedFlatClause>`] guaranteed to be **strictly ascending by
/// `key_utf8` with unique keys**. Fused-map evaluation pairs this slice with the result
/// of [`scan_record_root_object_for_keys_sorted`] by parallel iteration; if the invariant
/// is broken the pairing is silently misaligned and rows return wrong evidence. Construct
/// only via [`FusedFlatClauses::try_new`] (returns `None` on duplicate or out-of-order
/// keys), which makes the misaligned shape unrepresentable.
#[derive(Debug, Clone)]
pub(crate) struct FusedFlatClauses(Vec<FusedFlatClause>);

impl FusedFlatClauses {
	/// Construct from a vector already strictly ascending by `key_utf8` with unique keys.
	/// Returns `None` if the invariant is violated.
	pub(crate) fn try_new(inner: Vec<FusedFlatClause>) -> Option<Self> {
		if inner.windows(2).any(|w| w[0].key_utf8 >= w[1].key_utf8) {
			return None;
		}
		Some(Self(inner))
	}

	pub(crate) fn as_slice(&self) -> &[FusedFlatClause] {
		&self.0
	}
}

impl std::ops::Deref for FusedFlatClauses {
	type Target = [FusedFlatClause];

	fn deref(&self) -> &[FusedFlatClause] {
		&self.0
	}
}

#[derive(Debug, Clone)]
pub(crate) enum PredNode {
	And(Vec<PredNode>),
	Or(Vec<PredNode>),
	Not(Box<PredNode>),
	Leaf {
		path: Vec<String>,
		op: BinaryOperator,
		literal: Value,
		reversed: bool,
	},
	/// `field IN [..]` / `field NOT IN [..]` with a hashset-safe literal array or set.
	///
	/// `op` is [`BinaryOperator::Inside`] or [`BinaryOperator::NotInside`] only.
	LeafSetMembership {
		path: Vec<String>,
		op: BinaryOperator,
		set: Arc<HashSet<Value>>,
		/// Carried for symmetry with [`PredNode::Leaf`]; v1 hashset emission uses `false` only.
		#[allow(dead_code)]
		reversed: bool,
	},
	/// Leaf predicate evaluated via [`StreamingLeafEvaluator`] without decoding the leaf when
	/// possible; see [`LeafFallback`] for wire / shape escapes.
	LeafStreaming {
		path: Vec<String>,
		evaluator: Arc<dyn StreamingLeafEvaluator>,
		fallback: LeafFallback,
	},
	/// One map scan over a [`Value::Object`] VecMap at the current anchor (`at_record_root`:
	/// anchored at the table row's root object; otherwise at a nested object).
	///
	/// `clauses` is a [`FusedFlatClauses`] which enforces the strictly-ascending,
	/// deduplicated-by-`key_utf8` invariant at the type level — fused-map evaluation
	/// pairs the slice with [`scan_record_root_object_for_keys_sorted`] output by position.
	FusedFlatMapAnd {
		at_record_root: bool,
		clauses: FusedFlatClauses,
	},
	NavigatePrefix {
		segment: String,
		child: Box<PredNode>,
	},
}

/// Why a pre-decode filter cannot be built for a scan.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum PreDecodeFilterReason {
	/// The predicate's physical shape is not supported by [`compile::compile_predicate_shape`]
	/// (e.g. `Outside` / `Intersects` / `AllEqual` / `AnyEqual`, `MATCHES`, or non-static field
	/// paths).
	UnsupportedPredicate,
	/// One of the referenced root field names is computed (`DEFINE FIELD … VALUE …`); the raw
	/// KV bytes do not necessarily match the value the engine will materialise.
	ComputedFields,
	/// One of the referenced root field names has a non-`Allow` SELECT permission, so reading
	/// it from raw KV bytes would bypass per-field authorisation.
	FieldPermissions,
}

/// Plan / execute-time status of the pre-decode filter for a KV scan
/// ([`TableScan`](crate::exec::operators::scan::table::TableScan),
/// [`DynamicScan`](crate::exec::operators::scan::dynamic::DynamicScan),
/// [`RecordIdScan`](crate::exec::operators::scan::record_id::RecordIdScan)).
#[derive(Debug, Clone)]
pub(crate) enum PreDecodeFilterStatus {
	/// No WHERE predicate pushed into the scan — omit `pre_decode_filter` in EXPLAIN.
	NotApplicable,
	/// Predicate compiled and field checks passed at plan time.
	Active(Arc<PreDecodeFilter>),
	/// Predicate shape is known; field state or permission checks need runtime context.
	Deferred(Arc<PredNode>),
	/// Predicate shape unsupported or field checks failed.
	Ineligible(PreDecodeFilterReason),
}

impl PreDecodeFilterStatus {
	/// Human-readable value for the `pre_decode_filter` attribute in EXPLAIN output.
	///
	/// Returns [`None`] when the scan has no WHERE predicate pushed into it, in which case the
	/// `pre_decode_filter` attribute should be omitted from `attrs()` entirely.
	pub(crate) fn explain_text(&self) -> Option<String> {
		match self {
			Self::NotApplicable => None,
			Self::Active(_) => Some("yes".into()),
			Self::Deferred(_) => Some("deferred (runtime field state)".into()),
			Self::Ineligible(PreDecodeFilterReason::UnsupportedPredicate) => {
				Some("no (unsupported predicate)".into())
			}
			Self::Ineligible(PreDecodeFilterReason::ComputedFields) => {
				Some("no (computed fields)".into())
			}
			Self::Ineligible(PreDecodeFilterReason::FieldPermissions) => {
				Some("no (field permissions)".into())
			}
		}
	}
}

/// Partial truth status of the predicate from cheap structural inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Evidence {
	/// Predicate is definitely false for this row → safe to skip full decode.
	ProvablyFalse,
	/// Predicate is definitely true (for the sub-expression) from decoded field bytes.
	ProvablyTrue,
	/// Cannot conclude — must full-decode and evaluate as today.
	Unknown,
}

#[derive(Debug)]
pub(crate) struct PreDecodeFilter {
	pub(crate) root: PredNode,
	/// Hard cap on path-segment count for any pre-decode descent. Sourced
	/// from `ctx.config.idiom_recursion_limit` at the planner; bounds the
	/// stack and intermediate allocations done by
	/// [`crate::val::object_extract`]'s walker descent. Paths longer than
	/// the limit fall back to full-record decode + post-decode evaluation.
	pub(crate) depth_limit: u32,
}

impl PreDecodeFilter {
	pub(crate) fn new(root: PredNode, depth_limit: u32) -> Self {
		Self {
			root,
			depth_limit,
		}
	}

	pub(crate) fn apply(&self, key: &[u8], record_bytes: &[u8]) -> PreDecodeFilterOutcome {
		let ev = self.eval_node(key, record_bytes, &[], &self.root);
		match ev {
			Evidence::ProvablyFalse => PreDecodeFilterOutcome::Reject,
			Evidence::ProvablyTrue | Evidence::Unknown => PreDecodeFilterOutcome::NeedFullDecode,
		}
	}

	/// Evaluate `node` against `record_bytes` with `prefix` as a path
	/// prepended to every leaf access.
	///
	/// `NavigatePrefix` chains are folded into `prefix` rather than carrying a
	/// per-anchor state through the tree; the walker-based field extractor
	/// handles missing intermediates itself.
	fn eval_node(
		&self,
		key: &[u8],
		record_bytes: &[u8],
		prefix: &[String],
		node: &PredNode,
	) -> Evidence {
		match node {
			PredNode::And(xs) => {
				combine_and(xs.iter().map(|x| self.eval_node(key, record_bytes, prefix, x)))
			}
			PredNode::Or(xs) => {
				combine_or(xs.iter().map(|x| self.eval_node(key, record_bytes, prefix, x)))
			}
			PredNode::Not(inner) => match self.eval_node(key, record_bytes, prefix, inner) {
				Evidence::ProvablyFalse => Evidence::ProvablyTrue,
				Evidence::ProvablyTrue => Evidence::ProvablyFalse,
				Evidence::Unknown => Evidence::Unknown,
			},
			PredNode::Leaf {
				path,
				op,
				literal,
				reversed,
			} => self.eval_leaf(key, record_bytes, prefix, path, op, literal, *reversed),
			PredNode::LeafSetMembership {
				path,
				op,
				set,
				reversed: _,
			} => self.eval_set_membership(record_bytes, prefix, path, op, set.as_ref()),
			PredNode::LeafStreaming {
				path,
				evaluator,
				fallback,
			} => self.eval_leaf_streaming(record_bytes, prefix, path, evaluator.as_ref(), fallback),
			PredNode::FusedFlatMapAnd {
				clauses,
				..
			} => self.eval_fused_flat(record_bytes, prefix, clauses),
			PredNode::NavigatePrefix {
				segment,
				child: _,
			} if segment.as_str() == "id" => Evidence::Unknown,
			PredNode::NavigatePrefix {
				segment,
				child,
			} => {
				// Fold the navigate segment into the path prefix and keep
				// descending. The leaf / fused / scan node responsible for the
				// actual extraction will resolve the full path against the
				// row's encoded bytes.
				let mut next = Vec::with_capacity(prefix.len() + 1);
				next.extend_from_slice(prefix);
				next.push(segment.clone());
				self.eval_node(key, record_bytes, &next, child.as_ref())
			}
		}
	}

	fn eval_leaf_streaming(
		&self,
		record_bytes: &[u8],
		prefix: &[String],
		path: &[String],
		evaluator: &dyn StreamingLeafEvaluator,
		fallback: &LeafFallback,
	) -> Evidence {
		let stream_ev: Result<Evidence, WalkLeafErr> = (|| {
			if prefix.is_empty() && path.is_empty() {
				return Err(WalkLeafErr::Bail);
			}
			let mut reader = record_bytes;
			let mut record_walker =
				Record::walk_revisioned(&mut reader).map_err(|_| WalkLeafErr::Bail)?;
			record_walker.skip_metadata().map_err(|_| WalkLeafErr::Bail)?;
			let value_walker = record_walker.into_walk_data().map_err(|_| WalkLeafErr::Bail)?;
			// Closure form: the descent holds the navigated value's owning
			// `OwnedIndexedMapView` alive on its stack while we open a fresh
			// `Value` walker from the borrowed bytes and hand it to the
			// streaming evaluator. The `Evidence` return type doesn't borrow
			// from the walker, so we can hand it back across the closure.
			let result: DescendResult<Result<Evidence, WalkLeafErr>> =
				descend_to_value_walker_parts(
					value_walker,
					prefix,
					path,
					self.depth_limit,
					|value_bytes| {
						let mut reader: &[u8] = value_bytes;
						let w = <Value as revision::WalkRevisioned>::walk_revisioned(&mut reader)
							.map_err(|_| WalkLeafErr::Bail)?;
						Ok(evaluator.evaluate(w))
					},
				);
			match result {
				DescendResult::Found(inner) => inner,
				DescendResult::Missing => Err(WalkLeafErr::Missing),
				DescendResult::Bail => Err(WalkLeafErr::Bail),
			}
		})();
		match stream_ev {
			Ok(ev) => ev,
			Err(WalkLeafErr::Missing) => evidence_from_binary_cmp(
				&fallback.op,
				&fallback.literal,
				fallback.reversed,
				&Value::None,
			),
			Err(WalkLeafErr::Bail) => {
				let full: Vec<String> =
					prefix.iter().cloned().chain(path.iter().cloned()).collect();
				self.fallback_leaf_streaming(record_bytes, &full, fallback)
			}
		}
	}

	fn fallback_leaf_streaming(
		&self,
		record_bytes: &[u8],
		full: &[String],
		fallback: &LeafFallback,
	) -> Evidence {
		match extract_field_from_record_bytes(record_bytes, full, self.depth_limit) {
			Extracted::Found(v) => {
				evidence_from_binary_cmp(&fallback.op, &fallback.literal, fallback.reversed, &v)
			}
			Extracted::Missing => evidence_from_binary_cmp(
				&fallback.op,
				&fallback.literal,
				fallback.reversed,
				&Value::None,
			),
			Extracted::Bail => Evidence::Unknown,
		}
	}

	/// Evaluate `field IN set` / `field NOT IN set` using a compile-time [`HashSet`].
	fn eval_set_membership(
		&self,
		record_bytes: &[u8],
		prefix: &[String],
		path: &[String],
		op: &BinaryOperator,
		set: &HashSet<Value>,
	) -> Evidence {
		let v = match extract_field_from_record_bytes_parts(
			record_bytes,
			prefix,
			path,
			self.depth_limit,
		) {
			Extracted::Found(v) => v,
			Extracted::Missing => Value::None,
			Extracted::Bail => return Evidence::Unknown,
		};
		let inside = set.contains(&v);
		match op {
			BinaryOperator::Inside => {
				if inside {
					Evidence::ProvablyTrue
				} else {
					Evidence::ProvablyFalse
				}
			}
			BinaryOperator::NotInside => {
				if inside {
					Evidence::ProvablyFalse
				} else {
					Evidence::ProvablyTrue
				}
			}
			_ => Evidence::Unknown,
		}
	}

	#[allow(clippy::too_many_arguments)]
	fn eval_leaf(
		&self,
		key: &[u8],
		record_bytes: &[u8],
		prefix: &[String],
		path: &[String],
		op: &BinaryOperator,
		literal: &Value,
		reversed: bool,
	) -> Evidence {
		// Fast-path: equality on the synthetic `id` field at the row root —
		// derive the record id straight from the KV key, no decode.
		if prefix.is_empty() && path.len() == 1 && path[0].as_str() == "id" {
			let Ok(k) = RecordKey::decode_key(key) else {
				return Evidence::Unknown;
			};
			let v = Value::RecordId(RecordId {
				table: k.tb.into_owned(),
				key: k.id,
			});
			return evidence_from_binary_cmp(op, literal, reversed, &v);
		}
		// `id.<sub>` at the row root cannot be reliably proved from the
		// encoded value alone — table-level / projection nuances apply.
		if prefix.is_empty() && path.first().is_some_and(|s| s.as_str() == "id") && path.len() > 1 {
			return Evidence::Unknown;
		}
		// Walk the record, descending `prefix` then `path` without
		// concatenating into a fresh `Vec<String>` per row.
		match extract_field_from_record_bytes_parts(record_bytes, prefix, path, self.depth_limit) {
			Extracted::Found(v) => evidence_from_binary_cmp(op, literal, reversed, &v),
			Extracted::Missing => evidence_from_binary_cmp(op, literal, reversed, &Value::None),
			Extracted::Bail => Evidence::Unknown,
		}
	}

	fn eval_fused_flat(
		&self,
		record_bytes: &[u8],
		prefix: &[String],
		clauses: &FusedFlatClauses,
	) -> Evidence {
		if clauses.is_empty() {
			return Evidence::Unknown;
		}
		debug_assert!(
			clauses.windows(2).all(|w| w[0].key_utf8 < w[1].key_utf8),
			"FusedFlatClauses invariant violated",
		);
		// `scan_record_object_at_path_for_keys_sorted` handles both the
		// root-level (empty prefix) and scoped (NavigatePrefix) cases by
		// streaming entries through the walker without materialising the
		// navigated `Value::Object`. The `at_record_root` flag carried on
		// `PredNode::FusedFlatMapAnd` is metadata used by `compile.rs` to
		// classify nested vs root clauses for field-state checks; the
		// evaluator infers anchoring from `prefix` alone.
		match scan_record_object_at_path_for_keys_sorted(
			record_bytes,
			prefix,
			clauses.as_slice(),
			self.depth_limit,
		) {
			ScanResult::Bail => Evidence::Unknown,
			ScanResult::Missing => combine_and(clauses.iter().map(|clause| {
				evidence_from_binary_cmp(&clause.op, &clause.literal, clause.reversed, &Value::None)
			})),
			// `scan_record_object_at_path_for_keys_sorted` always returns a
			// vector positionally aligned with `clauses` (length-aligned, with
			// `Value::None` for keys missing from the encoded object). Treat
			// missing-from-object exactly like missing-from-record above.
			ScanResult::Found(values) => {
				debug_assert_eq!(values.len(), clauses.len());
				combine_and(clauses.iter().zip(values.iter()).map(|(clause, v)| {
					evidence_from_binary_cmp(&clause.op, &clause.literal, clause.reversed, v)
				}))
			}
		}
	}
}

/// Three-state AND of [`Evidence`] values.
///
/// Short-circuits on the first [`Evidence::ProvablyFalse`]. An empty input or any
/// [`Evidence::Unknown`] in the absence of a definite false yields [`Evidence::Unknown`];
/// otherwise [`Evidence::ProvablyTrue`].
fn combine_and<I: IntoIterator<Item = Evidence>>(iter: I) -> Evidence {
	let mut any = false;
	let mut unknown = false;
	for ev in iter {
		any = true;
		match ev {
			Evidence::ProvablyFalse => return Evidence::ProvablyFalse,
			Evidence::Unknown => unknown = true,
			Evidence::ProvablyTrue => {}
		}
	}
	if !any || unknown {
		Evidence::Unknown
	} else {
		Evidence::ProvablyTrue
	}
}

/// Three-state OR of [`Evidence`] values.
///
/// Short-circuits on the first [`Evidence::ProvablyTrue`]. An empty input or any
/// [`Evidence::Unknown`] in the absence of a definite true yields [`Evidence::Unknown`];
/// otherwise [`Evidence::ProvablyFalse`].
fn combine_or<I: IntoIterator<Item = Evidence>>(iter: I) -> Evidence {
	let mut any = false;
	let mut unknown = false;
	for ev in iter {
		any = true;
		match ev {
			Evidence::ProvablyTrue => return Evidence::ProvablyTrue,
			Evidence::Unknown => unknown = true,
			Evidence::ProvablyFalse => {}
		}
	}
	if !any || unknown {
		Evidence::Unknown
	} else {
		Evidence::ProvablyFalse
	}
}

fn evidence_from_binary_cmp(
	op: &BinaryOperator,
	literal: &Value,
	reversed: bool,
	v: &Value,
) -> Evidence {
	let (left, right) = if reversed {
		(literal, v)
	} else {
		(v, literal)
	};
	match apply_binary(op, left, right) {
		Some(Value::Bool(false)) => Evidence::ProvablyFalse,
		Some(Value::Bool(true)) => Evidence::ProvablyTrue,
		Some(_) | None => Evidence::Unknown,
	}
}

fn apply_binary(op: &BinaryOperator, left: &Value, right: &Value) -> Option<Value> {
	use BinaryOperator::*;
	match op {
		Equal => operate::equal(left, right).ok(),
		ExactEqual => operate::exact(left, right).ok(),
		NotEqual => operate::not_equal(left, right).ok(),
		LessThan => operate::less_than(left, right).ok(),
		LessThanEqual => operate::less_than_or_equal(left, right).ok(),
		MoreThan => operate::more_than(left, right).ok(),
		MoreThanEqual => operate::more_than_or_equal(left, right).ok(),
		Contain => operate::contain(left, right).ok(),
		NotContain => operate::not_contain(left, right).ok(),
		ContainAll => operate::contain_all(left, right).ok(),
		ContainAny => operate::contain_any(left, right).ok(),
		ContainNone => operate::contain_none(left, right).ok(),
		Inside => operate::inside(left, right).ok(),
		NotInside => operate::not_inside(left, right).ok(),
		AllInside => operate::inside_all(left, right).ok(),
		AnyInside => operate::inside_any(left, right).ok(),
		NoneInside => operate::inside_none(left, right).ok(),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use std::collections::{BTreeMap, HashSet};
	use std::sync::Arc;

	use memchr::memmem;
	use revision::{Revisioned, SerializeRevisioned};
	use surrealdb_strand::Strand;

	use super::streaming::{
		ArrayElementContains, ArrayOverlapsLiteralSet, OverlapMode, SubstringMatch,
		overlap_streaming_from_set,
	};
	use super::{
		FusedFlatClause, FusedFlatClauses, LeafFallback, PreDecodeFilter, PreDecodeFilterOutcome,
		PredNode,
	};
	use crate::catalog::Record;
	use crate::expr::operator::BinaryOperator;
	use crate::val::{Number, Object, Value};

	/// Depth limit used in test fixtures. Matches the default
	/// `ctx.config.idiom_recursion_limit` (256) so test behaviour reflects
	/// the production planner's wiring.
	const TEST_DEPTH_LIMIT: u32 = 256;

	fn wire_record_plain_object(obj: Object) -> Vec<u8> {
		let val = Value::Object(obj);
		let mut vb = Vec::new();
		val.serialize_revisioned(&mut vb).unwrap();
		let payload = vb;
		let mut out = Vec::new();
		Record::revision().serialize_revisioned(&mut out).unwrap();
		0u8.serialize_revisioned(&mut out).unwrap();
		out.extend_from_slice(&payload);
		out
	}

	#[test]
	fn empty_and_never_rejects() {
		let pf = PreDecodeFilter::new(PredNode::And(Vec::new()), TEST_DEPTH_LIMIT);
		let rec = wire_record_plain_object(Object::default());
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::NeedFullDecode);
	}

	#[test]
	fn leaf_eq_false_rejects_row() {
		let root = PredNode::Leaf {
			path: vec!["a".into()],
			op: BinaryOperator::Equal,
			literal: Value::Number(Number::Int(1)),
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(2)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_set_membership_hits_returns_need_full_decode_for_inside() {
		let set = Arc::new(HashSet::from([Value::Number(Number::Int(1))]));
		let root = PredNode::LeafSetMembership {
			path: vec!["a".into()],
			op: BinaryOperator::Inside,
			set,
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(1)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::NeedFullDecode);
	}

	#[test]
	fn eval_set_membership_misses_returns_reject_for_inside() {
		let set = Arc::new(HashSet::from([Value::Number(Number::Int(1))]));
		let root = PredNode::LeafSetMembership {
			path: vec!["a".into()],
			op: BinaryOperator::Inside,
			set,
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(99)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_set_membership_inverts_for_not_inside() {
		let set = Arc::new(HashSet::from([Value::Number(Number::Int(1))]));
		let root = PredNode::LeafSetMembership {
			path: vec!["a".into()],
			op: BinaryOperator::NotInside,
			set,
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(1)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_set_membership_missing_field_treated_as_value_none() {
		let set = Arc::new(HashSet::from([Value::Number(Number::Int(1))]));
		let root = PredNode::LeafSetMembership {
			path: vec!["missing".into()],
			op: BinaryOperator::Inside,
			set,
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(2)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_set_membership_empty_set_rejects_every_row_for_inside() {
		let set = Arc::new(HashSet::<Value>::new());
		let root = PredNode::LeafSetMembership {
			path: vec!["a".into()],
			op: BinaryOperator::Inside,
			set,
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(5)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_contains_substring_provably_false_via_apply_binary() {
		let root = PredNode::Leaf {
			path: vec!["msg".into()],
			op: BinaryOperator::Contain,
			literal: Value::String("needle".into()),
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("msg"), Value::String("hello".into()))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_contains_any_negative_rejects() {
		let root = PredNode::Leaf {
			path: vec!["tags".into()],
			op: BinaryOperator::ContainAny,
			literal: Value::from(vec![Value::String("x".into()), Value::String("y".into())]),
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj = Object::from(BTreeMap::from([(
			Strand::from("tags"),
			Value::from(vec![Value::String("a".into()), Value::String("b".into())]),
		)]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_not_inside_via_prednode_not_inverts() {
		let set = Arc::new(HashSet::from([Value::Number(Number::Int(1))]));
		let inner = PredNode::LeafSetMembership {
			path: vec!["a".into()],
			op: BinaryOperator::Inside,
			set,
			reversed: false,
		};
		let root = PredNode::Not(Box::new(inner));
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(1)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn eval_anyinside_via_apply_binary() {
		let root = PredNode::Leaf {
			path: vec!["arr".into()],
			op: BinaryOperator::AnyInside,
			literal: Value::from(vec![
				Value::Number(Number::Int(1)),
				Value::Number(Number::Int(2)),
			]),
			reversed: false,
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj = Object::from(BTreeMap::from([(
			Strand::from("arr"),
			Value::from(vec![Value::Number(Number::Int(3))]),
		)]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn navigate_id_segment_forces_full_decode() {
		let root = PredNode::NavigatePrefix {
			segment: "id".into(),
			child: Box::new(PredNode::Leaf {
				path: vec!["x".into()],
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(1)),
				reversed: false,
			}),
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(2)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::NeedFullDecode);
	}

	/// Navigate through a missing intermediate field: descendant leaf reads as `Value::None`,
	/// so `outer.x = 1` is provably false on a row where `outer` itself is absent.
	#[test]
	fn scoped_missing_intermediate_makes_descendant_leaf_provably_false() {
		let root = PredNode::NavigatePrefix {
			segment: "outer".into(),
			child: Box::new(PredNode::Leaf {
				path: vec!["x".into()],
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(1)),
				reversed: false,
			}),
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		// Record has no `outer` key.
		let obj =
			Object::from(BTreeMap::from([(Strand::from("other"), Value::Number(Number::Int(2)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	/// `FusedFlatMapAnd` over a missing scope: each clause reads `Value::None`. With at least
	/// one clause that compares unequal to `None`, the whole AND is provably false.
	#[test]
	fn scoped_missing_intermediate_makes_fused_clauses_provably_false() {
		let inner = FusedFlatClauses::try_new(vec![
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(1)),
				reversed: false,
			},
			FusedFlatClause {
				key_utf8: b"b".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(2)),
				reversed: false,
			},
		])
		.expect("sorted unique");
		let root = PredNode::NavigatePrefix {
			segment: "outer".into(),
			child: Box::new(PredNode::FusedFlatMapAnd {
				at_record_root: false,
				clauses: inner,
			}),
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		// Record has no `outer` key.
		let obj =
			Object::from(BTreeMap::from([(Strand::from("z"), Value::Number(Number::Int(99)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	/// Two-level nested fusion (`outer.inner.{a,b}`): walk through both prefixes, then evaluate
	/// the fused map at the deepest object. A row whose deepest leaf disagrees with one clause
	/// is rejected.
	#[test]
	fn scoped_two_level_nested_fused_rejects_mismatched_inner() {
		let inner_clauses = FusedFlatClauses::try_new(vec![
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(1)),
				reversed: false,
			},
			FusedFlatClause {
				key_utf8: b"b".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(2)),
				reversed: false,
			},
		])
		.expect("sorted unique");
		let root = PredNode::NavigatePrefix {
			segment: "outer".into(),
			child: Box::new(PredNode::NavigatePrefix {
				segment: "inner".into(),
				child: Box::new(PredNode::FusedFlatMapAnd {
					at_record_root: false,
					clauses: inner_clauses,
				}),
			}),
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		// {outer: {inner: {a: 1, b: 99}}} — clause `b == 2` is provably false.
		let inner = Object::from(BTreeMap::from([
			(Strand::from("a"), Value::Number(Number::Int(1))),
			(Strand::from("b"), Value::Number(Number::Int(99))),
		]));
		let middle = Object::from(BTreeMap::from([(Strand::from("inner"), Value::Object(inner))]));
		let outer = Object::from(BTreeMap::from([(Strand::from("outer"), Value::Object(middle))]));
		let rec = wire_record_plain_object(outer);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	/// Same shape as above but the row matches both clauses — pre-decode filter cannot prove
	/// false, so the row must be passed through to full decode.
	#[test]
	fn scoped_two_level_nested_fused_passes_matching_inner() {
		let inner_clauses = FusedFlatClauses::try_new(vec![
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(1)),
				reversed: false,
			},
			FusedFlatClause {
				key_utf8: b"b".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(2)),
				reversed: false,
			},
		])
		.expect("sorted unique");
		let root = PredNode::NavigatePrefix {
			segment: "outer".into(),
			child: Box::new(PredNode::NavigatePrefix {
				segment: "inner".into(),
				child: Box::new(PredNode::FusedFlatMapAnd {
					at_record_root: false,
					clauses: inner_clauses,
				}),
			}),
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let inner = Object::from(BTreeMap::from([
			(Strand::from("a"), Value::Number(Number::Int(1))),
			(Strand::from("b"), Value::Number(Number::Int(2))),
		]));
		let middle = Object::from(BTreeMap::from([(Strand::from("inner"), Value::Object(inner))]));
		let outer = Object::from(BTreeMap::from([(Strand::from("outer"), Value::Object(middle))]));
		let rec = wire_record_plain_object(outer);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::NeedFullDecode);
	}

	/// `FusedFlatClauses::try_new` rejects out-of-order keys.
	#[test]
	fn fused_flat_clauses_try_new_rejects_unsorted() {
		let bad = vec![
			FusedFlatClause {
				key_utf8: b"b".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::None,
				reversed: false,
			},
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::None,
				reversed: false,
			},
		];
		assert!(FusedFlatClauses::try_new(bad).is_none());
	}

	/// `FusedFlatClauses::try_new` rejects duplicate keys.
	#[test]
	fn fused_flat_clauses_try_new_rejects_duplicates() {
		let dup = vec![
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::None,
				reversed: false,
			},
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::None,
				reversed: false,
			},
		];
		assert!(FusedFlatClauses::try_new(dup).is_none());
	}

	#[test]
	fn streaming_substring_rejects_when_needle_absent() {
		let lit = Value::String("needle".into());
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(SubstringMatch {
			finder: memmem::Finder::new(b"needle").into_owned(),
			negated: false,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["msg".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::Contain,
				literal: lit,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("msg"), Value::String("hello".into()))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn streaming_substring_unknown_on_non_string_leaf_needs_decode() {
		let lit = Value::String("x".into());
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(SubstringMatch {
			finder: memmem::Finder::new(b"x").into_owned(),
			negated: false,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["n".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::Contain,
				literal: lit,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("n"), Value::Number(Number::Int(1)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::NeedFullDecode);
	}

	#[test]
	fn streaming_array_contains_rejects_on_miss() {
		let needle = Value::Number(Number::Int(99));
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(ArrayElementContains {
			needle: Arc::new(needle.clone()),
			negated: false,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["tags".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::Contain,
				literal: needle,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj = Object::from(BTreeMap::from([(
			Strand::from("tags"),
			Value::from(vec![Value::Number(Number::Int(1)), Value::Number(Number::Int(2))]),
		)]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn streaming_array_containsany_rejects_when_no_overlap() {
		let lit = Value::from(vec![Value::String("x".into()), Value::String("y".into())]);
		let set = Arc::new(HashSet::from([Value::String("x".into()), Value::String("y".into())]));
		let literal_to_idx = overlap_streaming_from_set(set.as_ref());
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(ArrayOverlapsLiteralSet {
			literal_to_idx,
			mode: OverlapMode::Any,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["tags".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::ContainAny,
				literal: lit,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj = Object::from(BTreeMap::from([(
			Strand::from("tags"),
			Value::from(vec![Value::String("a".into()), Value::String("b".into())]),
		)]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn streaming_array_containsall_rejects_when_mask_incomplete() {
		let lit = Value::from(vec![Value::Number(Number::Int(1)), Value::Number(Number::Int(2))]);
		let set =
			Arc::new(HashSet::from([Value::Number(Number::Int(1)), Value::Number(Number::Int(2))]));
		let literal_to_idx = overlap_streaming_from_set(set.as_ref());
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(ArrayOverlapsLiteralSet {
			literal_to_idx,
			mode: OverlapMode::All,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["a".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::ContainAll,
				literal: lit,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj = Object::from(BTreeMap::from([(
			Strand::from("a"),
			Value::from(vec![Value::Number(Number::Int(1))]),
		)]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn streaming_array_containsnone_rejects_on_first_hit() {
		let lit = Value::from(vec![Value::String("a".into()), Value::String("b".into())]);
		let set = Arc::new(HashSet::from([Value::String("a".into()), Value::String("b".into())]));
		let literal_to_idx = overlap_streaming_from_set(set.as_ref());
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(ArrayOverlapsLiteralSet {
			literal_to_idx,
			mode: OverlapMode::None,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["tags".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::ContainNone,
				literal: lit,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj = Object::from(BTreeMap::from([(
			Strand::from("tags"),
			Value::from(vec![Value::String("a".into()), Value::String("z".into())]),
		)]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	#[test]
	fn streaming_missing_field_substring_contain_is_false_on_none() {
		let lit = Value::String("hi".into());
		let eval: Arc<dyn super::StreamingLeafEvaluator> = Arc::new(SubstringMatch {
			finder: memmem::Finder::new(b"hi").into_owned(),
			negated: false,
		});
		let root = PredNode::LeafStreaming {
			path: vec!["missing".into()],
			evaluator: eval,
			fallback: LeafFallback {
				op: BinaryOperator::Contain,
				literal: lit,
				reversed: false,
			},
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		let obj =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(2)))]));
		let rec = wire_record_plain_object(obj);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	/// Regression: an `outer` object that exists but is missing some of the
	/// fused needles must still be evaluated as if the missing keys read
	/// `Value::None`, so a row like `{outer: {a: 1}}` is rejected by the
	/// predicate `outer.a = 1 AND outer.b = 2` rather than falling through
	/// to full decode.
	#[test]
	fn scoped_partial_object_with_missing_inner_keys_rejects() {
		let clauses = FusedFlatClauses::try_new(vec![
			FusedFlatClause {
				key_utf8: b"a".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(1)),
				reversed: false,
			},
			FusedFlatClause {
				key_utf8: b"b".to_vec(),
				op: BinaryOperator::Equal,
				literal: Value::Number(Number::Int(2)),
				reversed: false,
			},
		])
		.expect("sorted unique");
		let root = PredNode::NavigatePrefix {
			segment: "outer".into(),
			child: Box::new(PredNode::FusedFlatMapAnd {
				at_record_root: false,
				clauses,
			}),
		};
		let pf = PreDecodeFilter::new(root, TEST_DEPTH_LIMIT);
		// `outer` is present and is an object, but only carries `a`; `b` is
		// absent. The fused evaluator should treat `b` as `Value::None`,
		// reduce the AND to ProvablyFalse, and reject the row.
		let inner =
			Object::from(BTreeMap::from([(Strand::from("a"), Value::Number(Number::Int(1)))]));
		let outer = Object::from(BTreeMap::from([(Strand::from("outer"), Value::Object(inner))]));
		let rec = wire_record_plain_object(outer);
		assert_eq!(pf.apply(&[], &rec), PreDecodeFilterOutcome::Reject);
	}

	/// Exhaustiveness check for [`PreDecodeFilterStatus::explain_text`]: every
	/// `Ineligible` reason variant must produce an `EXPLAIN` string. Adding a
	/// new variant breaks the inner `match`, which forces the implementer to
	/// also extend `explain_text` and the corresponding language tests.
	#[test]
	fn explain_text_covers_every_ineligible_reason() {
		use super::{PreDecodeFilterReason, PreDecodeFilterStatus};

		fn all_reasons() -> impl IntoIterator<Item = PreDecodeFilterReason> {
			// Adding a new variant fails to compile here, prompting a fix.
			let probe: [PreDecodeFilterReason; 3] = [
				PreDecodeFilterReason::UnsupportedPredicate,
				PreDecodeFilterReason::ComputedFields,
				PreDecodeFilterReason::FieldPermissions,
			];
			for r in probe.iter() {
				match r {
					PreDecodeFilterReason::UnsupportedPredicate
					| PreDecodeFilterReason::ComputedFields
					| PreDecodeFilterReason::FieldPermissions => {}
				}
			}
			probe
		}

		for reason in all_reasons() {
			let status = PreDecodeFilterStatus::Ineligible(reason);
			assert!(
				status.explain_text().is_some(),
				"PreDecodeFilterStatus::Ineligible({:?}).explain_text() returned None",
				reason
			);
		}
		assert!(PreDecodeFilterStatus::NotApplicable.explain_text().is_none());
	}
}
