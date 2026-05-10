//! Zero-copy and streaming leaf evaluators for the pre-decode filter.
//!
//! [`SubstringMatch`] peeks UTF-8 bytes via [`revision::LeafWalker::with_bytes`] and uses
//! [`memchr::memmem::Finder`] — no `Strand` allocation on the hot path.
//!
//! Array walkers decode **one element at a time**; nested compound elements may still allocate
//! per element, but memory stays bounded by the literal set / needle, not the full array size.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use memchr::memmem;
use revision::WalkRevisioned;

use super::Evidence;
use crate::val::Value;

/// Walker for a [`Value`] backed by a byte slice (KV record bytes).
pub(crate) type ValueWalker<'r> = <Value as WalkRevisioned>::Walker<'r, &'r [u8]>;

/// Streaming evaluation of a leaf predicate without building the full [`Value`].
pub(crate) trait StreamingLeafEvaluator: std::fmt::Debug + Send + Sync {
	/// Inspect `leaf` and return partial truth for this row.
	fn evaluate(&self, leaf: ValueWalker<'_>) -> Evidence;
}

/// [`BinaryOperator::Contain`] / [`BinaryOperator::NotContain`] on a string leaf with a literal
/// substring, using substring search over wire UTF-8 bytes only.
///
/// **Allocations:** none on the hot path; the [`memmem::Finder`] is built once at compile time.
#[derive(Debug)]
pub(crate) struct SubstringMatch {
	/// Precomputed substring searcher for the needle (owns needle bytes).
	pub(crate) finder: memmem::Finder<'static>,
	pub(crate) negated: bool,
}

impl StreamingLeafEvaluator for SubstringMatch {
	fn evaluate(&self, leaf: ValueWalker<'_>) -> Evidence {
		if !leaf.is_string() {
			return Evidence::Unknown;
		}
		let Ok(strand_walker) = leaf.into_string() else {
			return Evidence::Unknown;
		};
		let Ok(hit) = strand_walker.with_bytes(|s| self.finder.find(s).is_some()) else {
			return Evidence::Unknown;
		};
		let truth = hit ^ self.negated;
		if truth {
			Evidence::ProvablyTrue
		} else {
			Evidence::ProvablyFalse
		}
	}
}

/// [`BinaryOperator::Contain`] / [`BinaryOperator::NotContain`] on an array leaf: decode elements
/// one at a time and compare with [`Value::eq`] against `needle`.
///
/// **Allocations:** at most one decoded element at a time; nested values follow ordinary decode
/// cost.
#[derive(Debug)]
pub(crate) struct ArrayElementContains {
	pub(crate) needle: Arc<Value>,
	pub(crate) negated: bool,
}

impl StreamingLeafEvaluator for ArrayElementContains {
	fn evaluate(&self, leaf: ValueWalker<'_>) -> Evidence {
		if !leaf.is_array() {
			return Evidence::Unknown;
		}
		let Ok(array_walker) = leaf.into_array() else {
			return Evidence::Unknown;
		};
		let Ok(mut seq) = array_walker.into_walk_field_0() else {
			return Evidence::Unknown;
		};
		while let Some(item) = seq.next_item() {
			let Ok(elem) = item.decode() else {
				return Evidence::Unknown;
			};
			if elem == *self.needle.as_ref() {
				let truth = !self.negated;
				return if truth {
					Evidence::ProvablyTrue
				} else {
					Evidence::ProvablyFalse
				};
			}
		}
		let truth = self.negated;
		if truth {
			Evidence::ProvablyTrue
		} else {
			Evidence::ProvablyFalse
		}
	}
}

/// How [`ArrayOverlapsLiteralSet`] combines membership hits across streamed elements.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum OverlapMode {
	/// [`BinaryOperator::ContainAny`]
	Any,
	/// [`BinaryOperator::ContainNone`]
	None,
	/// [`BinaryOperator::ContainAll`]
	All,
}

/// Cap on literals covered by a stack-allocated bitmask (`64 * STACK_MASK_WORDS` bits).
const STACK_MASK_WORDS: usize = 8;

/// [`BinaryOperator::ContainAny`] / [`ContainNone`](BinaryOperator::ContainNone) /
/// [`ContainAll`](BinaryOperator::ContainAll) with a literal set, streaming array elements.
///
/// **Allocations:** one decoded element at a time; `All` uses a small on-stack bitmask when the
/// literal count is ≤ `64 * STACK_MASK_WORDS`, otherwise one `Vec<u64>` per evaluation.
#[derive(Debug)]
pub(crate) struct ArrayOverlapsLiteralSet {
	/// Literal value → stable bit index for [`OverlapMode::All`].
	pub(crate) literal_to_idx: Arc<HashMap<Value, usize>>,
	pub(crate) mode: OverlapMode,
}

impl ArrayOverlapsLiteralSet {
	fn all_bits_set(mask: &[u64], bit_count: usize) -> bool {
		let full = bit_count / 64;
		for i in 0..full {
			if mask.get(i).copied().unwrap_or(0) != u64::MAX {
				return false;
			}
		}
		let rem = bit_count % 64;
		if rem == 0 {
			return true;
		}
		let last = mask.get(full).copied().unwrap_or(0);
		last == (1u64 << rem) - 1
	}
}

impl StreamingLeafEvaluator for ArrayOverlapsLiteralSet {
	fn evaluate(&self, leaf: ValueWalker<'_>) -> Evidence {
		let n_lit = self.literal_to_idx.len();
		if n_lit == 0 {
			return match self.mode {
				OverlapMode::Any => Evidence::ProvablyFalse,
				OverlapMode::None | OverlapMode::All => Evidence::ProvablyTrue,
			};
		}
		if !leaf.is_array() {
			return Evidence::Unknown;
		}
		let Ok(array_walker) = leaf.into_array() else {
			return Evidence::Unknown;
		};
		let Ok(mut seq) = array_walker.into_walk_field_0() else {
			return Evidence::Unknown;
		};
		let n_words = n_lit.div_ceil(64);
		match self.mode {
			OverlapMode::Any => {
				while let Some(item) = seq.next_item() {
					let Ok(elem) = item.decode() else {
						return Evidence::Unknown;
					};
					if self.literal_to_idx.contains_key(&elem) {
						return Evidence::ProvablyTrue;
					}
				}
				Evidence::ProvablyFalse
			}
			OverlapMode::None => {
				while let Some(item) = seq.next_item() {
					let Ok(elem) = item.decode() else {
						return Evidence::Unknown;
					};
					if self.literal_to_idx.contains_key(&elem) {
						return Evidence::ProvablyFalse;
					}
				}
				Evidence::ProvablyTrue
			}
			OverlapMode::All => {
				let mut stack_mask = [0u64; STACK_MASK_WORDS];
				let mut heap_mask: Vec<u64> = Vec::new();
				let mask: &mut [u64] = if n_words <= STACK_MASK_WORDS {
					&mut stack_mask[..n_words]
				} else {
					heap_mask.resize(n_words, 0);
					heap_mask.as_mut_slice()
				};
				while let Some(item) = seq.next_item() {
					let Ok(elem) = item.decode() else {
						return Evidence::Unknown;
					};
					let Some(&idx) = self.literal_to_idx.get(&elem) else {
						continue;
					};
					mask[idx / 64] |= 1u64 << (idx % 64);
					if Self::all_bits_set(mask, n_lit) {
						return Evidence::ProvablyTrue;
					}
				}
				if Self::all_bits_set(mask, n_lit) {
					Evidence::ProvablyTrue
				} else {
					Evidence::ProvablyFalse
				}
			}
		}
	}
}

/// Build a value → bit-index map from a hash-set literal (array / set RHS).
pub(crate) fn overlap_streaming_from_set(set: &HashSet<Value>) -> Arc<HashMap<Value, usize>> {
	let mut map = HashMap::with_capacity(set.len());
	for (i, v) in set.iter().enumerate() {
		map.insert(v.clone(), i);
	}
	Arc::new(map)
}
