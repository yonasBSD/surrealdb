//! In-memory cache for KV-backed DiskANN graph data.
//!
//! DiskANN search repeatedly touches a small working set of graph state, element vectors, and
//! adjacency lists. The persisted KV layout remains the source of truth, while this cache reduces
//! point-read latency and lets the provider batch only the entries that missed in memory.

use std::sync::Arc;

use dashmap::{DashMap, Entry};
use parking_lot::RwLock;
use quick_cache::sync::Cache;
use quick_cache::{DefaultHashBuilder, Lifecycle, Weighter};
use roaring::RoaringTreemap;

use crate::catalog::{DatabaseId, IndexId, NamespaceId, TableId};
use crate::idx::seqdocids::DocId;
use crate::idx::trees::diskann::{DiskAnnElement, DiskAnnNode, DiskAnnState, ElementId};
use crate::idx::trees::knn::Ids64;
use crate::idx::trees::vector::SerializedVector;
use crate::val::RecordIdKey;

type IndexKey = (NamespaceId, DatabaseId, TableId, IndexId);
type ElementCacheKey = (NamespaceId, DatabaseId, TableId, IndexId, ElementId);
type NodeCacheKey = ElementCacheKey;
type DocSetCacheKey = ElementCacheKey;
type DocIdCacheKey = (NamespaceId, DatabaseId, TableId, IndexId, DocId);

#[derive(Clone)]
struct CachedDocId {
	/// Pending generation observed when this doc-id mapping was read from KV.
	generation: Option<u64>,
	/// Record key stored under the `!dd` document-id mapping.
	id: Arc<RecordIdKey>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
enum DiskAnnCacheKey {
	Element(ElementCacheKey),
	Node(NodeCacheKey),
	DocSet(DocSetCacheKey),
	DocId(DocIdCacheKey),
	State(IndexKey),
}

#[derive(Clone)]
enum DiskAnnCacheValue {
	Element(Arc<DiskAnnElement>),
	Node(Arc<DiskAnnNode>),
	DocSet(Ids64),
	DocId(CachedDocId),
	State(DiskAnnState),
}

/// Tracks cached element ids per index so index removal can evict targeted entries without
/// scanning every cache key.
#[derive(Clone, Default)]
struct IdsPerIndex(Arc<DashMap<IndexKey, RwLock<RoaringTreemap>>>);

impl IdsPerIndex {
	fn insert(&self, index: IndexKey, id: ElementId) {
		self.0.entry(index).or_default().write().insert(id);
	}

	fn remove_index(&self, index: IndexKey) -> Option<RwLock<RoaringTreemap>> {
		self.0.remove(&index).map(|entry| entry.1)
	}

	fn remove_id(&self, index: IndexKey, id: ElementId) {
		if let Entry::Occupied(mut entry) = self.0.entry(index) {
			let is_empty = {
				let mut ids = entry.get_mut().write();
				ids.remove(id);
				ids.is_empty()
			};
			if is_empty {
				entry.remove_entry();
			}
		}
	}

	fn evict_id(&self, key: ElementCacheKey) {
		if let Entry::Occupied(mut entry) = self.0.entry((key.0, key.1, key.2, key.3)) {
			entry.get_mut().write().remove(key.4);
		}
	}

	#[cfg(test)]
	fn len(&self, index: IndexKey) -> u64 {
		self.0.get(&index).map(|ids| ids.read().len()).unwrap_or_default()
	}
}

#[derive(Clone)]
struct DiskAnnCacheLifecycle {
	element_indexes: IdsPerIndex,
	node_indexes: IdsPerIndex,
	doc_set_indexes: IdsPerIndex,
	doc_id_indexes: IdsPerIndex,
}

impl Lifecycle<DiskAnnCacheKey, DiskAnnCacheValue> for DiskAnnCacheLifecycle {
	type RequestState = ();

	fn begin_request(&self) -> Self::RequestState {}

	fn on_evict(&self, _: &mut Self::RequestState, key: DiskAnnCacheKey, _: DiskAnnCacheValue) {
		match key {
			DiskAnnCacheKey::Element(key) => self.element_indexes.evict_id(key),
			DiskAnnCacheKey::Node(key) => self.node_indexes.evict_id(key),
			DiskAnnCacheKey::DocSet(key) => self.doc_set_indexes.evict_id(key),
			DiskAnnCacheKey::DocId(key) => self.doc_id_indexes.evict_id(key),
			DiskAnnCacheKey::State(_) => {}
		}
	}
}

#[derive(Clone)]
struct DiskAnnCacheWeighter;

impl Weighter<DiskAnnCacheKey, DiskAnnCacheValue> for DiskAnnCacheWeighter {
	fn weight(&self, key: &DiskAnnCacheKey, val: &DiskAnnCacheValue) -> u64 {
		match (key, val) {
			(DiskAnnCacheKey::Element(key), DiskAnnCacheValue::Element(val)) => {
				(serialized_vector_size(&val.vector)
					+ std::mem::size_of_val(&val.deleted)
					+ std::mem::size_of::<Arc<DiskAnnElement>>()
					+ std::mem::size_of_val(key)) as u64
			}
			(DiskAnnCacheKey::Node(key), DiskAnnCacheValue::Node(val)) => {
				(val.neighbors.len() * std::mem::size_of::<ElementId>()
					+ std::mem::size_of::<Arc<DiskAnnNode>>()
					+ std::mem::size_of_val(key)) as u64
			}
			(DiskAnnCacheKey::DocSet(key), DiskAnnCacheValue::DocSet(val)) => {
				(val.iter().count() * std::mem::size_of::<u64>() + std::mem::size_of_val(key))
					as u64
			}
			(DiskAnnCacheKey::DocId(key), DiskAnnCacheValue::DocId(val)) => {
				(std::mem::size_of_val(key)
					+ std::mem::size_of_val(&val.generation)
					+ std::mem::size_of::<Arc<RecordIdKey>>()
					+ std::mem::size_of_val(val.id.as_ref())) as u64
			}
			(DiskAnnCacheKey::State(key), DiskAnnCacheValue::State(val)) => {
				(std::mem::size_of_val(key) + std::mem::size_of_val(val)) as u64
			}
			_ => unreachable!("mismatched DiskANN cache key/value"),
		}
	}
}

/// Shared weighted cache for one process' DiskANN graph data.
///
/// The cache is scoped by namespace, database, table, and index id. Element vectors (`De` keys),
/// adjacency lists (`Dn` keys), graph state (`Ds` key), and document mappings share one weighted
/// budget. Per-index membership sets let index removal evict exactly its hot graph data.
#[derive(Clone)]
pub(crate) struct DiskAnnCache(Arc<Inner>);

struct Inner {
	/// Shared weighted budget for all DiskANN cache families.
	cache: Cache<
		DiskAnnCacheKey,
		DiskAnnCacheValue,
		DiskAnnCacheWeighter,
		DefaultHashBuilder,
		DiskAnnCacheLifecycle,
	>,
	/// Element IDs currently present in the element cache, grouped by index.
	element_indexes: IdsPerIndex,
	/// Element IDs currently present in the node cache, grouped by index.
	node_indexes: IdsPerIndex,
	/// Element IDs currently present in the doc-set cache, grouped by index.
	doc_set_indexes: IdsPerIndex,
	/// Document IDs currently present in the doc-id cache, grouped by index.
	doc_id_indexes: IdsPerIndex,
}

impl DiskAnnCache {
	/// Creates a DiskANN ANN cache with one shared weight capacity (in bytes).
	pub(crate) fn new(cache_size: u64) -> Self {
		let element_indexes = IdsPerIndex::default();
		let node_indexes = IdsPerIndex::default();
		let doc_set_indexes = IdsPerIndex::default();
		let doc_id_indexes = IdsPerIndex::default();
		let lifecycle = DiskAnnCacheLifecycle {
			element_indexes: element_indexes.clone(),
			node_indexes: node_indexes.clone(),
			doc_set_indexes: doc_set_indexes.clone(),
			doc_id_indexes: doc_id_indexes.clone(),
		};
		let estimated_items = (cache_size / 256).max(1) as usize;
		Self(Arc::new(Inner {
			cache: Cache::with(
				estimated_items,
				cache_size,
				DiskAnnCacheWeighter,
				DefaultHashBuilder::default(),
				lifecycle,
			),
			element_indexes,
			node_indexes,
			doc_set_indexes,
			doc_id_indexes,
		}))
	}

	fn index_key(
		namespace_id: NamespaceId,
		database_id: DatabaseId,
		table_id: TableId,
		index_id: IndexId,
	) -> IndexKey {
		(namespace_id, database_id, table_id, index_id)
	}

	fn element_key(index: IndexKey, element_id: ElementId) -> ElementCacheKey {
		(index.0, index.1, index.2, index.3, element_id)
	}

	fn doc_id_key(index: IndexKey, doc_id: DocId) -> DocIdCacheKey {
		(index.0, index.1, index.2, index.3, doc_id)
	}

	/// Returns cached graph state for one index.
	pub(super) fn get_state(&self, index: IndexKey) -> Option<DiskAnnState> {
		match self.0.cache.get(&DiskAnnCacheKey::State(index)) {
			Some(DiskAnnCacheValue::State(state)) => Some(state),
			_ => None,
		}
	}

	/// Inserts or replaces cached graph state for one index.
	pub(super) fn insert_state(&self, index: IndexKey, state: DiskAnnState) {
		self.0.cache.insert(DiskAnnCacheKey::State(index), DiskAnnCacheValue::State(state));
	}

	/// Returns a shared cached graph element payload.
	pub(super) fn get_element(
		&self,
		index: IndexKey,
		element_id: ElementId,
	) -> Option<Arc<DiskAnnElement>> {
		match self.0.cache.get(&DiskAnnCacheKey::Element(Self::element_key(index, element_id))) {
			Some(DiskAnnCacheValue::Element(element)) => Some(element),
			_ => None,
		}
	}

	/// Inserts a persisted graph element and returns the shared cached payload.
	pub(super) fn insert_element(
		&self,
		index: IndexKey,
		element_id: ElementId,
		element: DiskAnnElement,
	) -> Arc<DiskAnnElement> {
		// Track membership before insertion so an immediate quick_cache eviction can clean up the
		// same per-index set through the lifecycle hook.
		let element = Arc::new(element);
		self.0.element_indexes.insert(index, element_id);
		self.0.cache.insert(
			DiskAnnCacheKey::Element(Self::element_key(index, element_id)),
			DiskAnnCacheValue::Element(Arc::clone(&element)),
		);
		element
	}

	/// Evicts one graph element from the cache.
	pub(super) fn remove_element(&self, index: IndexKey, element_id: ElementId) {
		self.0.element_indexes.remove_id(index, element_id);
		self.0.cache.remove(&DiskAnnCacheKey::Element(Self::element_key(index, element_id)));
	}

	/// Returns a shared cached adjacency-list payload.
	pub(super) fn get_node(
		&self,
		index: IndexKey,
		element_id: ElementId,
	) -> Option<Arc<DiskAnnNode>> {
		match self.0.cache.get(&DiskAnnCacheKey::Node(Self::element_key(index, element_id))) {
			Some(DiskAnnCacheValue::Node(node)) => Some(node),
			_ => None,
		}
	}

	/// Inserts a persisted adjacency list and returns the shared cached payload.
	pub(super) fn insert_node(
		&self,
		index: IndexKey,
		element_id: ElementId,
		node: DiskAnnNode,
	) -> Arc<DiskAnnNode> {
		// Keep the per-index set in step with quick_cache for efficient index-level eviction.
		let node = Arc::new(node);
		self.0.node_indexes.insert(index, element_id);
		self.0.cache.insert(
			DiskAnnCacheKey::Node(Self::element_key(index, element_id)),
			DiskAnnCacheValue::Node(Arc::clone(&node)),
		);
		node
	}

	#[cfg(test)]
	fn remove_node(&self, index: IndexKey, element_id: ElementId) {
		self.0.node_indexes.remove_id(index, element_id);
		self.0.cache.remove(&DiskAnnCacheKey::Node(Self::element_key(index, element_id)));
	}

	/// Returns a cached set of compact document IDs for one graph element.
	pub(super) fn get_doc_set(&self, index: IndexKey, element_id: ElementId) -> Option<Ids64> {
		match self.0.cache.get(&DiskAnnCacheKey::DocSet(Self::element_key(index, element_id))) {
			Some(DiskAnnCacheValue::DocSet(docs)) => Some(docs),
			_ => None,
		}
	}

	/// Inserts the compact document IDs represented by one graph element.
	pub(super) fn insert_doc_set(&self, index: IndexKey, element_id: ElementId, docs: Ids64) {
		self.0.doc_set_indexes.insert(index, element_id);
		self.0.cache.insert(
			DiskAnnCacheKey::DocSet(Self::element_key(index, element_id)),
			DiskAnnCacheValue::DocSet(docs),
		);
	}

	/// Evicts the cached document set for one graph element.
	pub(super) fn remove_doc_set(&self, index: IndexKey, element_id: ElementId) {
		self.0.doc_set_indexes.remove_id(index, element_id);
		self.0.cache.remove(&DiskAnnCacheKey::DocSet(Self::element_key(index, element_id)));
	}

	/// Returns a cached record key for a compact document ID if the generation still matches.
	pub(super) fn get_doc_id(
		&self,
		index: IndexKey,
		doc_id: DocId,
		generation: Option<u64>,
	) -> Option<Arc<RecordIdKey>> {
		let cached =
			match self.0.cache.get(&DiskAnnCacheKey::DocId(Self::doc_id_key(index, doc_id)))? {
				DiskAnnCacheValue::DocId(cached) => cached,
				_ => return None,
			};
		(cached.generation == generation).then_some(cached.id)
	}

	/// Inserts a compact document ID to record-key mapping read from KV.
	pub(super) fn insert_doc_id(
		&self,
		index: IndexKey,
		doc_id: DocId,
		generation: Option<u64>,
		id: RecordIdKey,
	) -> Arc<RecordIdKey> {
		let id = Arc::new(id);
		self.0.doc_id_indexes.insert(index, doc_id);
		self.0.cache.insert(
			DiskAnnCacheKey::DocId(Self::doc_id_key(index, doc_id)),
			DiskAnnCacheValue::DocId(CachedDocId {
				generation,
				id: Arc::clone(&id),
			}),
		);
		id
	}

	/// Evicts a cached compact document ID mapping.
	pub(super) fn remove_doc_id(&self, index: IndexKey, doc_id: DocId) {
		self.0.doc_id_indexes.remove_id(index, doc_id);
		self.0.cache.remove(&DiskAnnCacheKey::DocId(Self::doc_id_key(index, doc_id)));
	}

	/// Evicts every cache family entry scoped to one removed DiskANN index.
	///
	/// Per-index membership sets avoid scanning the entire cache. Removal yields periodically so a
	/// large cached graph does not monopolize the async executor.
	pub(crate) async fn remove_index(
		&self,
		namespace_id: NamespaceId,
		database_id: DatabaseId,
		table_id: TableId,
		index_id: IndexId,
	) {
		let index = Self::index_key(namespace_id, database_id, table_id, index_id);
		self.0.cache.remove(&DiskAnnCacheKey::State(index));
		if let Some(ids) = self.0.element_indexes.remove_index(index) {
			// Collect ids before yielding so the parking_lot guard is never held across a
			// cooperative yield.
			let ids: Vec<_> = ids.read().iter().collect();
			for (count, element_id) in ids.into_iter().enumerate() {
				self.0
					.cache
					.remove(&DiskAnnCacheKey::Element(Self::element_key(index, element_id)));
				if count % 1000 == 0 {
					yield_now!()
				}
			}
		}
		if let Some(ids) = self.0.node_indexes.remove_index(index) {
			// See the element path above: copy ids first, then remove from quick_cache in chunks.
			let ids: Vec<_> = ids.read().iter().collect();
			for (count, element_id) in ids.into_iter().enumerate() {
				self.0.cache.remove(&DiskAnnCacheKey::Node(Self::element_key(index, element_id)));
				if count % 1000 == 0 {
					yield_now!()
				}
			}
		}
		if let Some(ids) = self.0.doc_set_indexes.remove_index(index) {
			let ids: Vec<_> = ids.read().iter().collect();
			for (count, element_id) in ids.into_iter().enumerate() {
				self.0.cache.remove(&DiskAnnCacheKey::DocSet(Self::element_key(index, element_id)));
				if count % 1000 == 0 {
					yield_now!()
				}
			}
		}
		if let Some(ids) = self.0.doc_id_indexes.remove_index(index) {
			let ids: Vec<_> = ids.read().iter().collect();
			for (count, doc_id) in ids.into_iter().enumerate() {
				self.0.cache.remove(&DiskAnnCacheKey::DocId(Self::doc_id_key(index, doc_id)));
				if count % 1000 == 0 {
					yield_now!()
				}
			}
		}
	}

	#[cfg(test)]
	fn element_len(&self, index: IndexKey) -> u64 {
		self.0.element_indexes.len(index)
	}

	#[cfg(test)]
	fn node_len(&self, index: IndexKey) -> u64 {
		self.0.node_indexes.len(index)
	}

	#[cfg(test)]
	fn doc_set_len(&self, index: IndexKey) -> u64 {
		self.0.doc_set_indexes.len(index)
	}

	#[cfg(test)]
	fn doc_id_len(&self, index: IndexKey) -> u64 {
		self.0.doc_id_indexes.len(index)
	}

	#[cfg(test)]
	fn weight(&self) -> u64 {
		self.0.cache.weight()
	}

	#[cfg(test)]
	fn capacity(&self) -> u64 {
		self.0.cache.capacity()
	}
}

fn serialized_vector_size(vector: &SerializedVector) -> usize {
	match vector {
		SerializedVector::F64(values) => values.len() * std::mem::size_of::<f64>(),
		SerializedVector::F32(values) => values.len() * std::mem::size_of::<f32>(),
		SerializedVector::I64(values) => values.len() * std::mem::size_of::<i64>(),
		SerializedVector::I32(values) => values.len() * std::mem::size_of::<i32>(),
		SerializedVector::I16(values) => values.len() * std::mem::size_of::<i16>(),
		SerializedVector::F16(values) => values.len() * std::mem::size_of::<u16>(),
		SerializedVector::I8(values) => values.len() * std::mem::size_of::<i8>(),
		SerializedVector::U8(values) => values.len() * std::mem::size_of::<u8>(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::catalog::{DatabaseId, IndexId, NamespaceId, TableId};
	use crate::idx::trees::vector::SerializedVector;

	fn index() -> IndexKey {
		(NamespaceId(1), DatabaseId(2), TableId(3), IndexId(4))
	}

	#[tokio::test]
	async fn diskann_cache_families_share_one_capacity() {
		let cache = DiskAnnCache::new(1024);
		let index = index();

		cache.insert_state(
			index,
			DiskAnnState {
				enter_point: Some(7),
				next_element_id: 10,
			},
		);
		cache.insert_element(
			index,
			7,
			DiskAnnElement {
				vector: SerializedVector::F32(vec![1.0, 2.0, 3.0, 4.0]),
				deleted: false,
			},
		);
		cache.insert_node(
			index,
			7,
			DiskAnnNode {
				neighbors: vec![8, 9],
			},
		);
		cache.insert_doc_set(index, 7, Ids64::Vec2([11, 12]));
		cache.insert_doc_id(index, 11, Some(1), RecordIdKey::Number(99));

		assert_eq!(cache.capacity(), 1024);
		assert!(cache.weight() > 0);
		assert!(cache.weight() <= cache.capacity());
	}

	#[tokio::test]
	async fn diskann_cache_tracks_and_evicts_per_index() {
		let cache = DiskAnnCache::new(1024 * 1024);
		let index = index();
		let element = DiskAnnElement {
			vector: SerializedVector::F32(vec![1.0, 2.0]),
			deleted: false,
		};
		let node = DiskAnnNode {
			neighbors: vec![8, 9],
		};
		let state = DiskAnnState {
			enter_point: Some(7),
			next_element_id: 10,
		};

		cache.insert_state(index, state.clone());
		cache.insert_element(index, 7, element.clone());
		cache.insert_node(index, 7, node.clone());
		cache.insert_doc_set(index, 7, Ids64::One(11));
		cache.insert_doc_id(index, 11, Some(5), RecordIdKey::Number(17));

		assert_eq!(cache.get_state(index).unwrap().enter_point, state.enter_point);
		let first_element = cache.get_element(index, 7).unwrap();
		let second_element = cache.get_element(index, 7).unwrap();
		let first_node = cache.get_node(index, 7).unwrap();
		let second_node = cache.get_node(index, 7).unwrap();
		assert_eq!(first_element.vector, element.vector);
		assert_eq!(first_node.neighbors, node.neighbors);
		assert!(Arc::ptr_eq(&first_element, &second_element));
		assert!(Arc::ptr_eq(&first_node, &second_node));
		assert_eq!(cache.get_doc_set(index, 7), Some(Ids64::One(11)));
		assert_eq!(
			cache.get_doc_id(index, 11, Some(5)).unwrap().as_ref(),
			&RecordIdKey::Number(17)
		);
		assert!(cache.get_doc_id(index, 11, Some(6)).is_none());
		assert_eq!(cache.element_len(index), 1);
		assert_eq!(cache.node_len(index), 1);
		assert_eq!(cache.doc_set_len(index), 1);
		assert_eq!(cache.doc_id_len(index), 1);

		cache.remove_index(index.0, index.1, index.2, index.3).await;

		assert!(cache.get_state(index).is_none());
		assert!(cache.get_element(index, 7).is_none());
		assert!(cache.get_node(index, 7).is_none());
		assert!(cache.get_doc_set(index, 7).is_none());
		assert!(cache.get_doc_id(index, 11, Some(5)).is_none());
		assert_eq!(cache.element_len(index), 0);
		assert_eq!(cache.node_len(index), 0);
		assert_eq!(cache.doc_set_len(index), 0);
		assert_eq!(cache.doc_id_len(index), 0);
	}

	#[test]
	fn diskann_cache_invalidates_single_element_node_and_doc_set() {
		let cache = DiskAnnCache::new(1024 * 1024);
		let index = index();
		cache.insert_element(
			index,
			7,
			DiskAnnElement {
				vector: SerializedVector::U8(vec![1, 2, 3]),
				deleted: false,
			},
		);
		cache.insert_node(
			index,
			7,
			DiskAnnNode {
				neighbors: vec![1, 2],
			},
		);
		cache.insert_doc_set(index, 7, Ids64::One(42));
		cache.insert_doc_id(index, 42, Some(5), RecordIdKey::Number(7));
		assert!(cache.get_doc_id(index, 42, Some(4)).is_none());
		assert_eq!(cache.get_doc_id(index, 42, Some(5)).unwrap().as_ref(), &RecordIdKey::Number(7));

		cache.remove_element(index, 7);
		cache.remove_node(index, 7);
		cache.remove_doc_set(index, 7);
		cache.remove_doc_id(index, 42);

		assert!(cache.get_element(index, 7).is_none());
		assert!(cache.get_node(index, 7).is_none());
		assert!(cache.get_doc_set(index, 7).is_none());
		assert!(cache.get_doc_id(index, 42, Some(5)).is_none());
		assert_eq!(cache.element_len(index), 0);
		assert_eq!(cache.node_len(index), 0);
		assert_eq!(cache.doc_set_len(index), 0);
		assert_eq!(cache.doc_id_len(index), 0);
	}
}
