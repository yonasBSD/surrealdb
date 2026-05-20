//! GraphQL schema cache.
//!
//! Generated `async_graphql::dynamic::Schema` instances are expensive to build
//! (they require reading all table/field/access definitions from the datastore).
//! This module provides [`GraphQLSchemaCache`] which caches schemas keyed by
//! `(namespace, database, GraphQLConfig, schema-fingerprint)` so that repeated
//! requests to the same database reuse the previously generated schema, while
//! still invalidating automatically when the underlying SurrealQL schema
//! changes.
//!
//! The fingerprint is a `u64` content hash of every catalog entry that
//! influences schema generation: table + field definitions, function
//! definitions, and access definitions. Any DDL change naturally produces a
//! new key and the next request transparently regenerates the schema. See
//! GitHub issue #6942.

use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use anyhow::Result;
use async_graphql::dynamic::Schema;
use tokio::sync::RwLock;

use super::error::GqlError;
use super::schema::generate_schema;
use crate::catalog::providers::{AuthorisationProvider, DatabaseProvider, TableProvider};
use crate::catalog::{
	DatabaseId, GraphQLConfig, GraphQLFunctionsConfig, GraphQLTablesConfig, NamespaceId,
};
use crate::dbs::Session;
use crate::kvs::{Datastore, Transaction};

/// Cache key: (namespace name, database name, GraphQL configuration, schema fingerprint).
///
/// The configuration is included so that a `DEFINE CONFIG GRAPHQL` change
/// naturally produces a different key and triggers regeneration. The
/// fingerprint covers every other catalog change that influences schema
/// generation (DEFINE/REMOVE TABLE, DEFINE FIELD, DEFINE FUNCTION, DEFINE
/// ACCESS) — so any such DDL also produces a fresh key.
type CacheKey = (String, String, GraphQLConfig, u64);

/// Maximum number of `(ns, db, config, fingerprint)` entries held in the
/// schema cache. Each schema is relatively cheap (one `Arc<Schema>`); the cap
/// exists to stop unbounded growth from DDL churn — every catalog change
/// produces a new fingerprint and a fresh entry, so over the lifetime of a
/// long-running server the map would otherwise grow without bound.
const SCHEMA_CACHE_MAX_ENTRIES: usize = 256;

/// In-memory cache of generated GraphQL schemas.
///
/// Thread-safe via `Arc<RwLock<...>>` -- multiple readers can share a cached
/// schema concurrently, and writes (insert/remove) acquire exclusive access.
#[derive(Clone, Default)]
pub struct GraphQLSchemaCache {
	ns_db_schema_cache: Arc<RwLock<HashMap<CacheKey, Schema>>>,
}

impl Debug for GraphQLSchemaCache {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SchemaCache").field("ns_db_schema_cache", &self.ns_db_schema_cache).finish()
	}
}

impl GraphQLSchemaCache {
	/// Retrieve a cached schema or generate a new one.
	///
	/// 1. Reads the current `GraphQLConfig` and a content fingerprint of the schema state.
	/// 2. Returns the cached schema if one exists for the resulting key.
	/// 3. Otherwise, generates the schema via [`generate_schema`], caches it, and returns it.
	///
	/// On generation failure, stale cache entries are removed if the error
	/// indicates a database or schema-level problem.
	pub async fn get_schema(
		&self,
		datastore: &Arc<Datastore>,
		session: &Session,
	) -> Result<Schema, GqlError> {
		use crate::kvs::{LockType, TransactionType};

		let ns = session.ns.as_ref().ok_or(GqlError::UnspecifiedNamespace)?;
		let db = session.db.as_ref().ok_or(GqlError::UnspecifiedDatabase)?;

		// Open a single read transaction reused for both the config lookup and
		// the fingerprint computation. `generate_schema` opens its own
		// transaction on miss.
		let kvs = datastore;
		let tx = kvs.transaction(TransactionType::Read, LockType::Optimistic).await?;

		let db_def = match tx.get_db_by_name(ns, db, None).await? {
			Some(db) => db,
			None => return Err(GqlError::NotConfigured),
		};

		let cg = tx
			.expect_db_config(db_def.namespace_id, db_def.database_id, "graphql")
			.await
			.map_err(|e| {
				if matches!(e.downcast_ref(), Some(crate::err::Error::CgNotFound { .. })) {
					GqlError::NotConfigured
				} else {
					GqlError::DbError(e)
				}
			})?;
		let gql_config = (*cg).clone().try_into_graphql()?;

		let fingerprint =
			compute_schema_fingerprint(&tx, db_def.namespace_id, db_def.database_id, &gql_config)
				.await
				.map_err(GqlError::DbError)?;

		let cache_key = (ns.to_owned(), db.to_owned(), gql_config.clone(), fingerprint);

		{
			let guard = self.ns_db_schema_cache.read().await;
			if let Some(cand) = guard.get(&cache_key) {
				return Ok(cand.clone());
			}
		};

		// Try to generate the schema
		let schema = match generate_schema(datastore, session, gql_config).await {
			Ok(s) => s,
			Err(e) => {
				// If we get an error that could indicate stale cache (database not found,
				// schema errors from missing tables, etc.), clear the cache entry
				if matches!(e, GqlError::DbError(_) | GqlError::SchemaError(_)) {
					let mut guard = self.ns_db_schema_cache.write().await;
					guard.remove(&cache_key);
				}
				return Err(e);
			}
		};

		{
			let mut guard = self.ns_db_schema_cache.write().await;
			// Evict stale fingerprints for this (ns, db, config) — only the
			// most recent fingerprint can be served once we've observed it, so
			// older entries for the same prefix are dead weight.
			let (ns_key, db_key, cfg_key, _) = &cache_key;
			guard.retain(|(n, d, c, _), _| !(n == ns_key && d == db_key && c == cfg_key));
			// Hard cap: if the map is still oversize (many distinct ns/db/cfg
			// tuples), drop arbitrary entries until we're back under the
			// limit. We don't track recency, so eviction order is
			// implementation-defined — the practical effect is "stop growing
			// without bound." TODO: swap for an LRU (e.g. `IndexMap` with
			// `shift_remove` of the oldest entry) if real workloads start
			// thrashing many distinct (ns, db, cfg) tuples.
			while guard.len() >= SCHEMA_CACHE_MAX_ENTRIES {
				if let Some(k) = guard.keys().next().cloned() {
					guard.remove(&k);
				} else {
					break;
				}
			}
			guard.insert(cache_key, schema.clone());
		}

		Ok(schema)
	}
}

/// Hash the catalog entries that influence GraphQL schema generation.
///
/// Inputs hashed (must stay in sync with [`generate_schema`]):
/// - Tables exposed by `gql_config.tables`. Each `TableDefinition` already includes a
///   `cache_fields_ts` UUID that DEFINE/REMOVE FIELD bumps, so we don't need to fetch each table's
///   full field list — the timestamp is sufficient to invalidate the cache when any field changes.
/// - Functions exposed by `gql_config.functions` (and each [`crate::catalog::FunctionDefinition`]).
/// - All access definitions on the database (used for auth mutation generation).
///
/// If a new piece of catalog state starts influencing schema generation,
/// extend this helper accordingly — otherwise the cache will return stale
/// schemas after that piece of state changes.
async fn compute_schema_fingerprint(
	tx: &Transaction,
	ns: NamespaceId,
	db: DatabaseId,
	gql_config: &GraphQLConfig,
) -> Result<u64> {
	let mut hasher = std::collections::hash_map::DefaultHasher::new();

	// Tables (post-config filtering). Hashing the `TableDefinition` itself
	// covers `cache_fields_ts` (DEFINE/REMOVE FIELD), `graphql_alias`,
	// `graphql_deprecated`, table_type, view, permissions, etc. — every
	// catalog field that influences schema generation is part of the struct's
	// `Hash` impl.
	let tbs = tx.all_tb(ns, db, None).await?;
	let mut tables_to_hash: Vec<&crate::catalog::TableDefinition> = match &gql_config.tables {
		GraphQLTablesConfig::None => Vec::new(),
		GraphQLTablesConfig::Auto => tbs.iter().collect(),
		GraphQLTablesConfig::Include(inc) => tbs.iter().filter(|t| inc.contains(&t.name)).collect(),
		GraphQLTablesConfig::Exclude(exc) => {
			tbs.iter().filter(|t| !exc.contains(&t.name)).collect()
		}
	};
	// Sort for stable hashing — `all_tb` already returns a deterministic order
	// today, but pinning it here keeps the fingerprint robust against future
	// changes to the underlying iteration order.
	tables_to_hash.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
	for tb in &tables_to_hash {
		tb.hash(&mut hasher);
	}

	// Functions (post-config filtering).
	let fns = tx.all_db_functions(ns, db, None).await?;
	let mut fns_to_hash: Vec<&crate::catalog::FunctionDefinition> = match &gql_config.functions {
		GraphQLFunctionsConfig::None => Vec::new(),
		GraphQLFunctionsConfig::Auto => fns.iter().collect(),
		GraphQLFunctionsConfig::Include(inc) => {
			fns.iter().filter(|f| inc.iter().any(|n| n.as_str() == f.name.as_str())).collect()
		}
		GraphQLFunctionsConfig::Exclude(exc) => {
			fns.iter().filter(|f| !exc.iter().any(|n| n.as_str() == f.name.as_str())).collect()
		}
	};
	fns_to_hash.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
	for f in &fns_to_hash {
		f.hash(&mut hasher);
	}

	// Access definitions (used to build signIn/signUp mutations).
	let accesses = tx.all_db_accesses(ns, db, None).await?;
	let mut accesses_sorted: Vec<&crate::catalog::AccessDefinition> = accesses.iter().collect();
	accesses_sorted.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
	for a in &accesses_sorted {
		a.hash(&mut hasher);
	}

	Ok(hasher.finish())
}
