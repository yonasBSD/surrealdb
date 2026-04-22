use std::sync::Arc;

use surrealdb_core::dbs::Session;
use surrealdb_core::kvs::Datastore;
use surrealdb_core::rpc::{DbResult, Method, RpcProtocol, method_not_found};
use surrealdb_types::{Array, Error as TypesError, HashMap, Value};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::cnf::{PKG_NAME, PKG_VERSION};

/// HTTP RPC handler with per-request session isolation.
///
/// Sessions are inserted under unique per-request keys by `post_handler`
/// and removed after execution completes. No default session is stored.
pub struct Http {
	kvs: Arc<Datastore>,
	sessions: HashMap<Uuid, Arc<RwLock<Session>>>,
	/// Set of session IDs that were created implicitly by the transport for
	/// per-request isolation. These must be hidden from `sessions()` so
	/// clients cannot enumerate or target internal request UUIDs.
	ephemeral_sessions: HashMap<Uuid, ()>,
}

impl Http {
	pub fn new(kvs: Arc<Datastore>) -> Self {
		Self {
			kvs,
			sessions: HashMap::new(),
			ephemeral_sessions: HashMap::new(),
		}
	}

	/// Register a session created implicitly by the transport for a single
	/// request. Tracked so it can be filtered from `sessions()` results.
	///
	/// Insert into `ephemeral_sessions` BEFORE `sessions` so any concurrent
	/// `sessions()` call that snapshots the session map will also observe
	/// the ephemeral marker and filter the UUID out. Reversing this order
	/// opens a window where the internal per-request UUID can be returned
	/// to the client.
	///
	/// Crate-private: only the HTTP transport may mint ephemeral sessions.
	/// Exposing this publicly would let embedder crates inject hidden
	/// sessions into the shared session map.
	pub(crate) fn register_ephemeral_session(&self, id: Uuid, session: Arc<RwLock<Session>>) {
		self.ephemeral_sessions.insert(id, ());
		self.sessions.insert(id, session);
	}

	/// Remove a previously registered ephemeral session.
	///
	/// Guards against destroying a named (attached) session by verifying the
	/// UUID was in fact registered as ephemeral before touching `sessions`.
	/// A non-ephemeral UUID is a safe no-op. This upholds the contract that
	/// named sessions are only torn down via the trait-level `detach` /
	/// `del_session` path (which also performs live-query cleanup).
	///
	/// Remove from `sessions` only AFTER confirming the UUID was ephemeral,
	/// then clear the ephemeral marker so the UUID disappears from future
	/// `sessions()` snapshots before the marker is cleared.
	///
	/// Crate-private: only the HTTP transport may recycle ephemeral sessions.
	pub(crate) fn remove_ephemeral_session(&self, id: &Uuid) {
		if self.ephemeral_sessions.contains_key(id) {
			self.sessions.remove(id);
			self.ephemeral_sessions.remove(id);
		}
	}
}

impl RpcProtocol for Http {
	/// The datastore for this RPC interface
	fn kvs(&self) -> &Datastore {
		&self.kvs
	}

	/// The version information for this RPC context
	fn version_data(&self) -> DbResult {
		let value = Value::String(format!("{PKG_NAME}-{}", *PKG_VERSION));
		DbResult::Other(value)
	}

	/// A pointer to all active sessions
	fn session_map(&self) -> &HashMap<Uuid, Arc<RwLock<Session>>> {
		&self.sessions
	}

	/// Lists all explicitly attached sessions.
	///
	/// Filters out ephemeral per-request session IDs created by the
	/// transport layer so clients cannot enumerate internal UUIDs.
	///
	/// Concurrency note: the snapshot of `sessions` and the per-key lookup
	/// into `ephemeral_sessions` are two independent lock-free map reads
	/// with no cross-map atomicity. The insert ordering in
	/// [`Self::register_ephemeral_session`] prevents an in-flight ephemeral
	/// UUID from leaking. The symmetric removal-side window (a concurrent
	/// `remove_ephemeral_session` clearing the marker after the sessions
	/// snapshot but before the `contains_key` check) can only leak a stale
	/// UUID whose underlying session has already been torn down — any
	/// subsequent RPC using it returns `session not found`. Fully closing
	/// this narrow window would require cross-map locking on the hot
	/// per-request path and is deliberately not done here.
	async fn sessions(&self) -> Result<DbResult, TypesError> {
		let array: Array = self
			.session_map()
			.to_vec()
			.into_iter()
			.filter(|(key, _)| !self.ephemeral_sessions.contains_key(key))
			.map(|(key, _)| Value::Uuid(surrealdb_types::Uuid::from(key)))
			.collect();
		Ok(DbResult::Other(Value::Array(array)))
	}

	// ------------------------------
	// Realtime
	// ------------------------------

	/// Live queries are disabled on HTTP
	const LQ_SUPPORT: bool = false;

	/// Handles the cleanup of live queries
	async fn cleanup_lqs(&self, _session_id: &Uuid) {
		// Do nothing as HTTP is stateless
	}

	/// Handles the cleanup of live queries
	async fn cleanup_all_lqs(&self) {
		// Do nothing as HTTP is stateless
	}

	// ------------------------------
	// Overrides
	// ------------------------------

	/// Transactions are not supported on HTTP RPC context
	async fn begin(&self, _txn: Option<Uuid>, _session_id: Uuid) -> Result<DbResult, TypesError> {
		Err(method_not_found(Method::Begin.to_string()))
	}

	/// Transactions are not supported on HTTP RPC context
	async fn commit(
		&self,
		_txn: Option<Uuid>,
		_session_id: Uuid,
		_params: Array,
	) -> Result<DbResult, TypesError> {
		Err(method_not_found(Method::Commit.to_string()))
	}

	/// Transactions are not supported on HTTP RPC context
	async fn cancel(
		&self,
		_txn: Option<Uuid>,
		_session_id: Uuid,
		_params: Array,
	) -> Result<DbResult, TypesError> {
		Err(method_not_found(Method::Cancel.to_string()))
	}
}
