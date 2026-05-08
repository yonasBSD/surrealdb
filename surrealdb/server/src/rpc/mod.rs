pub mod format;
pub mod http;
pub mod response;
pub mod websocket;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::FuturesUnordered;
use surrealdb_core::channel::Receiver;
#[cfg(feature = "graphql")]
use surrealdb_core::gql::NotificationRouter;
use surrealdb_core::rpc::{DbResponse, DbResult};
use surrealdb_types::Notification;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[cfg(feature = "graphql")]
use crate::cnf::GQL_SUBSCRIPTION_CHANNEL_CAPACITY;
use crate::rpc::websocket::Websocket;

static CONN_CLOSED_ERR: &str = "Connection closed normally";
/// A type alias for an RPC Connection
type WebSocket = Arc<Websocket>;
/// Mapping of WebSocket ID to WebSocket
type WebSockets = RwLock<HashMap<Uuid, WebSocket>>;
/// Recorded state for a registered LIVE query. Stored on the global RPC
/// state so the live-query active gauge can be balanced (the cleanup paths
/// drop entries one-by-one with the originating tenant ctx) and so the
/// notification dispatch can label its delivery counter.
#[derive(Clone, Debug)]
pub struct LiveQueryEntry {
	pub websocket_id: Uuid,
	pub session_id: Uuid,
	/// Namespace at the time the LIVE statement was registered. `None`
	/// when the registering session had no NS selected.
	pub namespace: Option<String>,
	/// Database at the time the LIVE statement was registered. `None`
	/// when the registering session had no DB selected.
	pub database: Option<String>,
}

/// Mapping of LIVE Query ID to its registered entry.
type LiveQueries = RwLock<HashMap<Uuid, LiveQueryEntry>>;

pub struct RpcState {
	/// Stores the currently connected WebSockets
	pub web_sockets: WebSockets,
	/// Stores the currently initiated LIVE queries
	pub live_queries: LiveQueries,
	/// HTTP RPC handler with persistent sessions
	pub http: Arc<crate::rpc::http::Http>,
	/// Prometheus observer for per-protocol network byte counters. `None`
	/// when `SURREAL_METRICS_ENABLED=false` so the byte counter path is
	/// entirely inert for unconfigured deployments.
	pub metrics_observer: Option<Arc<crate::observe::metrics::MetricsObserver>>,
	#[cfg(feature = "graphql")]
	pub(crate) notification_router: Arc<NotificationRouter>,
}

impl RpcState {
	pub fn new(datastore: Arc<surrealdb_core::kvs::Datastore>) -> Self {
		Self::new_with_metrics(datastore, None)
	}

	pub fn new_with_metrics(
		datastore: Arc<surrealdb_core::kvs::Datastore>,
		metrics_observer: Option<Arc<crate::observe::metrics::MetricsObserver>>,
	) -> Self {
		Self {
			web_sockets: RwLock::new(HashMap::new()),
			live_queries: RwLock::new(HashMap::new()),
			http: Arc::new(crate::rpc::http::Http::new(datastore)),
			metrics_observer,
			#[cfg(feature = "graphql")]
			notification_router: Arc::new(NotificationRouter::new(
				*GQL_SUBSCRIPTION_CHANNEL_CAPACITY,
			)),
		}
	}
}

/// Performs notification delivery to the WebSockets.
///
/// This function listens on the datastore's notification channel and forwards
/// LIVE query notifications to the appropriate WebSocket connections. It runs
/// in a loop until the provided [`CancellationToken`] is cancelled.
///
/// # Parameters
/// - `ds`:        The [`Datastore`] whose notification channel to listen on
/// - `state`:     The [`RpcState`] containing WebSocket and LIVE query mappings
/// - `canceller`: A [`CancellationToken`] that stops the loop when cancelled
///
/// # Usage
///
/// This is called automatically by
/// [`SurrealRouter::spawn_notifications`](crate::ntw::SurrealRouter::spawn_notifications).
/// If you need lower-level control you can call it directly inside your own `tokio::spawn`.
pub async fn notifications(
	channel: Receiver<Notification>,
	state: Arc<RpcState>,
	canceller: CancellationToken,
) {
	// Store messages being delivered
	let mut futures = FuturesUnordered::new();
	// Loop continuously
	loop {
		tokio::select! {
			//
			biased;
			// Check if this has shutdown
			_ = canceller.cancelled() => break,
			// Process any buffered messages
			Some(_) = futures.next() => continue,
			// Receive a notification on the channel
			Ok(notification) = channel.recv() => {
				#[cfg(feature = "graphql")]
				if state.notification_router.has_subscribers() {
					state.notification_router.dispatch(&notification);
				}
				// Copy the lookup result out and drop the `live_queries`
				// read guard BEFORE acquiring `web_sockets`. An `if let` /
				// `&& let` chain would extend the first guard's lifetime
				// across the second `.read().await`, blocking concurrent
				// `live_queries.write()` callers (handle_live, handle_kill,
				// cleanup_lqs, cleanup_all_lqs) on this hot notification
				// path.
				let live_query = state
					.live_queries
					.read()
					.await
					.get(&notification.id)
					.cloned();
				if let Some(entry) = live_query
					&& let Some(rpc) = state.web_sockets.read().await.get(&entry.websocket_id).cloned() {
						// Count the notification once we know it will
						// actually be delivered to a client. We
						// deliberately avoid counting drops (unknown
						// LQ id or disconnected WS) so the metric
						// mirrors end-to-end deliveries.
						if let Some(obs) = state.metrics_observer.as_ref() {
							obs.record_live_query_notification(
								entry.namespace.as_deref(),
								entry.database.as_deref(),
							);
						}
						// Hide the connection's implicit session UUID from the
						// client: when a LIVE query was registered without an
						// explicit session_id it resolves to `rpc.id`, which
						// is an internal connection identifier the client
						// never supplied. Emit `null` in that case to match
						// the historical wire protocol.
						let wire_session_id =
							(entry.session_id != rpc.id).then_some(entry.session_id);
						let message = DbResponse::success(
							None,
							wire_session_id,
							DbResult::Live(notification),
						);
						let format = rpc.format;
						let sender = rpc.channel.clone();
						let future = crate::rpc::response::send(message, format, sender);
						futures.push(future);
				}
			},
		}
	}
}

/// Closes all WebSocket connections, waiting for graceful shutdown.
///
/// Signals each connected WebSocket to shut down and then waits until all
/// connections have been drained from the [`RpcState`].
pub async fn graceful_shutdown(state: Arc<RpcState>) {
	// Close WebSocket connections, ensuring queued messages are processed
	for (_, rpc) in state.web_sockets.read().await.iter() {
		rpc.shutdown.cancel();
	}
	// Wait for all existing WebSocket connections to finish sending
	while !state.web_sockets.read().await.is_empty() {
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
}

/// Forces a fast shutdown of all WebSocket connections.
///
/// Unlike [`graceful_shutdown`], this immediately drains the WebSocket map
/// without waiting for in-flight messages to be delivered.
pub fn shutdown(state: Arc<RpcState>) {
	// Close all WebSocket connections immediately
	if let Ok(mut writer) = state.web_sockets.try_write() {
		writer.drain();
	}
}
