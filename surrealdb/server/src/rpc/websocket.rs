use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::close_code::AGAIN;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use futures::{Sink, SinkExt, StreamExt};
use surrealdb_core::dbs::Session;
use surrealdb_core::kvs::{Datastore, LockType, Transaction, TransactionType};
use surrealdb_core::mem::ALLOC;
use surrealdb_core::observe::{
	NetworkBytesEvent, NetworkBytesEventCtx, NetworkBytesEventSafe, NetworkDirection,
	SessionAction, SessionEvent, SessionEventCtx, SessionEventSafe, SessionProtocol,
};
use surrealdb_core::rpc::format::Format;
use surrealdb_core::rpc::{DbResponse, DbResult, Method, RpcProtocol};
use surrealdb_types::{Array, Error as TypesError, HashMap, ToSql, Value};
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span};
use uuid::Uuid;

use super::RpcState;
use crate::cnf::{
	PKG_NAME, PKG_VERSION, WEBSOCKET_MAX_ATTACHED_SESSIONS, WEBSOCKET_PING_FREQUENCY,
	WEBSOCKET_RESPONSE_BUFFER_SIZE, WEBSOCKET_RESPONSE_CHANNEL_SIZE,
	WEBSOCKET_RESPONSE_FLUSH_PERIOD,
};
use crate::rpc::CONN_CLOSED_ERR;
use crate::rpc::format::WsFormat;
use crate::telemetry::traces::rpc::span_for_request;

/// An error string sent when the server is out of memory
const SERVER_OVERLOADED: &str = "The server is unable to handle the request";

/// An error string sent when the server is gracefully shutting down
const SERVER_SHUTTING_DOWN: &str = "The server is gracefully shutting down";

/// An error string sent when an in-flight RPC is dropped because the
/// connection-level `canceller` fires (e.g. the WebSocket has been torn down).
const REQUEST_CANCELLED: &str = "The request was cancelled because the WebSocket is closing";

pub struct Websocket {
	/// The unique id of this WebSocket connection
	pub(crate) id: Uuid,
	/// The request and response format for messages
	pub(crate) format: Format,
	/// The system state for all RPC WebSocket connections
	pub(crate) state: Arc<RpcState>,
	/// The datastore accessible to all RPC WebSocket connections
	pub(crate) datastore: Arc<Datastore>,
	/// The active sessions for this WebSocket connection.
	///
	/// This map is **per-connection**: it is created fresh for every
	/// WebSocket upgrade and torn down when the connection closes. A
	/// session id attached here is only reachable from RPC calls that
	/// arrive on this same socket, so cross-connection hijack via session
	/// id enumeration is not possible on the WebSocket transport by construction.
	/// The attach count is additionally capped by [`WEBSOCKET_MAX_ATTACHED_SESSIONS`]
	/// as defence-in-depth against a single misbehaving client.
	pub(crate) sessions: HashMap<Uuid, Arc<RwLock<Session>>>,
	/// The active transactions for this WebSocket connection
	pub(crate) transactions: DashMap<Uuid, Arc<Transaction>>,
	/// A cancellation token called when shutting down the server
	pub(crate) shutdown: CancellationToken,
	/// A cancellation token for cancelling all spawned tasks
	pub(crate) canceller: CancellationToken,
	/// The channels used to send and receive WebSocket messages
	pub(crate) channel: Sender<Message>,
}

impl Websocket {
	/// Serve the RPC endpoint
	pub async fn serve(
		id: Uuid,
		ws: WebSocket,
		format: Format,
		session: Session,
		datastore: Arc<Datastore>,
		state: Arc<RpcState>,
	) {
		// Log the succesful WebSocket connection
		trace!("WebSocket {id} connected");
		// Record the connect timestamp so we can emit the session lifetime
		// alongside the disconnect event further down.
		let connected_at = web_time::Instant::now();
		// Create a channel for sending messages
		let (sender, receiver) = channel(*WEBSOCKET_RESPONSE_CHANNEL_SIZE);
		let rec_limit = datastore.config().max_object_parsing_depth as usize;
		// Create and store the RPC connection
		let rpc = Arc::new(Websocket {
			id,
			format,
			state: state.clone(),
			shutdown: CancellationToken::new(),
			canceller: CancellationToken::new(),
			sessions: HashMap::new(),
			transactions: DashMap::new(),
			channel: sender.clone(),
			datastore,
		});

		// Store the default session keyed by connection id
		let session = session.with_rt(true);
		rpc.set_session(id, Arc::new(RwLock::new(session)));
		// Add this WebSocket to the list
		state.web_sockets.write().await.insert(id, rpc.clone());
		// Emit a session connect event so observability sinks can track
		// simultaneous connections without consulting the datastore.
		// The OTel `rpc.server.active_connections` and
		// `rpc.server.connection.count` instruments are recorded by
		// `OtelObserver::on_session_event` from the same dispatch.
		rpc.datastore.observer().on_session_event(&SessionEvent {
			safe: SessionEventSafe {
				action: SessionAction::Connect,
				protocol: SessionProtocol::WebSocket,
				duration: None,
			},
			ctx: SessionEventCtx {
				session_id: Some(id),
				service_name: None,
				..Default::default()
			},
		});
		// Store all concurrent spawned tasks
		let mut tasks = JoinSet::new();
		// Buffer the WebSocket response stream
		match *WEBSOCKET_RESPONSE_BUFFER_SIZE > 0 {
			true => {
				// Buffer the WebSocket response stream
				let buffer = ws.buffer(*WEBSOCKET_RESPONSE_BUFFER_SIZE);
				// Split the socket into sending and receiving streams
				let (ws_sender, ws_receiver) = buffer.split();
				// Spawn async tasks for the WebSocket
				tasks.spawn(Self::ping(rpc.clone(), sender.clone()));
				tasks.spawn(Self::read(rpc.clone(), ws_receiver, sender.clone(), rec_limit));
				tasks.spawn(Self::write(rpc.clone(), ws_sender, receiver));
			}
			false => {
				// Split the socket into sending and receiving streams
				let (ws_sender, ws_receiver) = ws.split();
				// Spawn async tasks for the WebSocket
				tasks.spawn(Self::ping(rpc.clone(), sender.clone()));
				tasks.spawn(Self::read(rpc.clone(), ws_receiver, sender.clone(), rec_limit));
				tasks.spawn(Self::write(rpc.clone(), ws_sender, receiver));
			}
		}
		// Wait for all tasks to finish
		while let Some(res) = tasks.join_next().await {
			if let Err(err) = res {
				error!("Error handling RPC connection: {err}");
			}
		}
		// Close the internal response channel
		std::mem::drop(sender);
		// Log the WebSocket disconnection
		trace!("WebSocket {id} disconnected");
		// Cleanup the live queries for this WebSocket
		rpc.cleanup_all_lqs().await;
		// Remove this WebSocket from the list
		state.web_sockets.write().await.remove(&id);
		// Emit a session disconnect event including the full session
		// lifetime so histogram-based observers can summarise dwell
		// time. The OTel `rpc.server.active_connections` decrement
		// flows through `OtelObserver::on_session_event` from this
		// dispatch.
		rpc.datastore.observer().on_session_event(&SessionEvent {
			safe: SessionEventSafe {
				action: SessionAction::Disconnect,
				protocol: SessionProtocol::WebSocket,
				duration: Some(connected_at.elapsed()),
			},
			ctx: SessionEventCtx {
				session_id: Some(id),
				service_name: None,
				..Default::default()
			},
		});
	}

	/// Send Ping messages to the client
	async fn ping(rpc: Arc<Websocket>, internal_sender: Sender<Message>) {
		// Create the interval ticker
		let mut interval = tokio::time::interval(WEBSOCKET_PING_FREQUENCY);
		// Clone the WebSocket cancellation token
		let canceller = rpc.canceller.clone();
		// Loop, and listen for messages to write
		loop {
			tokio::select! {
				// Process brances in order
				biased;
				// Check if we should teardown
				_ = canceller.cancelled() => break,
				// Send a regular ping message
				_ = interval.tick() => {
					// Create a new ping message
					let msg = Message::Ping(Bytes::from_static(b""));
					// Close the connection if the message fails
					if let Err(err) = internal_sender.send(msg).await {
						// Output any errors if not a close error
						if err.to_string() != CONN_CLOSED_ERR {
							trace!("WebSocket error: {err}");
						}
						// Cancel the WebSocket tasks
						canceller.cancel();
						// Exit out of the loop
						break;
					}
				},
			}
		}
	}

	/// Write messages to the client
	async fn write<S: SinkExt<Message> + Unpin>(
		rpc: Arc<Websocket>,
		mut socket: S,
		mut internal_receiver: Receiver<Message>,
	) where
		<S as Sink<Message>>::Error: fmt::Display,
	{
		// Clone the WebSocket cancellation token
		let canceller = rpc.canceller.clone();
		// Check if the responses are buffered
		let buffer = *WEBSOCKET_RESPONSE_BUFFER_SIZE > 0;
		// How often should responses be flushed
		let period = Duration::from_millis(*WEBSOCKET_RESPONSE_FLUSH_PERIOD);
		// Loop, and listen for messages to write
		loop {
			tokio::select! {
				// Process brances in order
				biased;
				// Check if we should teardown
				_ = canceller.cancelled() => break,
				// Retrieve a response from the channel
				Some(res) = internal_receiver.recv() => {
					// Capture the byte length before the message is moved
					// into the sink so we can fold it into the outbound
					// Prometheus counter when metrics are enabled.
					let out_bytes = match &res {
						Message::Text(msg) => msg.len(),
						Message::Binary(msg) => msg.len(),
						_ => 0,
					};
					// Check if the socket is buffered
					let result = match buffer {
						// Send the message to the socket buffer
						true => socket.feed(res).await,
						// Send the message direct to the socket
						false => socket.send(res).await
					};
					// Check if there was an error
					if let Err(err) = result {
						// Output any errors if not a close error
						if err.to_string() != CONN_CLOSED_ERR {
							trace!("WebSocket error: {err}");
						}
						// Cancel the WebSocket tasks
						canceller.cancel();
						// Exit out of the loop
						break;
					}
					// Record outbound bytes on success. We deliberately avoid
					// double-counting on the error path above. `ctx` carries
					// `(namespace, database, user)` from the bound session;
					// record-access principals collapse to the `<record>`
					// sentinel in `NetworkBytesEventCtx::from_session` to keep
					// dimensional cardinality bounded.
					if out_bytes > 0 {
						let ctx = rpc.default_network_ctx().await;
						rpc.datastore.observer().on_network_bytes(&NetworkBytesEvent {
							safe: NetworkBytesEventSafe {
								direction: NetworkDirection::Sent,
								protocol: SessionProtocol::WebSocket,
								bytes: out_bytes as u64,
							},
							ctx,
						});
					}
				},
				// Wait for a short period of time
				_ = tokio::time::sleep(period), if buffer => {
					// Flush the WebSocket socket buffer
					if let Err(err) = socket.flush().await {
						// Output any errors if not a close error
						if err.to_string() != CONN_CLOSED_ERR {
							trace!("WebSocket error: {err}");
						}
						// Cancel the WebSocket tasks
						canceller.cancel();
						// Exit out of the loop
						break;
					}
				}
			}
		}
	}

	/// Read messages sent from the client
	async fn read(
		rpc: Arc<Websocket>,
		mut socket: impl StreamExt<Item = Result<Message, axum::Error>> + Unpin,
		internal_sender: Sender<Message>,
		rec_limit: usize,
	) {
		// Clone the WebSocket shutdown token
		let shutdown = rpc.shutdown.clone();
		// Clone the WebSocket cancellation token
		let canceller = rpc.canceller.clone();
		// Store spawned tasks so we can wait for them
		let mut tasks = FuturesUnordered::new();
		// Loop, and listen for messages to write
		loop {
			tokio::select! {
				// Process brances in order
				biased;
				// Remove any completed tasks
				_ = tasks.next(), if !tasks.is_empty() => {},
				// Check if we are shutting down
				_ = shutdown.cancelled() => break,
				// Check if we should teardown
				_ = canceller.cancelled() => break,
				// Wait for the next received message
				Some(msg) = socket.next() => match msg {
					// We've received a message from the client
					Ok(msg) => match msg {
						Message::Text(_) | Message::Binary(_) => {
							// Clone the response sending channel
							let chn = internal_sender.clone();
							// Check to see whether we have available memory
							if ALLOC.is_beyond_threshold() {
								// Reject the message
								Self::close_socket(rpc.clone(), chn).await;
								// Exit out of the loop
								break;
							}
							// Otherwise spawn and handle the message
							tasks.push(Self::handle_message(&rpc, msg, chn, rec_limit));
						}
						Message::Close(_) => {
							// Respond with a close message
							if let Err(err) = internal_sender.send(Message::Close(None)).await {
								trace!("WebSocket error when replying to the close message: {err}");
							};
							// Cancel the WebSocket tasks
							canceller.cancel();
							// Exit out of the loop
							break;
						}
						Message::Ping(_) => {
							// Ping messages are responded to automatically
						}
						Message::Pong(_) => {
							// Pong messages are handled automatically
						}
					},
					Err(err) => {
						// There was an error with the WebSocket
						trace!("WebSocket error: {err}");
						// Cancel the WebSocket tasks
						canceller.cancel();
						// Exit out of the loop
						break;
					}
				}
			}
		}
		// Continue with the shutdown process
		tokio::select! {
			// Process brances in order
			biased;
			// Check if we have been cancelled
			_ = canceller.cancelled() => (),
			// Check if we are shutting down
			_ = shutdown.cancelled() => {
				// Wait for all tasks to finish
				while tasks.next().await.is_some() {
					// Do nothing
				}
			},
		}
		// Cancel the WebSocket tasks
		canceller.cancel();
		// Ensure everything is dropped
		std::mem::drop(tasks);
	}

	/// Handle an individual WebSocket message
	async fn handle_message(
		rpc: &Arc<Websocket>,
		msg: Message,
		chn: Sender<Message>,
		rec_limit: usize,
	) {
		// Clone the WebSocket cancellation token
		let shutdown = rpc.shutdown.clone();
		// Clone the WebSocket cancellation token
		let canceller = rpc.canceller.clone();
		// Calculate the message length and format
		let len = match msg {
			Message::Text(ref msg) => msg.len(),
			Message::Binary(ref msg) => msg.len(),
			_ => 0,
		};
		// Record inbound bytes by dispatching a network event through the
		// fan-out observer. Ping / Pong / Close / Raw frames report 0 and
		// the dispatch short-circuits inside each observer. `ctx` is built
		// from the bound session via `default_network_ctx`; record-access
		// principals collapse to a `<record>` sentinel to bound dimensional
		// label cardinality.
		if len > 0 {
			let ctx = rpc.default_network_ctx().await;
			rpc.datastore.observer().on_network_bytes(&NetworkBytesEvent {
				safe: NetworkBytesEventSafe {
					direction: NetworkDirection::Received,
					protocol: SessionProtocol::WebSocket,
					bytes: len as u64,
				},
				ctx,
			});
		}
		// Prepare the per-request tracing span. RPC duration / outcome
		// is now recorded centrally by `core::rpc::protocol` via
		// [`RpcEvent`], so we no longer thread an OTel context through
		// the response path: the tracing span is the only telemetry
		// frame we keep here.
		let span = span_for_request(&rpc.id);
		// `len` is the inbound frame size in bytes. Surfaced through
		// `NetworkBytesEvent` above, no longer attached to a per-RPC
		// telemetry context.
		let _ = len;
		// Parse the request
		async move {
			let span = Span::current();
			// Parse the RPC request structure
			match rpc.format.req_ws(msg,rec_limit) {
				Ok(req) => {
					// Now that we know the method, update the tracing
					// span so structured fields show up on the
					// surrounding span and on any OTel-bridged trace.
					span.record("rpc.method", req.method.to_str());
					span.record("otel.name", format!("surrealdb.rpc/{}", req.method));
					span.record(
						"rpc.request_id",
						req.id.as_ref().map(|id| id.to_sql()).unwrap_or_default(),
					);
					// Capture the request id, session id and a cloned channel handle up-front so we
					// can still build a `DbResponse::failure` if the cancel branch wins the
					// select below — by the time it fires, `req` and `chn` will have been moved
					// into the inner `async move`.
					let req_id = req.id.clone();
					let req_session_id = req.session_id;
					let cancel_chn = chn.clone();
					let cancel_format = rpc.format;
					// Process the message
					tokio::select! {
						biased;
						// The connection-level `canceller` has fired: the in-flight handler
						// future is about to be dropped (along with any transaction it owns).
						// Resource cleanup is handled by each `Transactable::Drop` impl
						// (notably `DSTransaction::Drop`, which spawns a recovery abort), so
						// the only thing left to do here is to make sure the client receives a
						// terminating response — without it the SDK keeps awaiting a reply
						// that will never come and the connection deadlocks.
						_ = canceller.cancelled() => {
							crate::rpc::response::send(
								DbResponse::failure(req_id, req_session_id.map(Into::into), TypesError::internal(REQUEST_CANCELLED.to_string())),
								cancel_format,
								cancel_chn
							).await;
						},
						// Wait for the message to be processed
						_ = async move {
							// Don't start processing if we are gracefully shutting down
							if shutdown.is_cancelled() {
								// Process the response
								crate::rpc::response::send(
									DbResponse::failure(req.id, req.session_id.map(Into::into), TypesError::internal(SERVER_SHUTTING_DOWN.to_string())),
									rpc.format,
									chn
								).await;
							}
							// Check to see whether we have available memory
							else if ALLOC.is_beyond_threshold() {
								// Process the response
								crate::rpc::response::send(
									DbResponse::failure(req.id, req.session_id.map(Into::into), TypesError::internal(SERVER_OVERLOADED.to_string())),
									rpc.format,
									chn
								).await;
							}
							// Otherwise process the request message
							else {
								let client_session: Option<Uuid> = req.session_id.map(Into::into);
								let session_id = client_session.unwrap_or(rpc.id);
								// Process the message
								let result = Self::process_message(
									rpc.clone(),
									session_id,
									client_session,
									req.txn.map(Into::into),
									req.method,
									req.params,
								)
									.await;

								crate::rpc::response::send(
									match result {
										Ok(result) => DbResponse::success(req.id, req.session_id.map(Into::into), result),
										Err(err) => DbResponse::failure(req.id, req.session_id.map(Into::into), err),
									},
									rpc.format,
									chn
								).await;
							}
						} => (),
					}
				}
				Err(err) => {
					// Process the response
					crate::rpc::response::send(
						DbResponse::failure(None, None, err),
						rpc.format,
						chn
					).await;
				}
			}
		}
		.instrument(span)
		.await;
	}

	/// Process a WebSocket message and generate a response
	async fn process_message(
		rpc: Arc<Websocket>,
		session_id: Uuid,
		client_session: Option<Uuid>,
		txn: Option<Uuid>,
		method: Method,
		params: Array,
	) -> Result<DbResult, TypesError> {
		debug!("Process RPC request");
		// Check that the method is a valid method
		if !method.is_valid() {
			return Err(TypesError::not_found(
				"Method not found".to_string(),
				Some(surrealdb_types::NotFoundError::Method {
					name: method.to_string(),
				}),
			));
		}
		// Execute the specified method
		RpcProtocol::execute(rpc.as_ref(), txn, session_id, client_session, method, params).await
	}

	/// Reject a WebSocket message due to server overloading
	async fn close_socket(rpc: Arc<Websocket>, chn: Sender<Message>) {
		// Log the error as a warning
		warn!("The server is overloaded and is unable to process a WebSocket request");
		// Create a custom close frame
		let frame = CloseFrame {
			code: AGAIN,
			reason: SERVER_OVERLOADED.into(),
		};
		// Respond with a close message
		if let Err(err) = chn.send(Message::Close(Some(frame))).await {
			debug!("WebSocket error when sending close message: {err}");
		};
		// Cancel the WebSocket tasks
		rpc.canceller.cancel();
	}

	/// Snapshot the connection's default session into a
	/// [`NetworkBytesEventCtx`] for tenant attribution. Short-circuits
	/// to the default ctx when the installed observer is a no-op so
	/// community builds without an audit/dimensional observer pay
	/// nothing on the byte-counting hot path.
	///
	/// The session may flip namespace/database via `USE NS … DB …`
	/// during the connection's lifetime, so the snapshot is taken
	/// per-event rather than cached. The cost is at most three
	/// `String` clones plus a fast read-lock acquire — negligible
	/// compared to the actual frame transfer.
	async fn default_network_ctx(&self) -> NetworkBytesEventCtx {
		if self.datastore.observer().is_noop() {
			return NetworkBytesEventCtx::default();
		}
		match self.get_session(&self.id) {
			Ok(lock) => NetworkBytesEventCtx::from_session(&*lock.read().await),
			Err(_) => NetworkBytesEventCtx::default(),
		}
	}
}

impl RpcProtocol for Websocket {
	/// The datastore for this RPC interface
	fn kvs(&self) -> &Datastore {
		&self.datastore
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

	/// Lists all explicitly attached sessions on this connection.
	///
	/// WebSocket session maps are **per-connection** - the returned ids are only those the same
	/// client attached on the same socket, so enumeration cannot leak another user's session id
	/// (unlike the HTTP transport, where the underlying vulnerability originated). Filters out
	/// this connection's implicit default session keyed by `self.id` so clients cannot enumerate
	/// or target it via `detach`.
	async fn sessions(&self) -> Result<DbResult, TypesError> {
		let connection_id = self.id;
		let array: Array = self
			.session_map()
			.to_vec()
			.into_iter()
			.filter(|(key, _)| *key != connection_id)
			.map(|(key, _)| Value::Uuid(surrealdb_types::Uuid::from(key)))
			.collect();
		Ok(DbResult::Other(Value::Array(array)))
	}

	/// Registers a new session with the given ID, subject to the
	/// [`WEBSOCKET_MAX_ATTACHED_SESSIONS`] per-connection cap.
	///
	/// The implicit connection session keyed by `self.id` counts towards
	/// the cap so a client cannot sidestep it. Defence-in-depth against
	/// a client attempting to exhaust memory within a single connection.
	async fn attach(&self, session_id: Uuid) -> Result<DbResult, TypesError> {
		if self.session_map().contains_key(&session_id) {
			return Err(surrealdb_core::rpc::session_exists(session_id));
		}
		if self.session_map().len() >= *WEBSOCKET_MAX_ATTACHED_SESSIONS {
			return Err(surrealdb_core::rpc::method_not_allowed(Method::Attach.to_string()));
		}
		let mut session = Session::default().with_rt(Self::LQ_SUPPORT);
		session.id = Some(session_id);
		self.session_map().insert(session_id, Arc::new(RwLock::new(session)));
		Ok(DbResult::Other(Value::None))
	}

	/// Detaches an explicitly attached session.
	///
	/// Explicitly rejects attempts to detach the connection's implicit
	/// default session (`self.id`) as a defence-in-depth measure: tearing
	/// it down would leave the connection in an inconsistent state.
	async fn detach(&self, session_id: Uuid) -> Result<DbResult, TypesError> {
		if session_id == self.id {
			return Err(surrealdb_core::rpc::invalid_params(
				"Cannot detach the implicit connection session",
			));
		}
		self.del_session(&session_id).await;
		Ok(DbResult::Other(Value::None))
	}

	// ------------------------------
	// Transactions
	// ------------------------------

	/// Retrieves a transaction by ID
	async fn get_tx(
		&self,
		id: Uuid,
	) -> Result<Arc<surrealdb_core::kvs::Transaction>, surrealdb_types::Error> {
		debug!("WebSocket get_tx called for transaction {id}");
		self.transactions
			.get(&id)
			.map(|tx| {
				debug!("Transaction {id} found in WebSocket transactions map");
				tx.clone()
			})
			.ok_or_else(|| {
				warn!(
					"Transaction {id} not found in WebSocket transactions map (have {} transactions)",
					self.transactions.len()
				);
				surrealdb_core::rpc::invalid_params("Transaction not found")
			})
	}

	/// Stores a transaction
	async fn set_tx(
		&self,
		id: Uuid,
		tx: Arc<surrealdb_core::kvs::Transaction>,
	) -> Result<(), surrealdb_types::Error> {
		self.transactions.insert(id, tx);
		Ok(())
	}

	// ------------------------------
	// Realtime
	// ------------------------------

	/// Live queries are enabled on WebSockets
	const LQ_SUPPORT: bool = true;

	/// Handles the execution of a LIVE statement.
	///
	/// Increments the Prometheus `surrealdb_live_query_active` gauge when
	/// metrics are enabled so operators can alert on runaway subscriber counts
	/// without peeking at internal datastructures.
	async fn handle_live(&self, lqid: &Uuid, session_id: Uuid) {
		self.state.live_queries.write().await.insert(*lqid, (self.id, session_id));
		if let Some(obs) = self.state.metrics_observer.as_ref() {
			obs.adjust_live_query_active(1);
		}
		trace!("Registered live query {lqid} on websocket {}", self.id);
	}

	/// Handles the execution of a KILL statement.
	///
	/// Decrements the active LIVE query gauge only when a registration was
	/// actually removed so duplicate kills do not drift the counter negative.
	async fn handle_kill(&self, lqid: &Uuid) {
		if let Some((id, session_id)) = self.state.live_queries.write().await.remove(lqid) {
			if let Some(obs) = self.state.metrics_observer.as_ref() {
				obs.adjust_live_query_active(-1);
			}
			trace!("Unregistered live query {lqid} on websocket {id} for session {session_id}");
		}
	}

	/// Handles the cleanup of live queries for a given session.
	///
	/// Batches the gauge update by the number of LIVE queries that were
	/// actually garbage collected.
	async fn cleanup_lqs(&self, session_id: &Uuid) {
		let mut gc = Vec::new();
		// Find all live queries for to this connection
		self.state.live_queries.write().await.retain(|key, value| {
			if value.0 == self.id && value.1 == *session_id {
				trace!("Removing live query: {key}");
				gc.push(*key);
				return false;
			}
			true
		});
		if let Some(obs) = self.state.metrics_observer.as_ref() {
			// `gc.len() as i64` is safe: bounded by the number of live queries
			// we could plausibly register per session.
			obs.adjust_live_query_active(-(gc.len() as i64));
		}
		// Garbage collect the live queries on this connection
		if let Err(err) = self.kvs().delete_queries(gc).await {
			error!("Error handling RPC connection: {err}");
		}
	}

	/// Handles the cleanup of live queries on WebSocket close.
	///
	/// Drops the gauge by the number of LIVE queries attached to this
	/// connection so the metric tracks the live map exactly.
	async fn cleanup_all_lqs(&self) {
		let mut gc = Vec::new();
		// Find all live queries for to this connection
		self.state.live_queries.write().await.retain(|key, value| {
			if value.0 == self.id {
				trace!("Removing live query: {key}");
				gc.push(*key);
				return false;
			}
			true
		});
		if let Some(obs) = self.state.metrics_observer.as_ref() {
			obs.adjust_live_query_active(-(gc.len() as i64));
		}
		// Garbage collect the live queries on this connection
		if let Err(err) = self.kvs().delete_queries(gc).await {
			error!("Error handling RPC connection: {err}");
		}
	}

	// ------------------------------
	// Methods for transactions
	// ------------------------------

	/// Begin a new transaction
	async fn begin(
		&self,
		_txn: Option<Uuid>,
		_session_id: Uuid,
	) -> Result<DbResult, surrealdb_types::Error> {
		// Create a new transaction
		let tx = self
			.kvs()
			.transaction(TransactionType::Write, LockType::Optimistic)
			.await
			.map_err(surrealdb_core::rpc::types_error_from_anyhow)?;
		// Generate a unique transaction ID
		let id = Uuid::now_v7();
		debug!("WebSocket begin: created transaction {id}");
		// Store the transaction in the map
		self.transactions.insert(id, Arc::new(tx));
		debug!(
			"WebSocket begin: stored transaction {id}, map now has {} transactions",
			self.transactions.len()
		);
		// Return the transaction ID to the client
		Ok(DbResult::Other(Value::Uuid(surrealdb::types::Uuid::from(id))))
	}

	/// Commit a transaction
	async fn commit(
		&self,
		_txn: Option<Uuid>,
		_session_id: Uuid,
		params: Array,
	) -> Result<DbResult, surrealdb_types::Error> {
		// Extract the transaction ID from params
		let mut params_vec = params.into_vec();
		let Some(Value::Uuid(txn_id)) = params_vec.pop() else {
			return Err(surrealdb_core::rpc::invalid_params("Expected transaction UUID"));
		};

		let txn_id = txn_id.into_inner();

		// Retrieve and remove the transaction from the map
		let Some((_, tx)) = self.transactions.remove(&txn_id) else {
			return Err(surrealdb_core::rpc::invalid_params("Transaction not found"));
		};

		// Commit the transaction
		tx.commit().await.map_err(surrealdb_core::rpc::types_error_from_anyhow)?;

		// Return success
		Ok(DbResult::Other(Value::None))
	}

	/// Cancel a transaction
	async fn cancel(
		&self,
		_txn: Option<Uuid>,
		_session_id: Uuid,
		params: Array,
	) -> Result<DbResult, surrealdb_types::Error> {
		// Extract the transaction ID from params
		let mut params_vec = params.into_vec();
		let Some(Value::Uuid(txn_id)) = params_vec.pop() else {
			return Err(surrealdb_core::rpc::invalid_params("Expected transaction UUID"));
		};

		let txn_id = txn_id.into_inner();

		// Retrieve and remove the transaction from the map
		let Some((_, tx)) = self.transactions.remove(&txn_id) else {
			return Err(surrealdb_core::rpc::invalid_params("Transaction not found"));
		};

		// Cancel the transaction
		tx.cancel().await.map_err(surrealdb_core::rpc::types_error_from_anyhow)?;

		// Return success
		Ok(DbResult::Other(Value::None))
	}
}

#[cfg(test)]
mod tests {
	use std::sync::{Arc, Mutex};

	use surrealdb_core::iam::{Auth, Role};
	use surrealdb_core::kvs::Datastore;
	use surrealdb_core::observe::{
		AuthEvent, ExecutionObserver, NetworkBytesEvent, QueryEvent, RpcEvent, SessionEvent,
		StatementEvent, TransactionEvent,
	};

	use super::*;

	/// Trivial non-noop observer used to exercise the populated-ctx
	/// branch of `default_network_ctx`. The default `is_noop` impl
	/// returns `false`, which is exactly what we need.
	#[derive(Default)]
	struct CapturingObserver {
		events: Mutex<Vec<NetworkBytesEvent>>,
	}

	impl ExecutionObserver for CapturingObserver {
		fn on_statement_complete(&self, _e: &StatementEvent) {}
		fn on_query_complete(&self, _e: &QueryEvent) {}
		fn on_transaction_complete(&self, _e: &TransactionEvent) {}
		fn on_rpc_complete(&self, _e: &RpcEvent) {}
		fn on_auth_event(&self, _e: &AuthEvent) {}
		fn on_session_event(&self, _e: &SessionEvent) {}
		fn on_network_bytes(&self, e: &NetworkBytesEvent) {
			self.events.lock().unwrap().push(e.clone());
		}
	}

	async fn ws_with_observer(observer: Option<Arc<dyn ExecutionObserver>>) -> Arc<Websocket> {
		let mut builder = Datastore::builder();
		if let Some(obs) = observer {
			builder = builder.with_observer(obs);
		}
		let ds = Arc::new(builder.build_with_path("memory").await.unwrap());
		let state = Arc::new(crate::rpc::RpcState::new(ds.clone()));
		let id = Uuid::new_v4();
		let (tx, _rx) = channel::<Message>(8);
		Arc::new(Websocket {
			id,
			format: Format::Json,
			state,
			datastore: ds,
			sessions: HashMap::new(),
			transactions: DashMap::new(),
			shutdown: CancellationToken::new(),
			canceller: CancellationToken::new(),
			channel: tx,
		})
	}

	#[tokio::test]
	async fn default_network_ctx_short_circuits_on_noop_observer() {
		// Default `Datastore` builds with a `NoopObserver`; the helper
		// must skip the lock entirely and return the default ctx so
		// community builds pay nothing on the byte hot path. We
		// install a fully-populated session under the connection id;
		// if the helper bypassed the noop check it would surface the
		// session fields, so an empty ctx proves the short-circuit
		// path was taken.
		let rpc = ws_with_observer(None).await;
		let sess = Session {
			au: Arc::new(Auth::for_root(Role::Owner)),
			..Session::default()
		}
		.with_ns("acme")
		.with_db("prod");
		rpc.session_map().insert(rpc.id, Arc::new(RwLock::new(sess)));

		let ctx = rpc.default_network_ctx().await;
		assert!(ctx.namespace.is_none(), "noop observer must not consult the session");
		assert!(ctx.database.is_none());
		assert!(ctx.user.is_none());
	}

	#[tokio::test]
	async fn default_network_ctx_reads_session_under_active_observer() {
		// With a non-noop observer, the helper must read
		// `(ns, db, user)` from the connection's default session.
		let observer: Arc<dyn ExecutionObserver> = Arc::new(CapturingObserver::default());
		let rpc = ws_with_observer(Some(observer)).await;
		let sess = Session {
			au: Arc::new(Auth::for_root(Role::Owner)),
			..Session::default()
		}
		.with_ns("acme")
		.with_db("prod");
		rpc.session_map().insert(rpc.id, Arc::new(RwLock::new(sess)));

		let ctx = rpc.default_network_ctx().await;
		assert_eq!(ctx.namespace.as_deref(), Some("acme"));
		assert_eq!(ctx.database.as_deref(), Some("prod"));
		assert_eq!(ctx.user.as_deref(), Some("system_auth"));
	}

	#[tokio::test]
	async fn default_network_ctx_with_missing_session_returns_default() {
		// Active observer but no session under `self.id` (corner case
		// during disconnect/teardown). The helper must fall back to
		// the default ctx rather than panic or block.
		let observer: Arc<dyn ExecutionObserver> = Arc::new(CapturingObserver::default());
		let rpc = ws_with_observer(Some(observer)).await;
		let ctx = rpc.default_network_ctx().await;
		assert!(ctx.namespace.is_none());
		assert!(ctx.database.is_none());
		assert!(ctx.user.is_none());
	}
}
