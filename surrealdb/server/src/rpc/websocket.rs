use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::close_code::AGAIN;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use futures::{Sink, SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry_http::HeaderExtractor;
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
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
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

/// Build an OTel parent `Context` from W3C Trace Context propagation
/// headers carried in the RPC envelope's `trace_context` field. Reuses
/// the `HeaderMap`-based `HeaderExtractor` so the same propagator path
/// is used as for HTTP — the only difference is where the headers come
/// from. Returns `None` when the map produces no usable entries, so the
/// caller can leave the span as a fresh root rather than parent it to
/// an empty context.
fn extract_trace_context(
	trace_context: &std::collections::HashMap<String, String>,
) -> Option<opentelemetry::Context> {
	let mut headers = HeaderMap::with_capacity(trace_context.len());
	for (k, v) in trace_context {
		if let (Ok(name), Ok(value)) =
			(HeaderName::try_from(k.as_str()), HeaderValue::try_from(v.as_str()))
		{
			headers.insert(name, value);
		}
	}
	if headers.is_empty() {
		return None;
	}
	Some(opentelemetry::global::get_text_map_propagator(|propagator| {
		propagator.extract(&HeaderExtractor(&headers))
	}))
}

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
			state: Arc::clone(&state),
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
		state.web_sockets.write().await.insert(id, Arc::clone(&rpc));
		// Emit a session connect event so observability sinks can track
		// simultaneous connections without consulting the datastore.
		// `MetricsObserver::on_session_event` increments
		// `surrealdb.session.active` (UpDown gauge) and
		// `surrealdb.session.total` (counter) from this dispatch.
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
				tasks.spawn(Self::ping(Arc::clone(&rpc), sender.clone()));
				tasks.spawn(Self::read(Arc::clone(&rpc), ws_receiver, sender.clone(), rec_limit));
				tasks.spawn(Self::write(Arc::clone(&rpc), ws_sender, receiver));
			}
			false => {
				// Split the socket into sending and receiving streams
				let (ws_sender, ws_receiver) = ws.split();
				// Spawn async tasks for the WebSocket
				tasks.spawn(Self::ping(Arc::clone(&rpc), sender.clone()));
				tasks.spawn(Self::read(Arc::clone(&rpc), ws_receiver, sender.clone(), rec_limit));
				tasks.spawn(Self::write(Arc::clone(&rpc), ws_sender, receiver));
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
		// time. `MetricsObserver::on_session_event` decrements
		// `surrealdb.session.active` and records the elapsed time on
		// `surrealdb.session.duration`.
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
								Self::close_socket(Arc::clone(&rpc), chn).await;
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
		// Parse the RPC envelope synchronously BEFORE `.instrument(span)`.
		//
		// Both pre-populating the span (rpc.method / otel.name /
		// rpc.request_id) and attaching the propagated OTel parent
		// (`req.trace_context`) must happen while the underlying
		// `tracing_opentelemetry::OtelData` is still in `Builder` state.
		// `Instrumented::poll` enters the wrapped span on its first
		// poll, which fires `on_enter` in the OTel `Layer` and calls
		// `start_with_context`, transitioning the state from `Builder`
		// to `Context` and freezing the span's `trace_id` from whatever
		// parent context was on the builder at that moment. After that
		// transition, `set_parent` returns `Err(AlreadyStarted)` and is
		// silently dropped — the WS span would surface in OTLP under a
		// fresh root trace, defeating per-message W3C propagation. The
		// regression test below
		// (`set_parent_before_instrument_attaches_remote_trace_id`)
		// guards this ordering.
		let parsed = rpc.format.req_ws(msg, rec_limit);
		if let Ok(req) = &parsed {
			// Now that we know the method, update the tracing span so
			// structured fields show up on any OTel-bridged trace.
			span.record("rpc.method", req.method.to_str());
			span.record("otel.name", format!("surrealdb.rpc/{}", req.method));
			span.record(
				"rpc.request_id",
				req.id.as_ref().map(|id| id.to_sql()).unwrap_or_default(),
			);
			// If the client included W3C Trace Context propagation
			// headers in the RPC envelope, use them as the OTel parent
			// of the per-message span. WebSocket has no per-message
			// header layer, so the context lives on the message body
			// under `trace_context`. Invalid entries are silently
			// dropped: `HeaderMap` rejects non-ASCII names/values, but
			// the propagator handles the resulting empty map
			// gracefully by producing a no-op parent. SDKs that don't
			// emit `trace_context` get today's behavior (fresh root
			// span per message).
			if let Some(trace_context) = req.trace_context.as_ref()
				&& let Some(parent_cx) = extract_trace_context(trace_context)
			{
				// `set_parent` returns `Err(SetParentError::LayerNotFound)`
				// when the OTel bridge layer isn't registered (OTLP
				// export disabled). Non-actionable here, so discard.
				let _ = span.set_parent(parent_cx);
			}
		}
		async move {
			match parsed {
				Ok(req) => {
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
									Arc::clone(rpc),
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
	/// Increments the `surrealdb.live_query.active` gauge (rendered by
	/// Prometheus as `surrealdb_live_query_active`) when metrics are enabled
	/// so operators can alert on runaway subscriber counts without peeking
	/// at internal datastructures. The gauge is labelled by the registering
	/// session's namespace and database so operators can pinpoint the
	/// tenant driving the load.
	///
	/// `namespace` and `database` are snapshotted by `run_query` off the
	/// read guard it already holds on the session lock, and passed down
	/// here so this function does NOT re-acquire that lock. Re-locking
	/// would be a recursive read on a write-preferring `RwLock` and
	/// would deadlock against any concurrent session-mutating RPC on
	/// the same WebSocket.
	async fn handle_live(
		&self,
		lqid: &Uuid,
		session_id: Uuid,
		namespace: Option<String>,
		database: Option<String>,
	) {
		self.state.live_queries.write().await.insert(
			*lqid,
			crate::rpc::LiveQueryEntry {
				websocket_id: self.id,
				session_id,
				namespace: namespace.clone(),
				database: database.clone(),
			},
		);
		if let Some(obs) = self.state.metrics_observer.as_ref() {
			obs.adjust_live_query_active(1, namespace.as_deref(), database.as_deref());
		}
		trace!("Registered live query {lqid} on websocket {}", self.id);
	}

	/// Handles the execution of a KILL statement.
	///
	/// Decrements the active LIVE query gauge only when a registration was
	/// actually removed so duplicate kills do not drift the counter negative.
	/// The decrement uses the namespace/database stashed at registration time
	/// so the gauge series is balanced even when the killing session has
	/// since switched namespaces.
	async fn handle_kill(&self, lqid: &Uuid) {
		if let Some(entry) = self.state.live_queries.write().await.remove(lqid) {
			if let Some(obs) = self.state.metrics_observer.as_ref() {
				obs.adjust_live_query_active(
					-1,
					entry.namespace.as_deref(),
					entry.database.as_deref(),
				);
			}
			trace!(
				"Unregistered live query {lqid} on websocket {} for session {}",
				entry.websocket_id, entry.session_id,
			);
		}
	}

	/// Handles the cleanup of live queries for a given session.
	///
	/// Drops the gauge per-entry using the namespace/database recorded at
	/// registration time so the gauge stays balanced even when entries on
	/// the same WebSocket span multiple namespaces.
	async fn cleanup_lqs(&self, session_id: &Uuid) {
		self.cleanup_lqs_filtered(Some(session_id)).await;
	}

	/// Handles the cleanup of live queries on WebSocket close.
	///
	/// Drops the gauge by the number of LIVE queries attached to this
	/// connection so the metric tracks the live map exactly. Each
	/// decrement uses the per-entry NS/DB so the gauge stays balanced.
	async fn cleanup_all_lqs(&self) {
		self.cleanup_lqs_filtered(None).await;
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

impl Websocket {
	/// Shared body for [`Self::cleanup_lqs`] and [`Self::cleanup_all_lqs`].
	///
	/// `session_filter` narrows the cleanup to a specific session id when
	/// `Some`, or matches every LIVE entry on this WebSocket when `None`
	/// (the connection-close path).
	///
	/// The NS/DB clones needed for the gauge decrements are gated on
	/// `metrics_observer.is_some()` so a connection running without
	/// metrics enabled does not pay 2N heap allocations on disconnect.
	async fn cleanup_lqs_filtered(&self, session_filter: Option<&Uuid>) {
		let want_metrics = self.state.metrics_observer.is_some();
		let mut gc = Vec::new();
		let mut decrements: Vec<(Option<String>, Option<String>)> = Vec::new();
		// Find all live queries on this connection that match the filter.
		self.state.live_queries.write().await.retain(|key, entry| {
			if entry.websocket_id != self.id {
				return true;
			}
			if let Some(sid) = session_filter
				&& entry.session_id != *sid
			{
				return true;
			}
			trace!("Removing live query: {key}");
			gc.push(*key);
			if want_metrics {
				decrements.push((entry.namespace.clone(), entry.database.clone()));
			}
			false
		});
		if let Some(obs) = self.state.metrics_observer.as_ref() {
			for (ns, db) in &decrements {
				obs.adjust_live_query_active(-1, ns.as_deref(), db.as_deref());
			}
		}
		// Garbage collect the live queries on this connection
		if let Err(err) = self.kvs().delete_queries(gc).await {
			error!("Error handling RPC connection: {err}");
		}
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
		let state = Arc::new(crate::rpc::RpcState::new(Arc::clone(&ds)));
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

	/// Install the W3C trace-context propagator once per process. The
	/// `extract_trace_context_*` tests share it because
	/// `set_text_map_propagator` is process-global; running them with no
	/// installed propagator would silently exercise the no-op default
	/// and produce empty contexts, masking regressions.
	fn ensure_propagator() {
		use std::sync::Once;
		static INIT: Once = Once::new();
		INIT.call_once(|| {
			opentelemetry::global::set_text_map_propagator(
				opentelemetry_sdk::propagation::TraceContextPropagator::new(),
			);
		});
	}

	#[test]
	fn extract_trace_context_with_traceparent_returns_remote_context() {
		use opentelemetry::trace::TraceContextExt;
		ensure_propagator();
		let mut map = std::collections::HashMap::new();
		map.insert(
			"traceparent".to_string(),
			"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
		);
		let cx = extract_trace_context(&map).expect("should produce a context");
		let span = cx.span();
		let span_cx = span.span_context();
		assert!(span_cx.is_valid(), "extracted span context should be valid");
		assert_eq!(format!("{}", span_cx.trace_id()), "0af7651916cd43dd8448eb211c80319c");
		assert_eq!(format!("{}", span_cx.span_id()), "b7ad6b7169203331");
		assert!(span_cx.is_remote(), "context must mark the parent as remote");
	}

	#[test]
	fn extract_trace_context_empty_map_returns_none() {
		ensure_propagator();
		let map = std::collections::HashMap::new();
		assert!(extract_trace_context(&map).is_none());
	}

	#[test]
	fn extract_trace_context_invalid_header_name_drops_entry() {
		// HTTP header names disallow whitespace; the entry is silently
		// skipped during `HeaderMap` construction, the map ends up empty,
		// and we return `None` rather than parenting the span to a no-op
		// context.
		ensure_propagator();
		let mut map = std::collections::HashMap::new();
		map.insert("not a valid header name".to_string(), "value".to_string());
		assert!(extract_trace_context(&map).is_none());
	}

	#[test]
	fn extract_trace_context_invalid_traceparent_value_yields_invalid_context() {
		// Junk traceparent value is accepted by `HeaderMap` (any ASCII
		// passes), but `TraceContextPropagator::extract` rejects it and
		// returns an empty context. The function still returns `Some`
		// because the map wasn't empty — `set_parent` on an empty context
		// is a harmless no-op, matching today's "fresh root" behavior.
		ensure_propagator();
		let mut map = std::collections::HashMap::new();
		map.insert("traceparent".to_string(), "garbage".to_string());
		let cx = extract_trace_context(&map).expect("non-empty map produces Some");
		use opentelemetry::trace::TraceContextExt;
		let span = cx.span();
		assert!(!span.span_context().is_valid());
	}

	/// Build a tracing subscriber with the OTel bridge layer attached
	/// to a real `SdkTracerProvider`. The provider has no exporter, but
	/// that's fine: the OTel layer's state machine (`OtelData::Builder`
	/// → `OtelData::Context`) and `OpenTelemetrySpanExt::set_parent`
	/// returns are what we want to exercise.
	fn otel_test_subscriber() -> (
		impl tracing::Subscriber + Send + Sync + 'static,
		opentelemetry_sdk::trace::SdkTracerProvider,
	) {
		use opentelemetry::trace::TracerProvider as _;
		use opentelemetry_sdk::trace::SdkTracerProvider;
		use tracing_subscriber::prelude::*;
		let provider = SdkTracerProvider::builder().build();
		let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));
		let subscriber = tracing_subscriber::registry().with(layer);
		(subscriber, provider)
	}

	#[test]
	fn set_parent_before_instrument_attaches_remote_trace_id() {
		// Regression test for the WS propagation ordering bug.
		//
		// `tracing_opentelemetry 0.32.1` carries an explicit state
		// machine: a span starts in `OtelData::Builder { parent_cx }`
		// and transitions to `OtelData::Context { current_cx }` the
		// first time `on_enter` fires (i.e. on the first poll of an
		// `Instrumented` future). `set_parent` only mutates the parent
		// while the state is `Builder`; once it's `Context`, the trace
		// id is frozen and the call returns `Err(AlreadyStarted)`.
		//
		// The production code in `handle_message` parses the envelope
		// and calls `set_parent` BEFORE wrapping the future in
		// `.instrument(span)`, so the call lands on a `Builder`-state
		// span and the remote trace id propagates through. This test
		// asserts that ordering: `set_parent` returns `Ok(())` and the
		// span's resolved context carries the parent's trace id.
		use opentelemetry::trace::TraceContextExt;
		ensure_propagator();
		let (subscriber, _provider) = otel_test_subscriber();
		tracing::subscriber::with_default(subscriber, || {
			let mut map = std::collections::HashMap::new();
			map.insert(
				"traceparent".to_string(),
				"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
			);
			let parent_cx = extract_trace_context(&map).expect("Some");

			let span = span_for_request(&Uuid::new_v4());
			// Span is in `Builder` state — `set_parent` must succeed.
			span.set_parent(parent_cx).expect("set_parent must succeed on Builder-state span");

			// Resolve the span's OTel context. `OpenTelemetrySpanExt::context`
			// forces the Builder→Context transition internally if needed and
			// returns the resulting context.
			let cx = span.context();
			let active = cx.span();
			let span_cx = active.span_context();
			assert!(span_cx.is_valid(), "span context should be valid after activation");
			assert_eq!(
				format!("{}", span_cx.trace_id()),
				"0af7651916cd43dd8448eb211c80319c",
				"span's resolved trace_id must match the propagated parent",
			);
		});
	}

	#[test]
	fn set_parent_after_span_entered_returns_already_started() {
		// Documents the bug the production code avoids. Once the span
		// has been entered (which `.instrument(span).await` does on
		// the first poll), `OtelData` transitions from `Builder` to
		// `Context` and `set_parent` becomes a no-op returning
		// `Err(AlreadyStarted)`. If anyone refactors `handle_message`
		// to call `set_parent` from inside the instrumented async
		// block, this test catches it.
		ensure_propagator();
		let (subscriber, _provider) = otel_test_subscriber();
		tracing::subscriber::with_default(subscriber, || {
			let mut map = std::collections::HashMap::new();
			map.insert(
				"traceparent".to_string(),
				"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
			);
			let parent_cx = extract_trace_context(&map).expect("Some");

			let span = span_for_request(&Uuid::new_v4());
			// Enter the span to simulate what `Instrumented::poll`
			// does before the wrapped future runs. `on_enter` consumes
			// the `SpanBuilder` and the state becomes `Context`.
			let _enter = span.enter();
			let err = span
				.set_parent(parent_cx)
				.expect_err("set_parent on entered span must return AlreadyStarted");
			assert!(
				matches!(err, tracing_opentelemetry::SetParentError::AlreadyStarted),
				"expected AlreadyStarted, got {err:?}",
			);
		});
	}
}
