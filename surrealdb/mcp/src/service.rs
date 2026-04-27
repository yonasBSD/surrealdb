//! MCP ServerHandler implementation for SurrealDB.
//!
//! `McpService` is the core MCP server type. One instance is created per MCP
//! session via the factory closure in `StreamableHttpService`.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use surrealdb_core::dbs::Session;
use surrealdb_core::kvs::Datastore;
use tokio::sync::OnceCell;
use web_time::Instant;

use crate::auth::{self, BoundSubject};
use crate::cnf::McpConfig;
use crate::session::McpSession;
use crate::tools::{connection, crud, query, run as run_tool, schema};
use crate::{audit, completions, prompts, resources};

const LOG: &str = "surrealdb::mcp";

/// The MCP server handler for SurrealDB.
#[derive(Clone)]
pub struct McpService {
	session: Arc<OnceCell<McpSession>>,
	/// Subject fingerprint captured at `initialize`. Used by
	/// [`McpService::verify_request_subject`] to reject inbound requests
	/// that present a *different* authenticated identity on the same MCP
	/// session id (the spec's "MUST verify all inbound requests" rule).
	/// Stored alongside the [`McpSession`] so both share a lifetime.
	bound_subject: Arc<OnceCell<BoundSubject>>,
	datastore: Arc<Datastore>,
	default_ns: Option<String>,
	default_db: Option<String>,
	/// Fallback session used when no authenticated session is attached to the
	/// incoming request context (e.g. the STDIO transport). HTTP callers go
	/// through `SurrealAuth` middleware and always supply a session via the
	/// request parts, so this is only consulted for in-process transports.
	base_session: Session,
	/// MCP-side runtime configuration. Cloned into every [`McpSession`] so
	/// handlers read caps off the session rather than process-global
	/// statics. See [`McpConfig`] for the available knobs.
	config: Arc<McpConfig>,
	#[allow(dead_code)] // Read by #[tool_handler] macro-generated code
	tool_router: ToolRouter<Self>,
}

/// Builder-style configuration for [`McpService`].
///
/// The positional `McpService::new(ds, ns, db, session)` signature has two
/// `Option<String>` parameters that are easy to transpose accidentally.
/// Prefer this builder in new code; [`McpService::new`] is kept for
/// compatibility.
#[derive(Clone)]
pub struct McpServiceConfig {
	datastore: Arc<Datastore>,
	default_ns: Option<String>,
	default_db: Option<String>,
	base_session: Session,
	config: Arc<McpConfig>,
}

impl McpServiceConfig {
	/// Start a fresh config for the given datastore.
	///
	/// `base_session` defaults to [`Session::default`]. In-process callers
	/// (e.g. `surreal mcp` stdio) that want pre-authenticated root access
	/// should call [`Self::with_base_session`] with [`Session::owner`].
	///
	/// The MCP runtime configuration is loaded from the `SURREAL_MCP_*`
	/// environment by default; embedders that don't want env auto-loading
	/// can override it via [`Self::with_config`].
	pub fn new(datastore: Arc<Datastore>) -> Self {
		Self {
			datastore,
			default_ns: None,
			default_db: None,
			base_session: Session::default(),
			config: McpConfig::from_env(),
		}
	}

	/// Set the default namespace applied to any session that doesn't
	/// already carry one.
	pub fn with_default_namespace(mut self, ns: impl Into<String>) -> Self {
		self.default_ns = Some(ns.into());
		self
	}

	/// Set the default database applied to any session that doesn't
	/// already carry one.
	pub fn with_default_database(mut self, db: impl Into<String>) -> Self {
		self.default_db = Some(db.into());
		self
	}

	/// Override the fallback [`Session`] used when no HTTP auth context is
	/// attached to the request (e.g. the STDIO transport).
	pub fn with_base_session(mut self, session: Session) -> Self {
		self.base_session = session;
		self
	}

	/// Override the MCP runtime configuration. Use this when an embedder
	/// has its own configuration source and shouldn't be reading
	/// `SURREAL_MCP_*` from the process environment.
	pub fn with_config(mut self, config: Arc<McpConfig>) -> Self {
		self.config = config;
		self
	}

	/// Consume the builder and construct an [`McpService`].
	pub fn build(self) -> McpService {
		McpService::new_with_config(
			self.datastore,
			self.default_ns,
			self.default_db,
			self.base_session,
			self.config,
		)
	}
}

impl McpService {
	/// Construct a new `McpService`.
	///
	/// Prefer [`McpServiceConfig`] for new call sites -- it avoids the
	/// positional `Option<String>, Option<String>` footgun. This
	/// constructor is retained for backwards-compatibility with existing
	/// callers.
	///
	/// `base_session` is used as the session when no HTTP auth context is
	/// present on the request (the STDIO transport case). Callers exposing a
	/// network surface should pass `Session::default()` and rely on the
	/// HTTP auth middleware to attach an authenticated session; in-process
	/// callers (e.g. `surreal mcp` stdio) should pass `Session::owner()`.
	pub fn new(
		datastore: Arc<Datastore>,
		default_ns: Option<String>,
		default_db: Option<String>,
		base_session: Session,
	) -> Self {
		// Default constructor loads MCP configuration from the
		// `SURREAL_MCP_*` environment, matching the behaviour of every
		// public binary (`surreal mcp`, the HTTP `/mcp` route).
		Self::new_with_config(
			datastore,
			default_ns,
			default_db,
			base_session,
			McpConfig::from_env(),
		)
	}

	/// Construct a new `McpService` with an explicit [`McpConfig`].
	///
	/// Used by [`McpServiceConfig::build`] and by tests / embedders that
	/// want to override the cap defaults without going via the
	/// `SURREAL_MCP_*` environment.
	pub fn new_with_config(
		datastore: Arc<Datastore>,
		default_ns: Option<String>,
		default_db: Option<String>,
		base_session: Session,
		config: Arc<McpConfig>,
	) -> Self {
		let mut tool_router = Self::tool_router();
		crate::tools::output_schemas::attach(&mut tool_router);
		Self {
			session: Arc::new(OnceCell::new()),
			bound_subject: Arc::new(OnceCell::new()),
			datastore,
			default_ns,
			default_db,
			base_session,
			config,
			tool_router,
		}
	}

	fn session(&self) -> Result<&McpSession, McpError> {
		self.session
			.get()
			.ok_or_else(|| McpError::internal_error("MCP session not initialized", None))
	}

	/// Get a reference to the inner session, if initialized.
	pub fn session_ref(&self) -> Result<&McpSession, McpError> {
		self.session()
	}

	/// Initialize the session. Called during MCP handshake.
	///
	/// Records the [`BoundSubject`] fingerprint of `session` so subsequent
	/// inbound requests on the same MCP session id can be verified against
	/// it. Calling `init_session` more than once on the same `McpService`
	/// is a protocol error.
	pub fn init_session(&self, session: Session) -> Result<(), McpError> {
		let subject = BoundSubject::from_session(&session);
		let mcp_session =
			McpSession::with_config(self.datastore.clone(), session, self.config.clone());
		self.session
			.set(mcp_session)
			.map_err(|_| McpError::internal_error("Session already initialized", None))?;
		// Use `OnceCell::set` here too — failing means the subject was
		// previously bound (which should never happen because session-set
		// already errored above), but the redundancy keeps the two cells
		// in lock-step.
		let _ = self.bound_subject.set(subject);
		Ok(())
	}

	/// Reject an inbound request that presents authenticated credentials
	/// disagreeing with the subject bound at `initialize` time.
	///
	/// Three outcomes (see [`crate::auth::check_subject`]):
	///
	/// - No credentials on the request (stdio, or HTTP without auth): allowed; the bound session
	///   continues to serve the call.
	/// - Same authenticated subject as binding: allowed.
	/// - Different authenticated subject than binding: rejected with `invalid_params`.
	fn verify_request_subject(&self, ctx: &RequestContext<RoleServer>) -> Result<(), McpError> {
		let Some(bound) = self.bound_subject.get() else {
			// If `init_session` was never called, `bound_subject` is
			// empty; return a protocol-level error so the caller knows
			// to send `initialize` first.
			return Err(McpError::internal_error(
				"MCP session not initialized: send `initialize` first",
				None,
			));
		};
		let incoming = auth::incoming_subject(ctx);
		auth::check_subject(bound, incoming)
	}

	/// Stable audit label for the bound subject. Returns `"unbound"`
	/// before `initialize` (only reachable from internal logging on
	/// pathological code paths).
	fn bound_subject_label(&self) -> String {
		self.bound_subject.get().map(BoundSubject::audit_label).unwrap_or_else(|| "unbound".into())
	}

	/// Verify the request, run `handler`, and emit the canonical audit
	/// log line for the invocation. Centralises the boilerplate every
	/// `#[tool]` would otherwise repeat (verify → time → audit) so the
	/// individual handlers stay focused on the SurrealQL they execute.
	///
	/// The verification step is run *inside* the timed inner block so
	/// credential-mismatch rejections and "session not initialized"
	/// failures still emit one canonical audit record per attempt,
	/// classified as [`audit::Outcome::ProtocolError`]. This is the
	/// detection surface operators forward to a SIEM to spot session
	/// hijack attempts; silently dropping the rejection from the audit
	/// feed would defeat the spec-mandated subject-binding defence.
	///
	/// Uses [`AsyncFnOnce`] so callers can pass a normal `async |s| { ... }`
	/// closure that borrows `s: &McpSession` for the duration of the
	/// returned future without needing explicit `BoxFuture` machinery.
	async fn dispatch_tool<F>(
		&self,
		tool: &'static str,
		ctx: &RequestContext<RoleServer>,
		handler: F,
	) -> Result<CallToolResult, McpError>
	where
		F: AsyncFnOnce(&McpSession) -> Result<CallToolResult, McpError>,
	{
		let subject = self.bound_subject_label();
		// Snapshot ns/db best-effort. If the session isn't initialized
		// yet we still want the audit record to fire, so fall back to
		// `(None, None)` rather than short-circuiting before the log.
		let (ns, db) = match self.session.get() {
			Some(s) => s.current_ns_db().await,
			None => (None, None),
		};
		let started = Instant::now();
		let outcome: Result<CallToolResult, McpError> = async {
			self.verify_request_subject(ctx)?;
			let session = self.session()?;
			handler(session).await
		}
		.await;
		let elapsed = started.elapsed();
		let (kind, kind_str) = audit::classify(&outcome);
		audit::record(tool, &subject, ns.as_deref(), db.as_deref(), kind, &kind_str, elapsed);
		outcome
	}
}

// ---------------------------------------------------------------------------
// Tool implementations -- use types from tools/ modules directly
// ---------------------------------------------------------------------------

// Tool annotations follow the MCP 2025-06-18 hint spec:
// - `read_only_hint = true` for tools that never write.
// - `destructive_hint = true` for tools that may mutate or remove data.
// - `idempotent_hint = true` for tools where repeated calls with the same arguments produce the
//   same result with no additional side effects.
// - `open_world_hint = false` everywhere because no MCP tool reaches the network on its own — every
//   effect is bounded by the local datastore and its capability rules.
#[tool_router]
impl McpService {
	#[tool(
		description = "Execute a SurrealQL query with optional parameterized inputs. Use $param syntax for placeholders and provide bindings in the parameters object.",
		annotations(
			title = "Run SurrealQL",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn query(
		&self,
		Parameters(p): Parameters<query::QueryParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("query", &ctx, async |s| query::execute(s, p).await).await
	}

	#[tool(
		description = "SELECT records with optional filtering, sorting, and pagination. `fields`, `where_clause`, `order_clause`, `group_clause`, and `split_clause` are raw SurrealQL expression fragments -- use the `query` tool with $param bindings for dynamic values.",
		annotations(
			title = "Select records",
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		)
	)]
	async fn select(
		&self,
		Parameters(p): Parameters<crud::SelectParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("select", &ctx, async |s| crud::select(s, p).await).await
	}

	#[tool(
		description = "CREATE a new record with optional content data. Data is bound as a typed variable.",
		annotations(
			title = "Create record",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn create(
		&self,
		Parameters(p): Parameters<crud::CreateParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("create", &ctx, async |s| crud::create(s, p).await).await
	}

	#[tool(
		description = "INSERT records into a table. Data is bound as a typed variable. Supports IGNORE and RELATION flags.",
		annotations(
			title = "Insert records",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn insert(
		&self,
		Parameters(p): Parameters<crud::InsertParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("insert", &ctx, async |s| crud::insert(s, p).await).await
	}

	#[tool(
		description = "UPSERT records with CONTENT, MERGE, or PATCH mode. Data is bound as a typed variable. `where_clause` is a SurrealQL expression fragment -- use the `query` tool with $param bindings for dynamic values.",
		annotations(
			title = "Upsert records",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn upsert(
		&self,
		Parameters(p): Parameters<crud::UpsertParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("upsert", &ctx, async |s| crud::upsert(s, p).await).await
	}

	#[tool(
		description = "UPDATE existing records with CONTENT, MERGE, or PATCH mode. Data is bound as a typed variable. `where_clause` is a SurrealQL expression fragment -- use the `query` tool with $param bindings for dynamic values.",
		annotations(
			title = "Update records",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn update(
		&self,
		Parameters(p): Parameters<crud::UpdateParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("update", &ctx, async |s| crud::update(s, p).await).await
	}

	#[tool(
		description = "DELETE records with an optional WHERE clause. `where_clause` is a SurrealQL expression fragment -- use the `query` tool with $param bindings for dynamic values.",
		annotations(
			title = "Delete records",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = true,
			open_world_hint = false
		)
	)]
	async fn delete(
		&self,
		Parameters(p): Parameters<crud::DeleteParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("delete", &ctx, async |s| crud::delete(s, p).await).await
	}

	#[tool(
		description = "RELATE records to create graph edges (from->table->to). Optional content is bound as a typed variable.",
		annotations(
			title = "Relate records",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn relate(
		&self,
		Parameters(p): Parameters<crud::RelateParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("relate", &ctx, async |s| crud::relate(s, p).await).await
	}

	#[tool(
		description = "Dump full schema information for a scope. Target: 'root', 'ns', 'db', or a table name. Defaults to the most specific current context. Use `list` when you only need entities of one kind.",
		annotations(
			title = "Inspect schema",
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		)
	)]
	async fn info(
		&self,
		Parameters(p): Parameters<schema::InfoParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("info", &ctx, async |s| schema::info(s, p).await).await
	}

	#[tool(
		description = "Enumerate schema entities of a single kind. `kind` is one of: namespaces, nodes, databases, tables, functions, analyzers, params, apis, buckets, models, modules, sequences, configs, users, accesses, fields, indexes, events. Set `table` for fields/indexes/events. Set `scope` (root|ns|db) for users/accesses.",
		annotations(
			title = "List schema entities",
			read_only_hint = true,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		)
	)]
	async fn list(
		&self,
		Parameters(p): Parameters<schema::ListParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("list", &ctx, async |s| schema::list(s, p).await).await
	}

	#[tool(
		name = "use",
		description = "Switch the active namespace and/or database. At least one of `namespace` or `database` must be provided; both can be set in a single call. Returns the resolved context.",
		annotations(
			title = "Switch namespace/database",
			read_only_hint = false,
			destructive_hint = false,
			idempotent_hint = true,
			open_world_hint = false
		)
	)]
	async fn use_context(
		&self,
		Parameters(p): Parameters<connection::UseParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("use", &ctx, async |s| connection::r#use(s, p).await).await
	}

	#[tool(
		description = "Invoke a SurrealQL function (e.g. `math::sum`, `string::concat`, `fn::my_function`) with typed argument bindings. Arguments are bound natively; the function name is restricted to `identifier(::identifier)*`. Permissions and capabilities are enforced by SurrealDB.",
		annotations(
			title = "Run function",
			read_only_hint = false,
			destructive_hint = true,
			idempotent_hint = false,
			open_world_hint = false
		)
	)]
	async fn run(
		&self,
		Parameters(p): Parameters<run_tool::RunParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<CallToolResult, McpError> {
		self.dispatch_tool("run", &ctx, async |s| run_tool::run(s, p).await).await
	}
}

// ---------------------------------------------------------------------------
// ServerHandler -- wires tools, resources, prompts, completions
// ---------------------------------------------------------------------------

#[tool_handler]
impl ServerHandler for McpService {
	fn get_info(&self) -> ServerInfo {
		ServerInfo::new(
			ServerCapabilities::builder()
				.enable_tools()
				.enable_resources()
				.enable_prompts()
				.enable_completions()
				.build(),
		)
		.with_server_info(Implementation::from_build_env())
		.with_instructions(resources::instructions::get_instructions().to_string())
	}

	#[tracing::instrument(skip_all, target = "surrealdb::mcp")]
	async fn initialize(
		&self,
		_request: InitializeRequestParams,
		ctx: RequestContext<RoleServer>,
	) -> Result<InitializeResult, McpError> {
		let mut session = ctx
			.extensions
			.get::<http::request::Parts>()
			.and_then(crate::auth::extract_session_from_parts)
			.unwrap_or_else(|| {
				tracing::debug!(
					target: LOG,
					"No session in request context, using configured base session"
				);
				self.base_session.clone()
			});

		if session.ns.is_none()
			&& let Some(ns) = &self.default_ns
		{
			session.ns = Some(ns.clone());
		}
		if session.db.is_none()
			&& let Some(db) = &self.default_db
		{
			session.db = Some(db.clone());
		}

		self.init_session(session)?;
		tracing::info!(target: LOG, "MCP session initialized");
		Ok(self.get_info())
	}

	async fn list_resources(
		&self,
		_: Option<PaginatedRequestParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<ListResourcesResult, McpError> {
		self.verify_request_subject(&ctx)?;
		Ok(ListResourcesResult {
			resources: resources::list_resources(),
			next_cursor: None,
			meta: None,
		})
	}

	async fn list_resource_templates(
		&self,
		_: Option<PaginatedRequestParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<ListResourceTemplatesResult, McpError> {
		self.verify_request_subject(&ctx)?;
		Ok(ListResourceTemplatesResult {
			resource_templates: resources::list_resource_templates(),
			next_cursor: None,
			meta: None,
		})
	}

	async fn read_resource(
		&self,
		request: ReadResourceRequestParams,
		ctx: RequestContext<RoleServer>,
	) -> Result<ReadResourceResult, McpError> {
		self.verify_request_subject(&ctx)?;
		resources::read_resource(self.session()?, &request.uri).await
	}

	async fn list_prompts(
		&self,
		_: Option<PaginatedRequestParams>,
		ctx: RequestContext<RoleServer>,
	) -> Result<ListPromptsResult, McpError> {
		self.verify_request_subject(&ctx)?;
		Ok(ListPromptsResult {
			prompts: prompts::list_prompts(),
			next_cursor: None,
			meta: None,
		})
	}

	async fn get_prompt(
		&self,
		request: GetPromptRequestParams,
		ctx: RequestContext<RoleServer>,
	) -> Result<GetPromptResult, McpError> {
		self.verify_request_subject(&ctx)?;
		// `request.arguments` is already a `serde_json::Map<String, Value>`,
		// so we can wrap it directly into a `Value::Object` without a
		// fallible `to_value` round-trip. When absent, downstream prompt
		// handlers treat `Value::Null` as "no arguments".
		let args = request
			.arguments
			.as_ref()
			.map(|m| serde_json::Value::Object(m.clone()))
			.unwrap_or(serde_json::Value::Null);
		prompts::get_prompt(&request.name, &args).ok_or_else(|| {
			McpError::invalid_params(format!("Unknown prompt: {}", request.name), None)
		})
	}

	async fn complete(
		&self,
		request: CompleteRequestParams,
		ctx: RequestContext<RoleServer>,
	) -> Result<CompleteResult, McpError> {
		self.verify_request_subject(&ctx)?;
		Ok(completions::handle_completion(self.session()?, &request).await)
	}
}

// ---------------------------------------------------------------------------
// Stdio transport
// ---------------------------------------------------------------------------

#[cfg(feature = "transport-io")]
pub use stdio_service::*;

#[cfg(feature = "transport-io")]
mod stdio_service {
	use super::*;

	/// Serve the MCP server over stdio (stdin/stdout).
	pub async fn serve_stdio(service: McpService) -> Result<(), anyhow::Error> {
		let stdin = tokio::io::stdin();
		let stdout = tokio::io::stdout();
		rmcp::ServiceExt::serve(service, (stdin, stdout))
			.await
			.map_err(|e| anyhow::anyhow!("MCP stdio error: {e}"))?
			.waiting()
			.await
			.map_err(|e| anyhow::anyhow!("MCP stdio error: {e}"))?;
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// HTTP service factory
// ---------------------------------------------------------------------------

#[cfg(feature = "server-http")]
pub use http_service::*;

#[cfg(feature = "server-http")]
mod http_service {
	use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
	use rmcp::transport::streamable_http_server::{
		StreamableHttpServerConfig, StreamableHttpService,
	};

	use super::*;

	/// The fully-typed MCP HTTP service.
	pub type McpHttpService = StreamableHttpService<McpService, LocalSessionManager>;

	/// Create a `StreamableHttpService` backed by the given datastore.
	///
	/// The HTTP transport always runs behind the `SurrealAuth` middleware,
	/// which attaches an authenticated `Session` to the request extensions.
	/// If that extraction fails for any reason we fall back to the anonymous
	/// `Session::default()` -- the datastore's capability rules then decide
	/// whether guest access is allowed.
	pub fn create_http_service(ds: Arc<Datastore>) -> McpHttpService {
		let mut config = StreamableHttpServerConfig::default();
		config.stateful_mode = true;
		StreamableHttpService::new(
			move || Ok(McpService::new(ds.clone(), None, None, Session::default())),
			Arc::new(LocalSessionManager::default()),
			config,
		)
	}
}
