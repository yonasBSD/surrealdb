use std::any::{Any, TypeId};
#[cfg(not(target_family = "wasm"))]
use std::collections::HashMap;
#[cfg(target_family = "wasm")]
use std::collections::HashSet;
#[cfg(not(target_family = "wasm"))]
use std::collections::hash_map::Entry;
use std::fmt::{self, Display};
#[cfg(storage)]
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Poll, ready};
use std::time::Duration;

#[allow(unused_imports)]
use anyhow::bail;
use anyhow::{Context as _, Result, ensure};
use async_channel::Sender;
use bytes::{Bytes, BytesMut};
use futures::{Future, Stream};
use rand::Rng;
use reblessive::TreeStack;
use surrealdb_types::{AuthError, Error as TypesError, SurrealValue, object};
#[cfg(not(target_family = "wasm"))]
use tokio::spawn;
use tokio::sync::Notify;
#[cfg(feature = "jwks")]
use tokio::sync::RwLock;
use tokio::time::{Instant, sleep, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use tracing::{debug, instrument, trace, warn};
use uuid::Uuid;

use super::api::Transactable;
use super::tr::Transactor;
use super::tx::Transaction;
use super::version::MajorVersion;
use super::{Key, Val, export};
use crate::api::err::ApiError;
use crate::api::invocation::process_api_request;
use crate::api::request::ApiRequest;
use crate::api::response::ApiResponse;
use crate::buc::manager::BucketsManager;
use crate::catalog::providers::{
	ApiProvider, CatalogProvider, DatabaseProvider, NamespaceProvider, NodeProvider, TableProvider,
	UserProvider,
};
use crate::catalog::{ApiDefinition, Index, NodeLiveQuery, SubscriptionDefinition};
use crate::cnf::dynamic::DynamicConfiguration;
use crate::cnf::{CommonConfig, ConfigMap};
use crate::ctx::Context;
#[cfg(feature = "jwks")]
use crate::dbs::capabilities::NetTarget;
use crate::dbs::capabilities::{
	ArbitraryQueryTarget, ExperimentalTarget, MethodTarget, RouteTarget,
};
use crate::dbs::node::{Node, Timestamp};
use crate::dbs::{Capabilities, Executor, Options, QueryResult, QueryResultBuilder, Session};
use crate::doc::AsyncEventRecord;
use crate::err::Error;
use crate::exec::function::FunctionRegistry;
use crate::expr::model::get_model_path;
use crate::expr::statements::{DefineModelStatement, DefineStatement, DefineUserStatement};
use crate::expr::{Base, Expr, FlowResultExt as _, Literal, LogicalPlan, TopLevelExpr};
#[cfg(feature = "http")]
use crate::http::HttpClient;
#[cfg(feature = "jwks")]
use crate::iam::jwks::JwksCache;
use crate::iam::{Action, Auth, Error as IamError, Resource, ResourceKind, Role};
use crate::idx::IndexKeyBase;
use crate::idx::index::IndexOperation;
use crate::idx::trees::store::IndexStores;
use crate::key::root::ic::IndexCompactionKey;
use crate::kvs::LockType::*;
use crate::kvs::TransactionType::*;
use crate::kvs::cache::ds::DatastoreCache;
use crate::kvs::clock::SystemClock;
use crate::kvs::ds::requirements::{
	TransactionBuilderFactoryRequirements, TransactionBuilderRequirements,
};
use crate::kvs::index::IndexBuilder;
use crate::kvs::sequences::Sequences;
use crate::kvs::slowlog::SlowLog;
use crate::kvs::tasklease::{LeaseHandler, TaskLeaseType};
#[cfg(test)]
use crate::kvs::testing::{RetryableConflictSite, maybe_inject_retryable_conflict};
use crate::kvs::{
	KVValue, LockType, NORMAL_BATCH_SIZE, TransactionType, is_retryable_transaction_conflict,
};
use crate::observe::{ExecutionObserver, NoopObserver};
use crate::sql::Ast;
#[cfg(feature = "surrealism")]
use crate::surrealism::cache::SurrealismCache;
use crate::syn::parser::{ParserSettings, StatementStream};
use crate::types::{PublicNotification, PublicValue, PublicVariables};
use crate::val::convert_value_to_public_value;
use crate::{CommunityComposer, syn};

mod builder;
pub use builder::Builder;

const TARGET: &str = "surrealdb::core::kvs::ds";
const NODE_DELETE_TIMEOUT: Duration = Duration::from_secs(60);

/// The role assigned to the initial user created when starting the server with
/// credentials for the first time
const INITIAL_USER_ROLE: &str = "owner";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownNodeDeleteOutcome {
	Archived,
	Failed,
	TimedOut,
}

async fn await_node_step<T, Fut>(
	deadline: Instant,
	timeout_duration: Duration,
	canceller: Option<&CancellationToken>,
	step: Fut,
) -> Result<T>
where
	Fut: Future<Output = Result<T>>,
{
	if let Some(canceller) = canceller {
		tokio::select! {
			biased;
			_ = canceller.cancelled() => bail!(Error::QueryCancelled),
			result = timeout_at(deadline, step) => match result {
				Ok(result) => result,
				Err(_) => bail!(Error::QueryTimedout(timeout_duration.into())),
			},
		}
	} else {
		match timeout_at(deadline, step).await {
			Ok(result) => result,
			Err(_) => bail!(Error::QueryTimedout(timeout_duration.into())),
		}
	}
}

async fn await_node_tx_step<T, Fut>(
	txn: &Transaction,
	deadline: Instant,
	timeout_duration: Duration,
	canceller: Option<&CancellationToken>,
	step: Fut,
) -> Result<T>
where
	Fut: Future<Output = Result<T>>,
{
	let result = if let Some(canceller) = canceller {
		tokio::select! {
			biased;
			_ = canceller.cancelled() => {
				let _ = txn.cancel().await;
				bail!(Error::QueryCancelled);
			}
			result = timeout_at(deadline, step) => result,
		}
	} else {
		timeout_at(deadline, step).await
	};

	match result {
		Ok(Ok(value)) => Ok(value),
		Ok(Err(e)) => {
			let _ = txn.cancel().await;
			Err(e)
		}
		Err(_) => {
			let _ = txn.cancel().await;
			bail!(Error::QueryTimedout(timeout_duration.into()))
		}
	}
}

fn archive_node_for_shutdown(
	timeout_duration: Duration,
	result: Result<()>,
) -> ShutdownNodeDeleteOutcome {
	match result {
		Ok(()) => ShutdownNodeDeleteOutcome::Archived,
		Err(e) => {
			if matches!(e.downcast_ref::<Error>(), Some(Error::QueryTimedout(_))) {
				warn!(
					target: TARGET,
					timeout = ?timeout_duration,
					"Timed out archiving node during shutdown; continuing shutdown"
				);
				return ShutdownNodeDeleteOutcome::TimedOut;
			}

			warn!(
				target: TARGET,
				error = %e,
				"Failed to archive node during shutdown; continuing shutdown"
			);
			ShutdownNodeDeleteOutcome::Failed
		}
	}
}

/// The underlying datastore instance which stores the dataset.
pub struct Datastore {
	transaction_factory: TransactionFactory,
	/// The unique id of this datastore, used in notifications.
	id: Uuid,
	/// Whether authentication is enabled on this datastore.
	auth_enabled: bool,
	/// The maximum duration timeout for running multiple statements in a query.
	dynamic_configuration: DynamicConfiguration,
	/// The slow log configuration determining when a query should be logged
	slow_log: Option<SlowLog>,
	/// The maximum duration timeout for running multiple statements in a
	/// transaction.
	transaction_timeout: Option<Duration>,
	/// The security and feature capabilities for this datastore.
	capabilities: Arc<Capabilities>,
	// Whether this datastore enables live query notifications to subscribers.
	notification_channel: Option<Sender<PublicNotification>>,
	// The index store cache
	index_stores: IndexStores,
	// The cross transaction cache
	cache: Arc<DatastoreCache>,
	/// Registry of built-in scalar, aggregate, projection and index
	/// functions, along with the method-dispatch table. Built once when the
	/// datastore is constructed and shared across all transactions via the
	/// `Arc`. Every `Context` clones this `Arc` rather than rebuilding the
	/// registry, which is otherwise the single biggest per-query cost.
	function_registry: Arc<FunctionRegistry>,
	// The index asynchronous builder
	index_builder: IndexBuilder,
	#[cfg(feature = "jwks")]
	// The JWKS object cache
	jwks_cache: Arc<RwLock<JwksCache>>,
	#[cfg(storage)]
	// The temporary directory
	temporary_directory: Option<Arc<PathBuf>>,
	// Map of bucket connections
	buckets: BucketsManager,
	// The sequences
	sequences: Sequences,
	// The surrealism cache
	#[cfg(feature = "surrealism")]
	surrealism_cache: Arc<SurrealismCache>,
	/// When `true`, surrealism modules are loaded lazily on first use
	/// instead of being eagerly compiled at startup.
	#[cfg(feature = "surrealism")]
	lazy_surrealism: bool,
	// Async event processing trigger
	async_event_trigger: Arc<Notify>,
	/// Config
	config: Arc<CommonConfig>,
	// Http client used to make requests.
	#[cfg(feature = "http")]
	http_client: Arc<HttpClient>,
	/// Observer invoked on significant events. Defaults to [`NoopObserver`].
	observer: Arc<dyn ExecutionObserver>,
}

/// Represents a collection of metrics for a specific datastore flavor.
///
/// This structure is used to expose datastore-specific metrics to the telemetry system.
pub struct Metrics {
	/// The name of the metrics group (e.g., "surrealdb.rocksdb").
	pub name: &'static str,
	/// A list of u64-based metrics.
	pub u64_metrics: Vec<Metric>,
}

/// Represents a single metric with a name and description.
pub struct Metric {
	/// The name of the metric.
	pub name: &'static str,
	/// A human-readable description of the metric.
	pub description: &'static str,
}

#[derive(Clone)]
pub(crate) struct TransactionFactory {
	// The inner datastore type
	builder: Arc<Box<dyn TransactionBuilder>>,
	// Async event processing trigger
	async_event_trigger: Arc<Notify>,
	/// Observer invoked on transaction lifecycle events. Defaults to
	/// [`NoopObserver`]; replaced by the datastore's observer when one is
	/// configured.
	observer: Arc<dyn ExecutionObserver>,
	config: Arc<CommonConfig>,
}

impl TransactionFactory {
	pub(super) fn new(
		async_event_trigger: Arc<Notify>,
		builder: Box<dyn TransactionBuilder>,
		config: Arc<CommonConfig>,
	) -> Self {
		Self {
			builder: Arc::new(builder),
			async_event_trigger,
			observer: Arc::new(NoopObserver),
			config,
		}
	}

	/// Replace the observer. Used by the datastore builder to propagate the
	/// chosen observer to all transactions created after the swap.
	pub(crate) fn with_observer(mut self, observer: Arc<dyn ExecutionObserver>) -> Self {
		self.observer = observer;
		self
	}

	/// Access the observer. Transaction instrumentation fires events through
	/// this handle.
	#[allow(dead_code)]
	pub(crate) fn observer(&self) -> &Arc<dyn ExecutionObserver> {
		&self.observer
	}

	#[allow(
		unreachable_code,
		unreachable_patterns,
		unused_variables,
		reason = "Some variables are unused when no backends are enabled."
	)]
	pub async fn transaction(
		&self,
		write: TransactionType,
		lock: LockType,
		sequences: Sequences,
	) -> Result<Transaction> {
		// Specify if the transaction is writeable
		let write = match write {
			Read => false,
			Write => true,
		};
		// Specify if the transaction is lockable
		let lock = match lock {
			Pessimistic => true,
			Optimistic => false,
		};
		// Create a new transaction on the datastore
		let (inner, local) = self.builder.new_transaction(write, lock).await?;
		Ok(Transaction::new(
			local,
			sequences,
			Arc::clone(&self.async_event_trigger),
			Arc::clone(&self.observer),
			Transactor {
				inner,
			},
			&self.config,
		))
	}

	/// Registers metrics for the current datastore flavor if supported.
	fn register_metrics(&self) -> Option<Metrics> {
		self.builder.register_metrics()
	}

	/// Collects a specific u64 metric by name if supported by the datastore flavor.
	fn collect_u64_metric(&self, metric: &str) -> Option<u64> {
		self.builder.collect_u64_metric(metric)
	}
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
/// Abstraction over storage backends for creating and managing transactions.
///
/// This trait allows decoupling `Datastore` from concrete KV engines (memory,
/// RocksDB, TiKV, SurrealKV, SurrealDS, etc.). Implementors translate the
/// generic transaction parameters into a backend-specific transaction and
/// report whether the transaction is considered "local" (used internally to
/// enable some optimizations).
///
/// This was introduced to make the server more composable/embeddable. External
/// crates can implement `TransactionBuilder` to plug in custom backends while
/// reusing the rest of SurrealDB.
pub trait TransactionBuilder: TransactionBuilderRequirements {
	/// Create a new backend transaction.
	///
	/// - `write`: whether the transaction is writable (Write vs Read)
	/// - `lock`: whether pessimistic locking is requested
	///
	/// Returns the backend transaction object and a flag indicating if the
	/// transaction is local to the process (true) or requires external resources
	/// (false).
	async fn new_transaction(
		&self,
		write: bool,
		lock: bool,
	) -> Result<(Box<dyn Transactable>, bool)>;

	/// Perform any backend-specific shutdown/cleanup.
	async fn shutdown(&self) -> Result<()>;

	/// Registers metrics for the current datastore flavor if supported.
	///
	/// This will return a list of available metrics and their descriptions.
	fn register_metrics(&self) -> Option<Metrics>;

	/// Collects a specific u64 metric by name if supported by the datastore flavor.
	///
	/// - `metric`: The name of the metric to collect.
	fn collect_u64_metric(&self, metric: &str) -> Option<u64>;

	/// Returns an immutable backend-specific extension handle.
	///
	/// Backends expose only stable, shareable handles through this hook. The
	/// default implementation keeps community datastores free of extension
	/// state.
	fn extension(&self, _: TypeId) -> Option<Arc<dyn Any + Send + Sync>> {
		None
	}
}

/// Transaction-builder construction result with router startup state.
///
/// The datastore consumes `builder`; server startup threads `router_state` into
/// the router factory so embedders can make immutable handles available to
/// their HTTP routes without process globals.
pub struct TransactionBuilderParts<S> {
	/// Transaction builder consumed by the datastore.
	pub builder: Box<dyn TransactionBuilder>,
	/// Immutable router startup state produced by the composer.
	pub router_state: S,
}

impl<S> TransactionBuilderParts<S> {
	/// Construct transaction-builder parts with router startup state.
	pub fn new(builder: Box<dyn TransactionBuilder>, router_state: S) -> Self {
		Self {
			builder,
			router_state,
		}
	}
}

impl TransactionBuilderParts<()> {
	/// Construct transaction-builder parts for composers without router state.
	pub fn without_router_state(builder: Box<dyn TransactionBuilder>) -> Self {
		Self::new(builder, ())
	}
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
/// Factory that parses a datastore path and returns a concrete `TransactionBuilder`.
///
/// Implementations can decide how to interpret connection strings (e.g. "memory",
/// "rocksdb:...", "tikv:...") and which clock to use. This lets the CLI and
/// server be generic over different storage backends without hard-coding them.
///
/// The `path_valid` helper is used by the CLI to validate the path early and
/// provide better error messages before starting the runtime.
pub trait TransactionBuilderFactory: TransactionBuilderFactoryRequirements {
	/// Immutable state threaded into router construction after datastore startup.
	type RouterState: Clone + Send + Sync + 'static;

	/// Create a new transaction builder for the datastore.
	///
	/// # Parameters
	/// - `path`: Database connection path string
	/// - `canceller`: Token for graceful shutdown and cancellation of long-running operations
	async fn new_transaction_builder(
		&self,
		path: &str,
		canceller: CancellationToken,
		config: ConfigMap,
	) -> Result<TransactionBuilderParts<Self::RouterState>>;

	/// Validate a datastore path string.
	fn path_valid(v: &str) -> Result<String>;
}

pub mod requirements {
	use std::fmt::Display;

	#[cfg(target_family = "wasm")]
	pub trait TransactionBuilderRequirements: Display {}

	#[cfg(not(target_family = "wasm"))]
	pub trait TransactionBuilderRequirements: Display + Send + Sync + 'static {}

	#[cfg(target_family = "wasm")]
	pub trait TransactionBuilderFactoryRequirements {}

	#[cfg(not(target_family = "wasm"))]
	pub trait TransactionBuilderFactoryRequirements: Send + Sync + 'static {}
}

pub enum DatastoreFlavor {
	#[cfg(feature = "kv-mem")]
	Mem(super::mem::Datastore),
	#[cfg(feature = "kv-rocksdb")]
	RocksDB(super::rocksdb::Datastore),
	#[cfg(feature = "kv-indxdb")]
	IndxDB(super::indxdb::Datastore),
	#[cfg(feature = "kv-tikv")]
	TiKV(super::tikv::Datastore),
	#[cfg(feature = "kv-surrealkv")]
	SurrealKV(super::surrealkv::Datastore),
}

impl TransactionBuilderFactoryRequirements for CommunityComposer {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl TransactionBuilderFactory for CommunityComposer {
	type RouterState = ();

	#[allow(unused_variables)]
	async fn new_transaction_builder(
		&self,
		path: &str,
		_canceller: CancellationToken,
		config: ConfigMap,
	) -> Result<TransactionBuilderParts<Self::RouterState>> {
		// Extract query parameters from the path before scheme extraction
		let (raw_path, config_string) = match path.split_once('?') {
			Some((p, q)) => (p, Some(q)),
			None => (path, None),
		};

		let config = if let Some(config_string) = config_string {
			config.join(
				ConfigMap::from_config_string(config_string).map_keys(|x| format!("datastore_{x}")),
			)
		} else {
			config
		};

		// Extract the scheme and path components
		let (flavour, path) = match raw_path.split_once("://").or_else(|| raw_path.split_once(':'))
		{
			None if raw_path == "memory" => ("memory", ""),
			// Treat "mem" as an alias for "memory"
			None if raw_path == "mem" => ("memory", ""),
			Some(("mem", path)) => ("memory", path),
			Some((flavour, path)) => (flavour, path),
			// Validated already in the CLI, should never happen
			_ => bail!(Error::Unreachable("Provide a valid database path parameter".to_owned())),
		};

		let path = if path.starts_with("/") {
			// if absolute, remove all slashes except one
			let normalised = format!("/{}", path.trim_start_matches("/"));
			info!(target: TARGET, "Starting kvs store at absolute path {flavour}:{normalised}");
			normalised
		} else if path.is_empty() {
			info!(target: TARGET, "Starting kvs store in memory");
			"".to_string()
		} else {
			info!(target: TARGET, "Starting kvs store at relative path {flavour}://{path}");
			path.to_string()
		};
		// Initiate the desired datastore
		match (flavour, path) {
			// Initiate an in-memory datastore
			(flavour @ "memory", path) => {
				#[cfg(feature = "kv-mem")]
				{
					// Create a new blocking threadpool
					super::threadpool::initialise();

					let config = config.with_key_value("datastore_persist", path);
					// Parse SurrealMX configuration from URL path and query parameters
					let config = config.load();
					// Initialise the storage engine
					let v = super::mem::Datastore::new(config).await.map(DatastoreFlavor::Mem)?;
					info!(target: TARGET, "Started kvs store in {flavour}");
					Ok(TransactionBuilderParts::without_router_state(Box::<DatastoreFlavor>::new(
						v,
					)))
				}
				#[cfg(not(feature = "kv-mem"))]
				bail!(Error::Kvs(crate::kvs::Error::Datastore("Cannot connect to the `memory` storage engine as it is not enabled in this build of SurrealDB".to_owned())));
			}
			// Initiate a RocksDB datastore
			(flavour @ "rocksdb", path) => {
				#[cfg(feature = "kv-rocksdb")]
				{
					// Create a new blocking threadpool
					super::threadpool::initialise();
					// Parse RocksDB-specific configuration from query parameters
					let config = config.load();
					// Initialise the storage engine
					let v = super::rocksdb::Datastore::new(&path, config)
						.await
						.map(DatastoreFlavor::RocksDB)?;
					info!(target: TARGET, "Started {flavour} kvs store");
					Ok(TransactionBuilderParts::without_router_state(Box::<DatastoreFlavor>::new(
						v,
					)))
				}
				#[cfg(not(feature = "kv-rocksdb"))]
				bail!(Error::Kvs(crate::kvs::Error::Datastore("Cannot connect to the `rocksdb` storage engine as it is not enabled in this build of SurrealDB".to_owned())));
			}
			// Initiate a SurrealKV database
			(flavour @ "surrealkv", path) => {
				#[cfg(feature = "kv-surrealkv")]
				{
					// Create a new blocking threadpool
					super::threadpool::initialise();
					// Parse SurrealKV-specific configuration from query parameters
					let config = config.load();
					// Initialise the storage engine
					let v = super::surrealkv::Datastore::new(&path, config)
						.await
						.map(DatastoreFlavor::SurrealKV)?;
					info!(target: TARGET, "Started {flavour} kvs store");
					Ok(TransactionBuilderParts::without_router_state(Box::<DatastoreFlavor>::new(
						v,
					)))
				}
				#[cfg(not(feature = "kv-surrealkv"))]
				bail!(Error::Kvs(crate::kvs::Error::Datastore("Cannot connect to the `surrealkv` storage engine as it is not enabled in this build of SurrealDB".to_owned())));
			}
			// Initiate an IndxDB database
			(flavour @ "indxdb", path) => {
				#[cfg(feature = "kv-indxdb")]
				{
					let v =
						super::indxdb::Datastore::new(&path).await.map(DatastoreFlavor::IndxDB)?;
					info!(target: TARGET, "Started {flavour} kvs store");
					Ok(TransactionBuilderParts::without_router_state(Box::<DatastoreFlavor>::new(
						v,
					)))
				}
				#[cfg(not(feature = "kv-indxdb"))]
				bail!(Error::Kvs(crate::kvs::Error::Datastore("Cannot connect to the `indxdb` storage engine as it is not enabled in this build of SurrealDB".to_owned())));
			}
			// Initiate a TiKV datastore
			(flavour @ "tikv", path) => {
				#[cfg(feature = "kv-tikv")]
				{
					let v = super::tikv::Datastore::new(&path).await.map(DatastoreFlavor::TiKV)?;
					info!(target: TARGET, "Started {flavour} kvs store");
					Ok(TransactionBuilderParts::without_router_state(Box::<DatastoreFlavor>::new(
						v,
					)))
				}
				#[cfg(not(feature = "kv-tikv"))]
				bail!(Error::Kvs(crate::kvs::Error::Datastore("Cannot connect to the `tikv` storage engine as it is not enabled in this build of SurrealDB".to_owned())));
			}
			// The datastore path is not valid
			(flavour, path) => {
				info!(target: TARGET, "Unable to load the specified datastore {flavour}{path}");
				bail!(Error::Kvs(crate::kvs::Error::Datastore(
					"Unable to load the specified datastore".into()
				)))
			}
		}
	}

	fn path_valid(v: &str) -> Result<String> {
		// Strip query parameters before validating the scheme
		let scheme_part = v.split_once('?').map(|(s, _)| s).unwrap_or(v);
		match scheme_part {
			"memory" => Ok(v.to_string()),
			"mem" => Ok(v.to_string()),
			v_s if v_s.starts_with("file:") => Ok(v.to_string()),
			v_s if v_s.starts_with("rocksdb:") => Ok(v.to_string()),
			v_s if v_s.starts_with("surrealkv:") => Ok(v.to_string()),
			v_s if v_s.starts_with("mem:") => Ok(v.to_string()),
			v_s if v_s.starts_with("tikv:") => Ok(v.to_string()),
			_ => bail!("Provide a valid database path parameter"),
		}
	}
}

impl TransactionBuilderRequirements for DatastoreFlavor {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl TransactionBuilder for DatastoreFlavor {
	#[allow(
		unreachable_code,
		unreachable_patterns,
		unused_variables,
		reason = "Some variables are unused when no backends are enabled."
	)]
	async fn new_transaction(
		&self,
		write: bool,
		lock: bool,
	) -> Result<(Box<dyn Transactable>, bool)> {
		//-> Pin<Box<dyn Future<Output = Result<(Box<dyn api::Transaction>, bool)>> + Send + 'a>> {
		//Box::pin(async move {
		Ok(match self {
			#[cfg(feature = "kv-mem")]
			Self::Mem(v) => {
				let tx = v.transaction(write, lock).await?;
				(tx, true)
			}
			#[cfg(feature = "kv-rocksdb")]
			Self::RocksDB(v) => {
				let tx = v.transaction(write, lock).await?;
				(tx, true)
			}
			#[cfg(feature = "kv-indxdb")]
			Self::IndxDB(v) => {
				let tx = v.transaction(write, lock).await?;
				(tx, true)
			}
			#[cfg(feature = "kv-tikv")]
			Self::TiKV(v) => {
				let tx = v.transaction(write, lock).await?;
				(tx, false)
			}
			#[cfg(feature = "kv-surrealkv")]
			Self::SurrealKV(v) => {
				let tx = v.transaction(write, lock).await?;
				(tx, true)
			}
			_ => unreachable!(),
		})
	}

	/// Registers metrics for the current datastore flavor if supported.
	fn register_metrics(&self) -> Option<Metrics> {
		match self {
			#[cfg(feature = "kv-rocksdb")]
			DatastoreFlavor::RocksDB(v) => Some(v.register_metrics()),
			#[allow(unreachable_patterns)]
			_ => None,
		}
	}

	/// Collects a specific u64 metric by name if supported by the datastore flavor.
	// Allow unused variable when kv-rocksdb feature is not enabled
	#[allow(unused_variables)]
	fn collect_u64_metric(&self, metric: &str) -> Option<u64> {
		match self {
			#[cfg(feature = "kv-rocksdb")]
			DatastoreFlavor::RocksDB(v) => v.collect_u64_metric(metric),
			#[allow(unreachable_patterns)]
			_ => None,
		}
	}

	async fn shutdown(&self) -> Result<()> {
		match self {
			#[cfg(feature = "kv-mem")]
			Self::Mem(v) => Ok(v.shutdown().await?),
			#[cfg(feature = "kv-rocksdb")]
			Self::RocksDB(v) => Ok(v.shutdown().await?),
			#[cfg(feature = "kv-indxdb")]
			Self::IndxDB(v) => Ok(v.shutdown().await?),
			#[cfg(feature = "kv-tikv")]
			Self::TiKV(v) => Ok(v.shutdown().await?),
			#[cfg(feature = "kv-surrealkv")]
			Self::SurrealKV(v) => Ok(v.shutdown().await?),
			#[allow(unreachable_patterns)]
			_ => unreachable!(),
		}
	}
}

impl Display for DatastoreFlavor {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		#![allow(unused_variables)]
		match self {
			#[cfg(feature = "kv-mem")]
			Self::Mem(_) => write!(f, "memory"),
			#[cfg(feature = "kv-rocksdb")]
			Self::RocksDB(_) => write!(f, "rocksdb"),
			#[cfg(feature = "kv-indxdb")]
			Self::IndxDB(_) => write!(f, "indxdb"),
			#[cfg(feature = "kv-tikv")]
			Self::TiKV(_) => write!(f, "tikv"),
			#[cfg(feature = "kv-surrealkv")]
			Self::SurrealKV(_) => write!(f, "surrealkv"),
			#[allow(unreachable_patterns)]
			_ => unreachable!(),
		}
	}
}

impl Display for Datastore {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.transaction_factory.builder.fmt(f)
	}
}

impl Datastore {
	pub fn builder() -> Builder {
		Builder::new()
	}

	async fn retry_index_operation_conflict(
		err: &anyhow::Error,
		operation: impl Into<String>,
	) -> bool {
		if is_retryable_transaction_conflict(err) {
			let operation = operation.into();
			debug!(
				target: TARGET,
				operation = %operation,
				error = %err,
				"retryable index operation conflict, retrying"
			);
			sleep(Duration::from_millis(100)).await;
			true
		} else {
			false
		}
	}

	async fn cancel_and_retry_index_operation_conflict(
		txn: &Transaction,
		err: &anyhow::Error,
		operation: impl Into<String>,
	) -> bool {
		let _ = txn.cancel().await;
		Self::retry_index_operation_conflict(err, operation).await
	}

	/// Creates a new datastore instance
	///
	/// # Examples
	///
	/// ```rust,no_run
	/// # use surrealdb_core::kvs::Datastore;
	/// # use anyhow::Error;
	/// # #[tokio::main]
	/// # async fn main() -> Result<(),Error> {
	/// let ds = Datastore::new("memory").await?;
	/// # Ok(())
	/// # }
	/// ```
	///
	/// Or to create a file-backed store:
	///
	/// ```rust,no_run
	/// # use surrealdb_core::kvs::Datastore;
	/// # use anyhow::Error;
	/// # #[tokio::main]
	/// # async fn main() -> Result<(),Error> {
	/// let ds = Datastore::new("surrealkv://temp.skv").await?;
	/// # Ok(())
	/// # }
	/// ```
	///
	/// Or to connect to a tikv-backed distributed store:
	///
	/// ```rust,no_run
	/// # use surrealdb_core::kvs::Datastore;
	/// # use anyhow::Error;
	/// # #[tokio::main]
	/// # async fn main() -> Result<(),Error> {
	/// let ds = Datastore::new("tikv://127.0.0.1:2379").await?;
	/// # Ok(())
	/// # }
	/// ```
	pub async fn new(path: &str) -> Result<Self> {
		Builder::new().build_with_path(path).await
	}

	/// Registers metrics for the current datastore flavor if supported.
	///
	/// This will return a list of available metrics and their descriptions.
	pub fn register_metrics(&self) -> Option<Metrics> {
		self.transaction_factory.register_metrics()
	}

	/// Collects a specific u64 metric by name if supported by the datastore flavor.
	///
	/// - `metric`: The name of the metric to collect.
	pub fn collect_u64_metric(&self, metric: &str) -> Option<u64> {
		self.transaction_factory.collect_u64_metric(metric)
	}

	/// The currently installed observer. Cheap to clone; internal handle is
	/// an `Arc`.
	///
	/// Exposed so higher layers (server, SDK) can emit transport-layer events
	/// such as session connect/disconnect that the core engine never sees.
	pub fn observer(&self) -> &Arc<dyn ExecutionObserver> {
		&self.observer
	}

	/// Create a new datastore with the same persistent data (inner), with
	/// flushed cache. Simulating a server restart
	pub fn restart(self) -> Self {
		self.buckets.clear();
		Self {
			id: self.id,
			auth_enabled: self.auth_enabled,
			dynamic_configuration: DynamicConfiguration::default(),
			slow_log: self.slow_log,
			transaction_timeout: self.transaction_timeout,
			capabilities: Arc::clone(&self.capabilities),
			notification_channel: self.notification_channel,
			index_stores: IndexStores::new(
				self.config.hnsw_cache_size,
				self.config.diskann_cache_size,
			),
			index_builder: IndexBuilder::new(self.transaction_factory.clone()),
			#[cfg(feature = "jwks")]
			jwks_cache: Arc::new(Default::default()),
			#[cfg(storage)]
			temporary_directory: self.temporary_directory,
			cache: Arc::new(DatastoreCache::new(self.config.datastore_cache_size)),
			function_registry: Arc::new(FunctionRegistry::with_builtins()),
			buckets: self.buckets,
			sequences: Sequences::new(self.transaction_factory.clone(), self.id),
			transaction_factory: self.transaction_factory,
			async_event_trigger: self.async_event_trigger,
			#[cfg(feature = "surrealism")]
			surrealism_cache: Arc::new(SurrealismCache::new(self.config.surrealism_cache_size)),
			#[cfg(feature = "surrealism")]
			lazy_surrealism: self.lazy_surrealism,
			#[cfg(feature = "http")]
			http_client: self.http_client,
			observer: self.observer,
			config: self.config,
		}
	}

	/// Create a test-only datastore facade that shares the same durable KV engine
	/// while resetting process-local state.
	///
	/// This lets unit tests model two SurrealDB compute nodes connected to the
	/// same storage backend without starting an external service. The cloned
	/// facade deliberately reuses the transaction factory, but gets its own node
	/// id, index builder, index stores, datastore cache, sequences, and other
	/// process-local caches. Tests that exercise cluster liveness should call
	/// [`Self::insert_node`] for both the original datastore and the fork.
	#[cfg(test)]
	pub(crate) fn fork_for_test_with_node_id(&self, id: Uuid) -> Self {
		let transaction_factory = self.transaction_factory.clone();
		Self {
			id,
			auth_enabled: self.auth_enabled,
			dynamic_configuration: self.dynamic_configuration.clone(),
			slow_log: self.slow_log.clone(),
			transaction_timeout: self.transaction_timeout,
			capabilities: Arc::clone(&self.capabilities),
			notification_channel: self.notification_channel.clone(),
			index_stores: IndexStores::new(
				self.config.hnsw_cache_size,
				self.config.diskann_cache_size,
			),
			index_builder: IndexBuilder::new(transaction_factory.clone()),
			#[cfg(feature = "jwks")]
			jwks_cache: Arc::new(RwLock::new(JwksCache::new())),
			#[cfg(storage)]
			temporary_directory: self.temporary_directory.clone(),
			cache: Arc::new(DatastoreCache::new(self.config.datastore_cache_size)),
			function_registry: Arc::new(FunctionRegistry::with_builtins()),
			buckets: self.buckets.clone(),
			sequences: Sequences::new(transaction_factory.clone(), id),
			transaction_factory,
			async_event_trigger: Arc::clone(&self.async_event_trigger),
			#[cfg(feature = "surrealism")]
			surrealism_cache: Arc::new(SurrealismCache::new(self.config.surrealism_cache_size)),
			#[cfg(feature = "surrealism")]
			lazy_surrealism: self.lazy_surrealism,
			#[cfg(feature = "http")]
			http_client: Arc::clone(&self.http_client),
			observer: Arc::clone(&self.observer),
			config: Arc::clone(&self.config),
		}
	}

	/// Set the node id for this datastore.
	pub fn with_node_id(mut self, id: Uuid) -> Self {
		self.id = id;
		self
	}

	/// Set a global transaction timeout for this Datastore
	pub fn with_transaction_timeout(mut self, duration: Option<Duration>) -> Self {
		self.transaction_timeout = duration;
		self
	}

	/// Get the configured transaction timeout, if any
	pub(crate) fn transaction_timeout(&self) -> Option<Duration> {
		self.transaction_timeout
	}

	#[cfg(storage)]
	/// Set a temporary directory for ordering of large result sets
	pub fn with_temporary_directory(mut self, path: Option<PathBuf>) -> Self {
		self.temporary_directory = path.map(Arc::new);
		self
	}

	/// Configure whether surrealism modules are loaded lazily on first use
	/// rather than eagerly at startup.
	#[cfg(feature = "surrealism")]
	pub fn with_lazy_surrealism(mut self, lazy: bool) -> Self {
		self.lazy_surrealism = lazy;
		self
	}

	/// Returns `true` if surrealism modules are loaded lazily.
	#[cfg(feature = "surrealism")]
	pub fn is_lazy_surrealism(&self) -> bool {
		self.lazy_surrealism
	}

	pub fn index_store(&self) -> &IndexStores {
		&self.index_stores
	}

	/// Is authentication enabled for this Datastore?
	pub fn is_auth_enabled(&self) -> bool {
		self.auth_enabled
	}

	pub fn id(&self) -> Uuid {
		self.id
	}

	/// Does the datastore allow excecuting an RPC method?
	pub(crate) fn allows_rpc_method(&self, method_target: &MethodTarget) -> bool {
		self.capabilities.allows_rpc_method(method_target)
	}

	/// Does the datastore allow requesting an HTTP route?
	/// This function needs to be public to allow access from the CLI crate.
	pub fn allows_http_route(&self, route_target: &RouteTarget) -> bool {
		self.capabilities.allows_http_route(route_target)
	}

	/// Is the user allowed to query?
	pub fn allows_query_by_subject(&self, subject: impl Into<ArbitraryQueryTarget>) -> bool {
		self.capabilities.allows_query(&subject.into())
	}

	/// Does the datastore allow connections to a network target?
	#[cfg(feature = "jwks")]
	pub(crate) fn allows_network_target(&self, net_target: &NetTarget) -> bool {
		self.capabilities.allows_network_target(net_target)
	}

	/// Set specific capabilities for this Datastore
	pub fn get_capabilities(&self) -> &Capabilities {
		&self.capabilities
	}

	#[cfg(feature = "jwks")]
	pub(crate) fn jwks_cache(&self) -> &Arc<RwLock<JwksCache>> {
		&self.jwks_cache
	}

	pub(super) fn clock_now(&self) -> Timestamp {
		SystemClock::new().now()
	}

	// Used for testing live queries
	#[cfg(test)]
	pub(crate) fn get_cache(&self) -> Arc<DatastoreCache> {
		Arc::clone(&self.cache)
	}

	// Initialise the cluster and run bootstrap utilities
	// Returns the current version and a flag indicating if this is a new datastore
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn check_version(&self) -> Result<(MajorVersion, bool)> {
		// Retry because concurrent instances may conflict when writing the version key
		let (version, is_new) = Self::retry("Check version", || self.get_version()).await?;
		// Check we are running the latest version
		if !version.is_latest() {
			bail!(Error::OutdatedStorageVersion {
				expected: MajorVersion::latest().into(),
				actual: version.into(),
			});
		}
		// Everything ok
		Ok((version, is_new))
	}

	// Initialise the cluster and run bootstrap utilities
	// Returns the current version and a flag indicating if this is a new datastore
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn get_version(&self) -> Result<(MajorVersion, bool)> {
		// Start a new writeable transaction
		let txn = self.transaction(Write, Optimistic).await?.enclose();
		// Create the key where the version is stored
		let key = crate::key::version::new();
		// Check if a version is already set in storage
		let val = match catch!(txn, txn.get(&key, None).await) {
			// There is a version set in the storage
			Some(val) => {
				// We didn't write anything, so just rollback
				catch!(txn, txn.cancel().await);
				// Return the current version
				(val, false)
			}
			// There is no version set in the storage
			None => {
				// Fetch any keys immediately following the version key
				let rng = crate::key::version::proceeding();
				let keys = catch!(txn, txn.keys(rng, 1, 0, None).await);
				// Check the storage if there are any other keys set
				let version = if keys.is_empty() {
					// There are no keys set in storage, so this is a new database
					MajorVersion::latest()
				} else {
					// There were keys in storage, so this is an upgrade.
					// Log the first key found for diagnostic purposes.
					warn!(
						target: TARGET,
						first_key = ?keys.first().map(|k| format!("{:?}", k)),
						"No version key found but existing data detected in storage. \
						 This storage contains data from a previous SurrealDB version. \
						 The server will not start until the data is migrated or removed."
					);
					MajorVersion::v1()
				};
				// Attempt to set the current version in storage
				catch!(txn, txn.replace(&key, &version).await);
				// We set the version, so commit the transaction
				catch!(txn, txn.commit().await);
				// Return the current version
				(version, true)
			}
		};
		// Everything ok
		Ok(val)
	}

	// --------------------------------------------------
	// Initialisation functions
	// --------------------------------------------------

	/// Setup the initial cluster access credentials
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn initialise_credentials(&self, user: &str, pass: &str) -> Result<()> {
		// Retry because concurrent instances may conflict when creating the root user
		Self::retry("Initialise credentials", || self.initialise_credentials_attempt(user, pass))
			.await
	}

	/// Single attempt to create the root user if none exists.
	/// Separated from `initialise_credentials` so it can be wrapped in the retry loop.
	async fn initialise_credentials_attempt(&self, user: &str, pass: &str) -> Result<()> {
		// Start a new writeable transaction
		let txn = self.transaction(Write, Optimistic).await?.enclose();
		// Fetch the root users from the storage
		let users = catch!(txn, txn.all_root_users(None).await);
		// Process credentials, depending on existing users
		if users.is_empty() {
			// Display information in the logs
			info!(target: TARGET, "Credentials were provided, and no root users were found. The root user '{user}' will be created");
			// Create and new root user definition
			let stm = DefineUserStatement::new_with_password(
				Base::Root,
				user.to_owned(),
				pass,
				INITIAL_USER_ROLE.to_owned(),
			);
			let opt = Options::new(&CommonConfig::default())
				.with_auth(Arc::new(Auth::for_root(Role::Owner)));
			let mut ctx = self.setup_ctx()?;
			ctx.set_transaction(Arc::clone(&txn));
			let ctx = ctx.freeze();
			let mut stack = TreeStack::new();
			let res = stack.enter(|stk| stm.compute(stk, &ctx, &opt, None)).finish().await;
			catch!(txn, res);
			// We added a user, so commit the transaction
			txn.commit().await
		} else {
			// Display information in the logs
			warn!(target: TARGET, "Credentials were provided, but existing root users were found. The root user '{user}' will not be created");
			warn!(target: TARGET, "Consider removing the --user and --pass arguments from the server start command");
			// We didn't write anything, so just rollback
			txn.cancel().await
		}
	}

	/// Setup the default namespace and database
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn initialise_defaults(&self, namespace: &str, database: &str) -> Result<()> {
		info!(target: TARGET, "This is a new SurrealDB instance. Initialising default namespace '{namespace}' and database '{database}'");
		// Create the SQL statement
		let sql = r"
			DEFINE NAMESPACE $namespace COMMENT 'Default namespace generated by SurrealDB';
			USE NS $namespace;
			DEFINE DATABASE $database COMMENT 'Default database generated by SurrealDB';
			DEFINE CONFIG DEFAULT NAMESPACE $namespace DATABASE $database;
		"
		.to_string();

		// Create the variables
		let vars = map! {
			"namespace".to_string() => namespace.to_string().into_value(),
			"database".to_string() => database.to_string().into_value(),
		};

		// Execute the SQL statement
		self.execute(
			&sql,
			&Session::owner(),
			Some(vars.into_iter().collect::<std::collections::BTreeMap<_, _>>().into()),
		)
		.await?;
		// Everything ok
		Ok(())
	}

	/// Performs a database import from SQL
	#[instrument(level = "trace", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn startup(&self, sql: &str, sess: &Session) -> Result<Vec<QueryResult>> {
		// Output function invocation details to logs
		trace!(target: TARGET, "Running datastore startup import script");
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);
		// Execute the SQL import
		self.execute(sql, sess, None).await.map_err(|e| anyhow::anyhow!(e))
	}

	/// Run the datastore shutdown tasks, performing any necessary cleanup
	#[instrument(level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn shutdown(&self) -> Result<()> {
		// Output function invocation details to logs
		trace!(target: TARGET, "Running datastore shutdown operations");
		// Archive this datastore in the cluster, but don't let a blocked
		// metadata transaction prevent storage engine shutdown.
		let _ = archive_node_for_shutdown(
			NODE_DELETE_TIMEOUT,
			self.delete_node_with_timeout(NODE_DELETE_TIMEOUT).await,
		);
		// Run any storage engine shutdown tasks
		self.transaction_factory.builder.shutdown().await
	}

	// --------------------------------------------------
	// Surrealism eager loading
	// --------------------------------------------------

	/// Pre-load all Surrealism module runtimes into the cache so that
	/// subsequent query planning can resolve function metadata (e.g. the
	/// `writeable` flag) without triggering on-demand compilation.
	///
	/// Modules are loaded in parallel using a `JoinSet`. Any individual
	/// failure is logged but does not abort the overall loading process.
	#[cfg(feature = "surrealism")]
	pub async fn eager_load_surrealism_modules(&self) {
		use crate::catalog::providers::{DatabaseProvider, NamespaceProvider};
		use crate::surrealism::cache::SurrealismCacheLookup;

		let txn = match self.transaction(Read, Optimistic).await {
			Ok(txn) => Arc::new(txn),
			Err(e) => {
				warn!(target: TARGET, error = %e, "Surrealism eager load: failed to open transaction");
				return;
			}
		};

		let mut ctx = match self.setup_ctx() {
			Ok(ctx) => ctx,
			Err(e) => {
				warn!(target: TARGET, error = %e, "Surrealism eager load: failed to set up context");
				return;
			}
		};
		ctx.set_transaction(Arc::clone(&txn));
		let ctx = ctx.freeze();

		let nss = match txn.all_ns(None).await {
			Ok(nss) => nss,
			Err(e) => {
				warn!(target: TARGET, error = %e, "Surrealism eager load: failed to list namespaces");
				return;
			}
		};

		// Collect all module lookups first, then load in parallel.
		struct ModuleLookup {
			ns_id: crate::catalog::NamespaceId,
			db_id: crate::catalog::DatabaseId,
			bucket: String,
			key: String,
			display_name: String,
		}

		let mut lookups = Vec::new();
		for ns in nss.iter() {
			let dbs = match txn.all_db(ns.namespace_id, None).await {
				Ok(dbs) => dbs,
				Err(e) => {
					warn!(
						target: TARGET,
						error = %e, ns = %ns.name,
						"Surrealism eager load: failed to list databases"
					);
					continue;
				}
			};
			for db in dbs.iter() {
				let modules = match txn.all_db_modules(ns.namespace_id, db.database_id, None).await
				{
					Ok(m) => m,
					Err(e) => {
						warn!(
							target: TARGET,
							error = %e, ns = %ns.name, db = %db.name,
							"Surrealism eager load: failed to list modules"
						);
						continue;
					}
				};
				for md in modules.iter() {
					if let crate::catalog::ModuleExecutable::Surrealism(s) = &md.executable {
						lookups.push(ModuleLookup {
							ns_id: ns.namespace_id,
							db_id: db.database_id,
							bucket: s.bucket.clone(),
							key: s.key.clone(),
							display_name: md
								.name
								.clone()
								.unwrap_or_else(|| "<unnamed>".to_string()),
						});
					}
				}
			}
		}

		if lookups.is_empty() {
			debug!(target: TARGET, "Surrealism eager load: no modules to load");
			return;
		}

		let total = lookups.len();
		debug!(target: TARGET, count = total, "Surrealism eager load: loading modules");

		let concurrency =
			std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8).clamp(2, 16);
		let load_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));

		let mut join_set = tokio::task::JoinSet::new();
		for lookup in lookups {
			let ctx = Arc::clone(&ctx);
			let load_sem = Arc::clone(&load_sem);
			join_set.spawn(async move {
				let _permit = load_sem
					.acquire_owned()
					.await
					.expect("Surrealism eager load semaphore must not be closed");
				let cache_lookup = SurrealismCacheLookup::File(
					&lookup.ns_id,
					&lookup.db_id,
					&lookup.bucket,
					&lookup.key,
				);
				match ctx.get_surrealism_runtime(cache_lookup).await {
					Ok(_) => {
						debug!(
							target: TARGET,
							module = %lookup.display_name,
							"Surrealism eager load: loaded module"
						);
						true
					}
					Err(e) => {
						warn!(
							target: TARGET,
							module = %lookup.display_name,
							error = %e,
							"Surrealism eager load: failed to load module"
						);
						false
					}
				}
			});
		}

		let mut loaded = 0usize;
		let mut failed = 0usize;
		while let Some(result) = join_set.join_next().await {
			match result {
				Ok(true) => loaded += 1,
				Ok(false) => failed += 1,
				Err(e) => {
					warn!(target: TARGET, error = %e, "Surrealism eager load: task panicked");
					failed += 1;
				}
			}
		}

		if failed > 0 {
			warn!(
				target: TARGET,
				loaded, failed, total,
				"Surrealism eager load: completed with failures"
			);
		} else {
			tracing::info!(
				target: TARGET,
				loaded, total,
				"Surrealism eager load: all modules loaded"
			);
		}
	}

	// --------------------------------------------------
	// Node functions
	// --------------------------------------------------

	/// Initialise the cluster and run bootstrap utilities
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn bootstrap(&self) -> Result<()> {
		// Each bootstrap step is retried independently, because concurrent instances
		// writing to the same cluster metadata keys may cause transaction conflicts.
		// Insert this node in the cluster
		Self::retry("Insert node", || self.insert_node()).await?;
		// Mark inactive nodes as archived
		Self::retry("Expire nodes", || self.expire_nodes()).await?;
		// Remove archived nodes
		Self::retry("Remove nodes", || self.remove_nodes()).await?;
		// Everything ok
		Ok(())
	}

	/// Retries an async operation until it succeeds or the global timeout elapses.
	///
	/// Only [`TransactionConflict`](crate::kvs::Error::TransactionConflict)
	/// errors are retried; any other error is returned immediately to the
	/// caller. On each retryable failure a randomized delay (0–10 s) is
	/// applied before the next attempt, adding jitter to reduce repeated
	/// collisions when multiple instances start concurrently against the
	/// same storage backend.
	///
	/// The global timeout is checked only after a *failed* attempt; a successful
	/// result is always returned immediately, even if the elapsed time
	/// exceeds the budget. Each attempt's timeout is the lesser of its
	/// natural timeout (10 s * attempt number) and the remaining global
	/// budget, so total wall-clock time never significantly exceeds the
	/// global timeout. If no attempt succeeds within the budget, an error
	/// is returned.
	async fn retry<F, Fut, R>(task: &str, func: F) -> Result<R>
	where
		F: Fn() -> Fut,
		Fut: Future<Output = Result<R>>,
	{
		let global_timeout = Duration::from_secs(120);
		let per_attempt_timeout = Duration::from_secs(10);
		let time = Instant::now();
		let mut last_error = None;
		let mut attempt = 1;
		loop {
			// Cap each attempt to the remaining global budget
			let remaining = global_timeout.saturating_sub(time.elapsed());
			if remaining.is_zero() {
				break;
			}
			let attempt_timeout = (per_attempt_timeout * attempt).min(remaining);
			if let Ok(result) = timeout(attempt_timeout, func()).await {
				match result {
					Ok(result) => return Ok(result),
					Err(e) => {
						// Only retry on transaction conflict errors
						if let Some(crate::kvs::Error::TransactionConflict(_)) = e.downcast_ref() {
							last_error = Some(e);
						} else {
							return Err(e);
						}
					}
				}
			}
			// Check if the global timeout has been exceeded
			if time.elapsed() >= global_timeout {
				break;
			}
			// Randomized back-off capped to the remaining budget
			let remaining = global_timeout.saturating_sub(time.elapsed());
			if remaining.is_zero() {
				break;
			}
			let tempo = Duration::from_secs(rand::rng().random_range(0..10)).min(remaining);
			sleep(tempo).await;
			attempt += 1;
		}
		if let Some(e) = last_error {
			error!(target: TARGET, "{task} - All {attempt} attempts failed. Last error: {e}");
		} else {
			error!(target: TARGET, "{task} - All {attempt} attempts failed.");
		}
		bail!(Error::Internal(format!("{task} failed after {attempt} attempts due to timeout")));
	}

	/// Inserts a node for the first time into the cluster.
	///
	/// This function should be run at server or database startup.
	///
	/// This function ensures that this node is entered into the cluster
	/// membership entries. This function must be run at server or database
	/// startup, in order to write the initial entry and timestamp to storage.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn insert_node(&self) -> Result<()> {
		// Log when this method is run
		trace!(target: TARGET, id = %self.id,"Inserting node in the cluster");
		// Refresh system usage metrics
		crate::sys::refresh().await;
		// Open transaction and set node data
		let txn = self.transaction(Write, Optimistic).await?;
		let key = crate::key::root::nd::Nd::new(self.id);
		let now = self.clock_now();
		let node = Node::new(self.id, now, false);
		let res = run!(txn, txn.put(&key, &node).await);
		match res {
			Err(e) => {
				if matches!(
					e.downcast_ref::<Error>(),
					Some(Error::Kvs(crate::kvs::Error::TransactionKeyAlreadyExists))
				) {
					Err(anyhow::Error::new(Error::ClAlreadyExists {
						id: self.id.to_string(),
					}))
				} else {
					Err(e)
				}
			}
			x => x,
		}
	}

	/// Updates an already existing node in the cluster.
	///
	/// This function should be run periodically at a regular interval.
	///
	/// This function updates the entry for this node with an up-to-date
	/// timestamp. This ensures that the node is not marked as expired by any
	/// garbage collection tasks, preventing any data cleanup for this node.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn update_node(&self) -> Result<()> {
		// Log when this method is run
		trace!(target: TARGET, id = %self.id, "Updating node in the cluster");
		// Refresh system usage metrics
		crate::sys::refresh().await;
		// Open transaction and set node data
		let txn = self.transaction(Write, Optimistic).await?;
		let key = crate::key::root::nd::new(self.id);
		let now = self.clock_now();
		let node = Node::new(self.id, now, false);
		run!(txn, txn.replace(&key, &node).await)
	}

	/// Updates this node, bounding each step and explicitly cancelling any
	/// open write transaction before returning on timeout or cancellation.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self, canceller))]
	pub async fn update_node_with_timeout(
		&self,
		timeout_duration: Duration,
		canceller: &CancellationToken,
	) -> Result<()> {
		trace!(target: TARGET, id = %self.id, timeout = ?timeout_duration, "Updating node in the cluster with timeout");

		let deadline = Instant::now() + timeout_duration;

		await_node_step(deadline, timeout_duration, Some(canceller), async {
			crate::sys::refresh().await;
			Ok(())
		})
		.await?;

		let txn = await_node_step(
			deadline,
			timeout_duration,
			Some(canceller),
			self.transaction(Write, Optimistic),
		)
		.await?;
		let key = crate::key::root::nd::new(self.id);
		let now = self.clock_now();
		let node = Node::new(self.id, now, false);

		await_node_tx_step(
			&txn,
			deadline,
			timeout_duration,
			Some(canceller),
			txn.replace(&key, &node),
		)
		.await?;
		await_node_tx_step(&txn, deadline, timeout_duration, Some(canceller), txn.commit()).await
	}

	/// Deletes a node from the cluster.
	///
	/// This function should be run when a node is shutting down.
	///
	/// This function marks the node as archived, ready for garbage collection.
	/// Later on when garbage collection is running the live queries assigned
	/// to this node will be removed, along with the node itself.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn delete_node(&self) -> Result<()> {
		// Log when this method is run
		trace!(target: TARGET, id = %self.id, "Archiving node in the cluster");
		// Open transaction and set node data
		let txn = self.transaction(Write, Optimistic).await?;
		let key = crate::key::root::nd::new(self.id);
		let val = catch!(txn, txn.get_node(self.id).await);
		let node = val.as_ref().archive();
		run!(txn, txn.replace(&key, &node).await)
	}

	/// Archives this node, bounding each step and explicitly cancelling any
	/// open write transaction before returning on timeout.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn delete_node_with_timeout(&self, timeout_duration: Duration) -> Result<()> {
		trace!(target: TARGET, id = %self.id, timeout = ?timeout_duration, "Archiving node in the cluster with timeout");

		let deadline = Instant::now() + timeout_duration;
		let txn =
			await_node_step(deadline, timeout_duration, None, self.transaction(Write, Optimistic))
				.await?;
		let key = crate::key::root::nd::new(self.id);
		let val = await_node_tx_step(&txn, deadline, timeout_duration, None, txn.get_node(self.id))
			.await?;
		let node = val.as_ref().archive();

		await_node_tx_step(&txn, deadline, timeout_duration, None, txn.replace(&key, &node))
			.await?;
		await_node_tx_step(&txn, deadline, timeout_duration, None, txn.commit()).await
	}

	/// Expires nodes which have timedout from the cluster.
	///
	/// This function should be run periodically at an interval.
	///
	/// This function marks the node as archived, ready for garbage collection.
	/// Later on when garbage collection is running the live queries assigned
	/// to this node will be removed, along with the node itself.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn expire_nodes(&self) -> Result<()> {
		// Log when this method is run
		trace!(target: TARGET, "Archiving expired nodes in the cluster");
		// Fetch all of the inactive nodes
		let inactive = {
			let txn = self.transaction(Read, Optimistic).await?;
			let nds = catch!(txn, txn.all_nodes().await);
			let now = self.clock_now();
			catch!(txn, txn.cancel().await);
			// Filter the inactive nodes
			nds.iter()
				.filter_map(|n| {
					// Check that the node is active and has expired
					match n.is_active() && n.heartbeat < now - Duration::from_secs(30) {
						true => Some(n.to_owned()),
						false => None,
					}
				})
				.collect::<Vec<_>>()
		};
		// Check if there are inactive nodes
		if !inactive.is_empty() {
			// Open a writeable transaction
			let txn = self.transaction(Write, Optimistic).await?;
			// Archive the inactive nodes
			for nd in inactive.iter() {
				// Log the live query scanning
				trace!(target: TARGET, id = %nd.id, "Archiving node in the cluster");
				// Mark the node as archived
				let node = nd.archive();
				// Get the key for the node entry
				let key = crate::key::root::nd::new(nd.id);
				// Update the node entry
				catch!(txn, txn.replace(&key, &node).await);
			}
			// Commit the changes
			catch!(txn, txn.commit().await);
		}
		// Everything was successful
		Ok(())
	}

	/// Removes and cleans up nodes which are no longer in this cluster.
	///
	/// This function should be run periodically at an interval.
	///
	/// This function clears up all nodes which have been marked as archived.
	/// When a matching node is found, all node queries, and table queries are
	/// garbage collected, before the node itself is completely deleted.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn remove_nodes(&self) -> Result<()> {
		// Log when this method is run
		trace!(target: TARGET, "Cleaning up archived nodes in the cluster");
		// Fetch all of the archived nodes
		let archived = {
			let txn = self.transaction(Read, Optimistic).await?;
			let nds = catch!(txn, txn.all_nodes().await);
			catch!(txn, txn.cancel().await);
			// Filter the archived nodes
			nds.iter().filter_map(Node::archived).collect::<Vec<_>>()
		};
		// Loop over the archived nodes
		for id in archived.iter() {
			// Open a writeable transaction
			let beg = crate::key::node::lq::prefix(*id)?;
			let end = crate::key::node::lq::suffix(*id)?;
			let mut next = Some(beg..end);
			let txn = self.transaction(Write, Optimistic).await?;
			{
				// Log the live query scanning
				trace!(target: TARGET, id = %id, "Deleting live queries for node");
				// Scan the live queries for this node
				while let Some(rng) = next {
					// Fetch the next batch of keys and values
					let res = catch!(txn, txn.batch_keys_vals(rng, NORMAL_BATCH_SIZE, None).await);
					next = res.next;
					for (k, v) in res.result.iter() {
						// Decode the data for this live query
						let val: NodeLiveQuery = KVValue::kv_decode_value(v.clone())?;
						// Get the key for this node live query
						let nlq = catch!(txn, crate::key::node::lq::Lq::decode_key(k));
						// Check that the node for this query is archived
						if archived.contains(&nlq.nd) {
							// Get the key for this table live query
							let tlq = crate::key::table::lq::new(val.ns, val.db, &val.tb, nlq.lq);
							// Delete the table live query
							catch!(txn, txn.clr(&tlq).await);
							// Delete the node live query
							catch!(txn, txn.clr(&nlq).await);
						}
					}
					// Pause and yield execution
					yield_now!();
				}
			}
			{
				// Log the node deletion
				trace!(target: TARGET, id = %id, "Deleting node from the cluster");
				// Get the key for the node entry
				let key = crate::key::root::nd::new(*id);
				// Delete the cluster node entry
				catch!(txn, txn.clr(&key).await);
			}
			// Commit the changes
			catch!(txn, txn.commit().await);
		}
		// Everything was successful
		Ok(())
	}

	/// Clean up all other miscellaneous data.
	///
	/// This function should be run periodically at an interval.
	///
	/// This function clears up all data which might have been missed from
	/// previous cleanup runs, or when previous runs failed. This function
	/// currently deletes all live queries, for nodes which no longer exist
	/// in the cluster, from all namespaces, databases, and tables. It uses
	/// a number of transactions in order to prevent failure of large or
	/// long-running transactions on distributed storage engines.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn garbage_collect(&self) -> Result<()> {
		// Log the node deletion
		trace!(target: TARGET, "Garbage collecting all miscellaneous data");
		// Fetch archived nodes
		let archived = {
			let txn = self.transaction(Read, Optimistic).await?;
			let nds = catch!(txn, txn.all_nodes().await);
			txn.cancel().await?;
			// Filter the archived nodes
			nds.iter().filter_map(Node::archived).collect::<Vec<_>>()
		};
		// Fetch all namespaces
		let nss = {
			let txn = self.transaction(Read, Optimistic).await?;
			let res = catch!(txn, txn.all_ns(None).await);
			txn.cancel().await?;
			res
		};
		// Loop over all namespaces
		for ns in nss.iter() {
			// Log the namespace
			trace!(target: TARGET, "Garbage collecting data in namespace {}", ns.name);
			// Fetch all databases
			let dbs = {
				let txn = self.transaction(Read, Optimistic).await?;
				let res = catch!(txn, txn.all_db(ns.namespace_id, None).await);
				txn.cancel().await?;
				res
			};
			// Loop over all databases
			for db in dbs.iter() {
				// Log the namespace
				trace!(target: TARGET, "Garbage collecting data in database {}/{}", ns.name, db.name);
				// Fetch all tables
				let tbs = {
					let txn = self.transaction(Read, Optimistic).await?;
					let res = catch!(txn, txn.all_tb(ns.namespace_id, db.database_id, None).await);
					txn.cancel().await?;
					res
				};
				// Loop over all tables
				for tb in tbs.iter() {
					// Log the namespace
					trace!(target: TARGET, "Garbage collecting data in table {}/{}/{}", ns.name, db.name, tb.name);
					// Iterate over the table live queries
					let beg =
						crate::key::table::lq::prefix(db.namespace_id, db.database_id, &tb.name)?;
					let end =
						crate::key::table::lq::suffix(db.namespace_id, db.database_id, &tb.name)?;
					let mut next = Some(beg..end);
					let txn = self.transaction(Write, Optimistic).await?;
					while let Some(rng) = next {
						// Fetch the next batch of keys and values
						let max = NORMAL_BATCH_SIZE;
						let res = catch!(txn, txn.batch_keys_vals(rng, max, None).await);
						next = res.next;
						for (k, v) in res.result.iter() {
							// Decode the LIVE query statement
							let stm: SubscriptionDefinition = KVValue::kv_decode_value(v.clone())?;
							// Get the node id and the live query id
							let (nid, lid) = (stm.node, stm.id);
							// Check that the node for this query is archived
							if archived.contains(&stm.node) {
								// Get the key for this node live query
								let tlq = catch!(txn, crate::key::table::lq::Lq::decode_key(k));
								// Get the key for this table live query
								let nlq = crate::key::node::lq::new(nid, lid);
								// Delete the node live query
								catch!(txn, txn.clr(&nlq).await);
								// Delete the table live query
								catch!(txn, txn.clr(&tlq).await);
							}
						}
						// Pause and yield execution
						yield_now!();
					}
					// Commit the changes
					catch!(txn, txn.commit().await);
				}
			}
		}
		// All ok
		Ok(())
	}

	// --------------------------------------------------
	// Live query functions
	// --------------------------------------------------

	/// Clean up the live queries for a disconnected connection.
	///
	/// This function should be run when a WebSocket disconnects.
	///
	/// This function clears up the live queries on the current node, which
	/// are specified by uique live query UUIDs. This is necessary when a
	/// WebSocket disconnects, and any associated live queries need to be
	/// cleaned up and removed.
	#[instrument(err, level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn delete_queries(&self, ids: Vec<uuid::Uuid>) -> Result<()> {
		// Log the node deletion
		trace!(target: TARGET, "Deleting live queries for a connection");
		// Fetch expired nodes
		let txn = self.transaction(Write, Optimistic).await?;
		// Loop over the live query unique ids
		for id in ids {
			// Get the key for this node live query
			let nlq = crate::key::node::lq::new(self.id(), id);
			// Fetch the LIVE meta data node entry
			if let Some(lq) = catch!(txn, txn.get(&nlq, None).await) {
				// Get the key for this node live query
				let nlq = crate::key::node::lq::new(self.id(), id);
				// Get the key for this table live query
				let tlq = crate::key::table::lq::new(lq.ns, lq.db, &lq.tb, id);
				// Delete the table live query
				catch!(txn, txn.clr(&tlq).await);
				// Delete the node live query
				catch!(txn, txn.clr(&nlq).await);
			}
		}
		// Commit the changes
		catch!(txn, txn.commit().await);
		// All ok
		Ok(())
	}

	// --------------------------------------------------
	// Changefeed functions
	// --------------------------------------------------

	/// Performs changefeed garbage collection as a background task.
	///
	/// This method is responsible for cleaning up old changefeed data across
	/// all databases. It uses a distributed task lease mechanism to coordinate
	/// which node performs this maintenance operation. Once a batch starts it
	/// runs to completion even if the lease expires, so brief overlap is
	/// possible.
	///
	/// The process involves:
	/// 1. Acquiring a lease for the ChangeFeedCleanup task
	/// 2. Cleaning up old changefeed data from all databases
	///
	/// # Arguments
	/// * `interval` - The interval between compaction runs, to calculate the lease duration
	#[instrument(level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn changefeed_process(&self, interval: &Duration) -> Result<()> {
		// Output function invocation details to logs
		trace!(target: TARGET, "Attempting changefeed garbage collection");
		// Create a new lease handler
		let lh = LeaseHandler::new(
			self.sequences.clone(),
			self.id,
			self.transaction_factory.clone(),
			TaskLeaseType::ChangeFeedCleanup,
			*interval * 2,
		)?;
		// If we don't get the lease, another node is handling this task
		if !lh.has_lease().await? {
			return Ok(());
		}
		// Output function invocation details to logs
		trace!(target: TARGET, "Running changefeed garbage collection");
		// Create a new transaction
		let txn = self.transaction(Write, Optimistic).await?;
		// Perform the garbage collection
		catch!(txn, crate::cf::gc_all_at(&lh, &txn).await);
		// Commit the changes
		catch!(txn, txn.commit().await);
		// Everything ok
		Ok(())
	}

	// --------------------------------------------------
	// Indexing functions
	// --------------------------------------------------

	fn ensure_not_cancelled(canceller: &CancellationToken) -> Result<()> {
		if canceller.is_cancelled() {
			bail!(Error::QueryCancelled);
		}
		Ok(())
	}

	/// Processes the index compaction queue.
	///
	/// This method is called periodically by the index compaction thread to
	/// process indexes that have been marked for compaction. It acquires a
	/// distributed lease to coordinate compaction across the cluster. Once a
	/// batch starts it runs to completion even if the lease expires, so brief
	/// overlap is possible.
	///
	/// The method scans the index compaction queue (stored as `Ic` keys) and
	/// delegates to [`Self::index_compaction_loop`], which compacts each
	/// distinct index exactly once — duplicate queue entries for the same
	/// index are skipped. On native targets compaction tasks run in parallel
	/// (one spawned task per index), while on wasm they run sequentially.
	/// Indexes that support compaction include full-text, count, and HNSW.
	///
	/// The queue is read in a short-lived read transaction so that user
	/// transactions enqueueing new compaction requests do not conflict with
	/// the compaction cycle. Each index compaction runs on its own write
	/// transaction. Once all compactions have completed, a separate write
	/// transaction removes the processed queue entries. Compaction failures
	/// are logged but do not prevent other indexes from being processed.
	///
	/// # Arguments
	/// * `dbs` - The shared datastore instance, cloned into each compaction task
	/// * `interval` - The interval between compaction runs, used to calculate the lease duration
	/// * `canceller` - Token checked before starting each lease, batch, and compaction unit
	///
	/// # Returns
	/// A tuple `(iterations, errors)` where `iterations` is the number of
	/// compaction batches processed and `errors` is the total number of
	/// individual index compaction failures across all batches.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::ds", skip(dbs, canceller))]
	pub async fn index_compaction(
		dbs: Arc<Datastore>,
		interval: Duration,
		canceller: CancellationToken,
	) -> Result<(usize, usize)> {
		// Output function invocation details to logs
		trace!(target: TARGET, "Attempting index compaction process");
		// Create a new lease handler
		let lh = LeaseHandler::new_with_canceller(
			dbs.sequences.clone(),
			dbs.id,
			dbs.transaction_factory.clone(),
			TaskLeaseType::IndexCompaction,
			interval * 2,
			canceller.clone(),
		)?;
		let mut count_iteration = 0;
		let mut count_error = 0;
		// We continue without interruptions while there are keys and the lease
		'compaction: loop {
			Self::ensure_not_cancelled(&canceller)?;
			// Attempt to acquire a lease for the IndexCompaction task
			// If we don't get the lease, another node is handling this task
			if !lh.has_lease().await? {
				return Ok((count_iteration, count_error));
			}
			Self::ensure_not_cancelled(&canceller)?;
			// Output function invocation details to logs
			trace!(target: TARGET, "Running index compaction process");
			// Read the compaction queue in a short-lived read transaction
			// to avoid holding a write lock across the entire compaction cycle
			let (beg, end) = IndexCompactionKey::range();
			let range = beg..end;
			let items = {
				let txn = dbs.transaction(Read, Optimistic).await?;
				let res = txn.getr(range, None).await;
				let _ = txn.cancel().await;
				res?
			};
			Self::ensure_not_cancelled(&canceller)?;
			if items.is_empty() {
				return Ok((count_iteration, count_error));
			}
			// Collect the keys so we can delete them after processing
			let keys: Vec<Key> = items.iter().map(|(k, _)| k.clone()).collect();
			// Process compaction for each index
			count_iteration += 1;
			count_error +=
				Self::index_compaction_loop(Arc::clone(&dbs), &lh, items, canceller.clone())
					.await?;
			// Delete the processed queue entries in a separate write
			// transaction. This avoids conflicts with concurrent user
			// transactions that may enqueue new compaction requests.
			// Failed indexes are not re-enqueued here; the next user
			// write to the affected index will naturally trigger a new
			// compaction request.
			loop {
				let txn = dbs.transaction(Write, Optimistic).await?;
				if let Err(e) = Self::ensure_not_cancelled(&canceller) {
					let _ = txn.cancel().await;
					return Err(e);
				}
				for k in &keys {
					if let Err(e) = txn.del(k).await {
						warn!(target: TARGET, "Failed to delete compaction queue entry: {e}");
					}
				}
				if let Err(e) = Self::ensure_not_cancelled(&canceller) {
					let _ = txn.cancel().await;
					return Err(e);
				}
				#[cfg(test)]
				if let Err(e) = maybe_inject_retryable_conflict(
					RetryableConflictSite::IndexCompactionQueueCleanup,
					dbs.id,
				) {
					if Self::cancel_and_retry_index_operation_conflict(
						&txn,
						&e,
						"Retryable conflict committing compaction queue cleanup, retrying",
					)
					.await
					{
						continue;
					}
					warn!(target: TARGET, "Failed to commit compaction queue cleanup: {e}");
					break 'compaction;
				}
				if let Err(e) = txn.commit().await {
					if Self::cancel_and_retry_index_operation_conflict(
						&txn,
						&e,
						"Retryable conflict committing compaction queue cleanup, retrying",
					)
					.await
					{
						continue;
					}
					warn!(target: TARGET, "Failed to commit compaction queue cleanup: {e}");
					break 'compaction;
				}
				break;
			}
		}
		Ok((count_iteration, count_error))
	}

	#[cfg(not(target_family = "wasm"))]
	async fn await_index_compaction_handle(
		ikb: &IndexKeyBase,
		handle: &mut tokio::task::JoinHandle<Result<()>>,
		canceller: &CancellationToken,
	) {
		match handle.await {
			Ok(Ok(())) => {}
			Ok(Err(e))
				if canceller.is_cancelled()
					&& matches!(e.downcast_ref::<Error>(), Some(Error::QueryCancelled)) => {}
			Ok(Err(e)) => {
				warn!("Index compaction {ikb} fails while awaiting cancellation: {e}");
			}
			Err(e) => {
				warn!("Index compaction {ikb} join fails while awaiting cancellation: {e}");
			}
		}
	}

	#[cfg(not(target_family = "wasm"))]
	async fn await_index_compaction_handles(
		handles: &mut Vec<(IndexKeyBase, tokio::task::JoinHandle<Result<()>>)>,
		canceller: &CancellationToken,
	) {
		while let Some((ikb, mut handle)) = handles.pop() {
			Self::await_index_compaction_handle(&ikb, &mut handle, canceller).await;
		}
	}

	/// Compacts each distinct index found in the queue items.
	///
	/// On native targets, compaction tasks are spawned in parallel — one per
	/// distinct index — and joined afterwards. Duplicate queue entries for
	/// the same index are deduplicated via a [`HashMap`] so only one task is
	/// spawned per index. Failures are logged but do not abort the loop.
	///
	/// Returns the number of indexes that failed to compact.
	#[cfg(not(target_family = "wasm"))]
	async fn index_compaction_loop(
		dbs: Arc<Datastore>,
		lh: &LeaseHandler,
		items: Vec<(Key, Val)>,
		canceller: CancellationToken,
	) -> Result<usize> {
		let mut compacted_indexes = HashMap::new();
		for (k, _) in items {
			Self::ensure_not_cancelled(&canceller)?;
			lh.try_maintain_lease().await?;
			let ic = IndexCompactionKey::decode_key(&k)?;
			let ikb = IndexKeyBase::new(ic.ns, ic.db, ic.tb.as_ref().clone(), ic.ix);
			if let Entry::Vacant(e) = compacted_indexes.entry(ikb) {
				e.insert(());
			}
		}
		let mut error_count = 0;
		let mut handles: Vec<(IndexKeyBase, tokio::task::JoinHandle<Result<()>>)> =
			Vec::with_capacity(compacted_indexes.len());
		for (ikb, _) in compacted_indexes {
			if let Err(e) = Self::ensure_not_cancelled(&canceller) {
				Self::await_index_compaction_handles(&mut handles, &canceller).await;
				return Err(e);
			}
			let dbs = Arc::clone(&dbs);
			let canceller = canceller.clone();
			let task_ikb = ikb.clone();
			let jh = spawn(async move { dbs.process_index_compaction(&task_ikb, canceller).await });
			handles.push((ikb, jh));
		}
		while let Some((ikb, mut jh)) = handles.pop() {
			let res = tokio::select! {
				biased;
				_ = canceller.cancelled() => {
					Self::await_index_compaction_handle(&ikb, &mut jh, &canceller).await;
					Self::await_index_compaction_handles(&mut handles, &canceller).await;
					bail!(Error::QueryCancelled);
				}
				res = &mut jh => res?,
			};
			if let Err(e) = res {
				if canceller.is_cancelled() {
					Self::await_index_compaction_handles(&mut handles, &canceller).await;
					return Err(e);
				}
				error_count += 1;
				warn!("Index compaction {ikb} fails: {e}");
			}
		}
		Ok(error_count)
	}

	/// Compacts each distinct index found in the queue items.
	///
	/// On wasm, `tokio::spawn` is unavailable so compactions run
	/// sequentially. A [`HashSet`] is used to skip duplicate queue entries
	/// for the same index. Failures are logged but do not abort the loop,
	/// matching the non-wasm behavior so that a single transient failure
	/// does not prevent other indexes from being compacted.
	///
	/// Returns the number of indexes that failed to compact.
	#[cfg(target_family = "wasm")]
	async fn index_compaction_loop(
		dbs: Arc<Datastore>,
		lh: &LeaseHandler,
		items: Vec<(Key, Val)>,
		canceller: CancellationToken,
	) -> Result<usize> {
		let mut seen = HashSet::new();
		let mut error_count = 0;
		for (k, _) in items {
			Self::ensure_not_cancelled(&canceller)?;
			lh.try_maintain_lease().await?;
			let ic = IndexCompactionKey::decode_key(&k)?;
			let ikb = IndexKeyBase::new(ic.ns, ic.db, ic.tb.as_ref().clone(), ic.ix);
			if !seen.insert(ikb.clone()) {
				continue;
			}
			let res: Result<()> =
				async { dbs.process_index_compaction(&ikb, canceller.clone()).await }.await;
			if let Err(e) = res {
				if canceller.is_cancelled() {
					return Err(e);
				}
				error_count += 1;
				warn!("Index compaction {ikb} fails: {e}");
			}
		}
		Ok(error_count)
	}

	/// Performs the actual compaction of a single index.
	///
	/// Looks up the index definition identified by `ikb` and dispatches to
	/// the appropriate compaction implementation based on the index type:
	/// full-text, count, HNSW, or DiskANN. Indexes that are being removed
	/// (`prepare_remove`), not found, or of an unsupported type are silently
	/// skipped with a trace log.
	async fn process_index_compaction(
		&self,
		ikb: &IndexKeyBase,
		canceller: CancellationToken,
	) -> Result<()> {
		Self::ensure_not_cancelled(&canceller)?;
		let ix = {
			let txn = self.transaction(Read, Optimistic).await?;
			let res =
				txn.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None).await;
			let _ = txn.cancel().await;
			res?
		};
		Self::ensure_not_cancelled(&canceller)?;
		match ix {
			Some(ix) if !ix.prepare_remove => match &ix.index {
				Index::FullText(p) => {
					self.process_fulltext_compaction(ikb, p, &canceller).await?;
				}
				Index::Count(_) => {
					self.process_count_compaction(ikb, &canceller).await?;
				}
				Index::Hnsw(_) => {
					// HNSW compaction owns its pending-key allocation and pending-range
					// drain semantics separately from full-text/count compaction.
					self.process_hnsw_compaction(ikb, &canceller).await?;
				}
				#[cfg(not(target_family = "wasm"))]
				Index::DiskAnn(_) => {
					self.process_diskann_compaction(ikb, &canceller).await?;
				}
				_ => {
					trace!(target: TARGET, "Index compaction: Index {:?} does not support compaction, skipping", ikb);
				}
			},
			_ => {
				trace!(target: TARGET, "Index compaction: Index {:?} not found, skipping", ikb);
			}
		}
		Ok(())
	}

	/// Runs HNSW compaction as bounded read-plan/write-apply batches.
	///
	/// Pending entries are captured in a read transaction and conditionally
	/// deleted in a short write transaction before graph mutation. If a write
	/// fails after local graph mutation may have started, the cached HNSW index
	/// is evicted so later use reloads persisted state.
	async fn process_hnsw_compaction(
		&self,
		ikb: &IndexKeyBase,
		canceller: &CancellationToken,
	) -> Result<()> {
		loop {
			Self::ensure_not_cancelled(canceller)?;
			let prepared = {
				let txn = Arc::new(self.transaction(Read, Optimistic).await?);
				let res: Result<
					Option<(
						crate::catalog::TableId,
						crate::idx::trees::hnsw::index::HnswCompactionPlan,
					)>,
				> = async {
					let Some(tb) = txn.get_tb(ikb.ns(), ikb.db(), ikb.table(), None).await? else {
						return Ok(None);
					};
					match txn
						.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None)
						.await?
					{
						Some(ix) if !ix.prepare_remove && matches!(&ix.index, Index::Hnsw(_)) => {
							let mut ctx = self.setup_ctx()?;
							ctx.set_transaction(Arc::clone(&txn));
							let ctx = ctx.freeze();
							let plan = IndexOperation::prepare_hnsw_compaction(&ctx, ikb).await?;
							Ok(Some((tb.table_id, plan)))
						}
						_ => Ok(None),
					}
				}
				.await;
				let _ = txn.cancel().await;
				res?
			};
			let Some((tb, plan)) = prepared else {
				return Ok(());
			};
			if !plan.has_work() {
				return Ok(());
			}
			let has_more = plan.has_more();
			Self::ensure_not_cancelled(canceller)?;

			let txn = Arc::new(self.transaction(Write, Optimistic).await?);
			let res: Result<bool> = async {
				match txn
					.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None)
					.await?
				{
					Some(ix) if !ix.prepare_remove => match &ix.index {
						Index::Hnsw(p) => {
							let mut ctx = self.setup_ctx()?;
							ctx.set_transaction(Arc::clone(&txn));
							let ctx = ctx.freeze();
							IndexOperation::apply_hnsw_compaction(
								&ctx,
								&self.index_stores,
								ikb,
								&ix,
								p,
								plan,
							)
							.await
						}
						_ => Ok(false),
					},
					_ => Ok(false),
				}
			}
			.await;
			match res {
				Ok(true) => {
					if let Err(e) = Self::ensure_not_cancelled(canceller) {
						let _ = txn.cancel().await;
						if let Err(evict) =
							self.index_stores.remove_hnsw_index(tb, ikb.clone()).await
						{
							warn!(target: TARGET, "Failed to evict HNSW index after compaction cancellation: {evict}");
						}
						return Err(e);
					}
					#[cfg(test)]
					if let Err(e) = maybe_inject_retryable_conflict(
						RetryableConflictSite::HnswCompaction,
						self.id,
					) {
						let _ = txn.cancel().await;
						if let Err(evict) =
							self.index_stores.remove_hnsw_index(tb, ikb.clone()).await
						{
							warn!(target: TARGET, "Failed to evict HNSW index after compaction commit error: {evict}");
						}
						if Self::retry_index_operation_conflict(
							&e,
							format!(
								"Retryable conflict committing HNSW compaction for {ikb}, retrying"
							),
						)
						.await
						{
							continue;
						}
						return Err(e);
					}
					if let Err(e) = txn.commit().await {
						let _ = txn.cancel().await;
						if let Err(evict) =
							self.index_stores.remove_hnsw_index(tb, ikb.clone()).await
						{
							warn!(target: TARGET, "Failed to evict HNSW index after compaction commit error: {evict}");
						}
						if Self::retry_index_operation_conflict(
							&e,
							format!(
								"Retryable conflict committing HNSW compaction for {ikb}, retrying"
							),
						)
						.await
						{
							continue;
						}
						return Err(e);
					}
				}
				Ok(false) => {
					let _ = txn.cancel().await;
					return Ok(());
				}
				Err(e) => {
					let _ = txn.cancel().await;
					if let Err(evict) = self.index_stores.remove_hnsw_index(tb, ikb.clone()).await {
						warn!(target: TARGET, "Failed to evict HNSW index after compaction error: {evict}");
					}
					if Self::retry_index_operation_conflict(
						&e,
						format!("Retryable conflict applying HNSW compaction for {ikb}, retrying"),
					)
					.await
					{
						continue;
					}
					return Err(e);
				}
			}
			Self::ensure_not_cancelled(canceller)?;
			if !has_more {
				return Ok(());
			}
		}
	}

	#[cfg(not(target_family = "wasm"))]
	/// Runs DiskANN compaction as bounded read-plan/write-apply batches.
	async fn process_diskann_compaction(
		&self,
		ikb: &IndexKeyBase,
		canceller: &CancellationToken,
	) -> Result<()> {
		loop {
			Self::ensure_not_cancelled(canceller)?;
			let prepared = {
				let txn = Arc::new(self.transaction(Read, Optimistic).await?);
				let res: Result<
					Option<(
						crate::catalog::TableId,
						crate::idx::trees::diskann::index::DiskAnnCompactionPlan,
					)>,
				> = async {
					let Some(tb) = txn.get_tb(ikb.ns(), ikb.db(), ikb.table(), None).await? else {
						return Ok(None);
					};
					match txn
						.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None)
						.await?
					{
						Some(ix)
							if !ix.prepare_remove && matches!(&ix.index, Index::DiskAnn(_)) =>
						{
							let mut ctx = self.setup_ctx()?;
							ctx.set_transaction(Arc::clone(&txn));
							let ctx = ctx.freeze();
							let plan =
								IndexOperation::prepare_diskann_compaction(&ctx, ikb).await?;
							Ok(Some((tb.table_id, plan)))
						}
						_ => Ok(None),
					}
				}
				.await;
				let _ = txn.cancel().await;
				res?
			};
			let Some((tb, plan)) = prepared else {
				return Ok(());
			};
			if !plan.requires_apply() {
				return Ok(());
			}
			let has_more = plan.has_more();
			Self::ensure_not_cancelled(canceller)?;

			let txn = Arc::new(self.transaction(Write, Optimistic).await?);
			let res: Result<bool> = async {
				match txn
					.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None)
					.await?
				{
					Some(ix) if !ix.prepare_remove => match &ix.index {
						Index::DiskAnn(p) => {
							let mut ctx = self.setup_ctx()?;
							ctx.set_transaction(Arc::clone(&txn));
							let ctx = ctx.freeze();
							IndexOperation::apply_diskann_compaction(
								&ctx,
								&self.index_stores,
								ikb,
								&ix,
								p,
								plan,
							)
							.await
						}
						_ => Ok(false),
					},
					_ => Ok(false),
				}
			}
			.await;
			match res {
				Ok(true) => {
					if let Err(e) = Self::ensure_not_cancelled(canceller) {
						let _ = txn.cancel().await;
						if let Err(evict) =
							self.index_stores.remove_diskann_index(tb, ikb.clone()).await
						{
							warn!(target: TARGET, "Failed to evict DiskANN index after compaction cancellation: {evict}");
						}
						return Err(e);
					}
					if let Err(e) = txn.commit().await {
						if let Err(evict) =
							self.index_stores.remove_diskann_index(tb, ikb.clone()).await
						{
							warn!(target: TARGET, "Failed to evict DiskANN index after compaction commit error: {evict}");
						}
						return Err(e);
					}
				}
				Ok(false) => {
					let _ = txn.cancel().await;
					return Ok(());
				}
				Err(e) => {
					let _ = txn.cancel().await;
					if let Err(evict) =
						self.index_stores.remove_diskann_index(tb, ikb.clone()).await
					{
						warn!(target: TARGET, "Failed to evict DiskANN index after compaction error: {evict}");
					}
					return Err(e);
				}
			}
			Self::ensure_not_cancelled(canceller)?;
			if !has_more {
				return Ok(());
			}
		}
	}

	/// Runs full-text compaction as a read-plan followed by a guarded write.
	///
	/// This avoids holding a mutable range scan over `!dc`/`!tt`; deltas
	/// committed after the read snapshot remain for a later compaction.
	async fn process_fulltext_compaction(
		&self,
		ikb: &IndexKeyBase,
		p: &crate::catalog::FullTextParams,
		canceller: &CancellationToken,
	) -> Result<()> {
		loop {
			Self::ensure_not_cancelled(canceller)?;
			let plan = {
				let txn = self.transaction(Read, Optimistic).await?;
				let res = IndexOperation::prepare_fulltext_compaction(
					&self.index_stores,
					ikb,
					&txn,
					p,
					&self.config.file_allowlist,
				)
				.await;
				let _ = txn.cancel().await;
				res?
			};
			if !plan.has_work() {
				return Ok(());
			}
			let has_more = plan.has_more();
			Self::ensure_not_cancelled(canceller)?;

			let txn = self.transaction(Write, Optimistic).await?;
			let res = async {
				match txn
					.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None)
					.await?
				{
					Some(ix) if !ix.prepare_remove => match &ix.index {
						Index::FullText(p) => {
							IndexOperation::apply_fulltext_compaction(
								&self.index_stores,
								ikb,
								&txn,
								p,
								&self.config.file_allowlist,
								plan,
							)
							.await
						}
						_ => Ok(false),
					},
					_ => Ok(false),
				}
			}
			.await;
			match res {
				Ok(true) => {
					if let Err(e) = Self::ensure_not_cancelled(canceller) {
						let _ = txn.cancel().await;
						return Err(e);
					}
					#[cfg(test)]
					if let Err(e) = maybe_inject_retryable_conflict(
						RetryableConflictSite::FullTextCompaction,
						self.id,
					) {
						if Self::cancel_and_retry_index_operation_conflict(
							&txn,
							&e,
							format!(
								"Retryable conflict committing full-text compaction for {ikb}, retrying"
							),
						)
						.await
						{
							continue;
						}
						return Err(e);
					}
					if let Err(e) = txn.commit().await {
						if Self::cancel_and_retry_index_operation_conflict(
							&txn,
							&e,
							format!(
								"Retryable conflict committing full-text compaction for {ikb}, retrying"
							),
						)
						.await
						{
							continue;
						}
						return Err(e);
					}
				}
				Ok(false) => {
					let _ = txn.cancel().await;
					return Ok(());
				}
				Err(e) => {
					let _ = txn.cancel().await;
					if Self::retry_index_operation_conflict(
						&e,
						format!(
							"Retryable conflict applying full-text compaction for {ikb}, retrying"
						),
					)
					.await
					{
						continue;
					}
					return Err(e);
				}
			}
			Self::ensure_not_cancelled(canceller)?;
			if !has_more {
				return Ok(());
			}
		}
	}

	/// Runs count-index compaction as a read-plan followed by a guarded write.
	///
	/// The write phase deletes only keys captured in the plan, so concurrent
	/// `!iu` deltas are preserved and included by later reads/compactions.
	async fn process_count_compaction(
		&self,
		ikb: &IndexKeyBase,
		canceller: &CancellationToken,
	) -> Result<()> {
		loop {
			Self::ensure_not_cancelled(canceller)?;
			let plan = {
				let txn = self.transaction(Read, Optimistic).await?;
				let res = IndexOperation::prepare_count_compaction(ikb, &txn).await;
				let _ = txn.cancel().await;
				res?
			};
			if !plan.has_work() {
				return Ok(());
			}
			let has_more = plan.has_more();
			Self::ensure_not_cancelled(canceller)?;

			let txn = self.transaction(Write, Optimistic).await?;
			let res = async {
				match txn
					.get_tb_index_by_id(ikb.ns(), ikb.db(), ikb.table(), ikb.index(), None)
					.await?
				{
					Some(ix) if !ix.prepare_remove && matches!(&ix.index, Index::Count(_)) => {
						IndexOperation::apply_count_compaction(ikb, &txn, plan).await
					}
					_ => Ok(false),
				}
			}
			.await;
			match res {
				Ok(true) => {
					if let Err(e) = Self::ensure_not_cancelled(canceller) {
						let _ = txn.cancel().await;
						return Err(e);
					}
					#[cfg(test)]
					if let Err(e) = maybe_inject_retryable_conflict(
						RetryableConflictSite::CountCompaction,
						self.id,
					) {
						if Self::cancel_and_retry_index_operation_conflict(
							&txn,
							&e,
							format!(
								"Retryable conflict committing count compaction for {ikb}, retrying"
							),
						)
						.await
						{
							continue;
						}
						return Err(e);
					}
					if let Err(e) = txn.commit().await {
						if Self::cancel_and_retry_index_operation_conflict(
							&txn,
							&e,
							format!(
								"Retryable conflict committing count compaction for {ikb}, retrying"
							),
						)
						.await
						{
							continue;
						}
						return Err(e);
					}
				}
				Ok(false) => {
					let _ = txn.cancel().await;
					return Ok(());
				}
				Err(e) => {
					let _ = txn.cancel().await;
					if Self::retry_index_operation_conflict(
						&e,
						format!("Retryable conflict applying count compaction for {ikb}, retrying"),
					)
					.await
					{
						continue;
					}
					return Err(e);
				}
			}
			Self::ensure_not_cancelled(canceller)?;
			if !has_more {
				return Ok(());
			}
		}
	}

	/// Process queued async events using a distributed lease to coordinate batches.
	/// Once a batch starts it runs to completion even if the lease expires, so
	/// brief overlap is possible.
	#[instrument(level = "trace", target = "surrealdb::core::kvs::ds", skip(self))]
	pub async fn event_processing(&self, interval: Duration) -> Result<()> {
		// Output function invocation details to logs
		trace!(target: TARGET, "Attempting event processing process");
		// Create a new lease handler
		let lh = LeaseHandler::new(
			self.sequences.clone(),
			self.id,
			self.transaction_factory.clone(),
			TaskLeaseType::EventProcessing,
			interval * 2,
		)?;
		// We continue without interruptions while there are keys and the lease
		loop {
			// Attempt to acquire a lease for the EventProcessing task
			// If we don't get the lease, another node is handling this task
			if !lh.has_lease().await? {
				return Ok(());
			}
			// Output function invocation details to logs
			trace!(target: TARGET, "Running event processing process");
			if AsyncEventRecord::process_next_events_batch(self, Some(&lh)).await? == 0 {
				// The last batch didn't have any events to process,
				// we can sleep until the next wake-up call
				return Ok(());
			}
		}
	}

	// --------------------------------------------------
	// Other functions
	// --------------------------------------------------

	/// Create a new transaction on this datastore
	///
	/// ```rust,no_run
	/// use surrealdb_core::kvs::{Datastore, TransactionType::*, LockType::*};
	/// use anyhow::Error;
	///
	/// #[tokio::main]
	/// async fn main() -> Result<(),Error> {
	///     let ds = Datastore::new("rocksdb://database.db").await?;
	///     let mut tx = ds.transaction(Write, Optimistic).await?;
	///     tx.cancel().await?;
	///     Ok(())
	/// }
	/// ```
	pub async fn transaction(&self, write: TransactionType, lock: LockType) -> Result<Transaction> {
		self.transaction_factory.transaction(write, lock, self.sequences.clone()).await
	}

	pub(crate) fn sequences(&self) -> &Sequences {
		&self.sequences
	}

	pub(crate) fn transaction_factory(&self) -> &TransactionFactory {
		&self.transaction_factory
	}
	pub fn async_event_trigger(&self) -> &Arc<Notify> {
		&self.async_event_trigger
	}

	pub async fn health_check(&self) -> Result<()> {
		let tx = self.transaction(Read, Optimistic).await?;

		// Cancel the transaction
		trace!("Cancelling health check transaction");
		// Attempt to fetch data
		match tx.get(&vec![0x00], None).await {
			Err(err) => {
				// Ensure the transaction is cancelled
				let _ = tx.cancel().await;
				// Return an error for this endpoint
				Err(err)
			}
			Ok(_) => {
				// Ensure the transaction is cancelled
				let _ = tx.cancel().await;
				// Return success for this endpoint
				Ok(())
			}
		}
	}

	/// Parse and execute an SQL query
	///
	/// ```rust,no_run
	/// use anyhow::Error;
	/// use surrealdb_core::kvs::Datastore;
	/// use surrealdb_core::dbs::Session;
	///
	/// #[tokio::main]
	/// async fn main() -> Result<(),Error> {
	///     let ds = Datastore::new("memory").await?;
	///     let ses = Session::owner();
	///     let ast = "USE NS test DB test; SELECT * FROM person;";
	///     let res = ds.execute(ast, &ses, None).await?;
	///     Ok(())
	/// }
	/// ```
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn execute(
		&self,
		txt: &str,
		sess: &Session,
		vars: Option<PublicVariables>,
	) -> std::result::Result<Vec<QueryResult>, TypesError> {
		// Parse the SQL query text
		let ast = syn::parse_with_capabilities(txt, &self.capabilities, &self.config)
			.map_err(|e| TypesError::validation(e.to_string(), None))?;
		// Process the AST
		self.process(ast, sess, vars).await
	}

	/// Execute a query with an existing transaction
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn execute_with_transaction(
		&self,
		txt: &str,
		sess: &Session,
		vars: Option<PublicVariables>,
		tx: Arc<Transaction>,
	) -> std::result::Result<Vec<QueryResult>, TypesError> {
		// Parse the SQL query text
		let ast = syn::parse_with_capabilities(txt, &self.capabilities, &self.config)
			.map_err(|e| TypesError::validation(e.to_string(), None))?;
		// Process the AST with the transaction
		self.process_with_transaction(ast, sess, vars, tx).await
	}

	/// Process an AST with an existing transaction
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn process_with_transaction(
		&self,
		ast: Ast,
		sess: &Session,
		vars: Option<PublicVariables>,
		tx: Arc<Transaction>,
	) -> std::result::Result<Vec<QueryResult>, TypesError> {
		// Check if the session has expired
		if sess.expired() {
			return Err(TypesError::not_allowed(
				"The session has expired".to_string(),
				AuthError::SessionExpired,
			));
		}

		// Check if anonymous actors can execute queries when auth is enabled
		if let Err(e) = self.check_anon(sess) {
			return Err(TypesError::not_allowed(
				format!("Anonymous access not allowed: {e}"),
				AuthError::NotAllowed {
					actor: "anonymous".to_owned(),
					action: "process".to_owned(),
					resource: "query".to_owned(),
				},
			));
		}

		// Create a new query options
		let opt = self.setup_options(sess);

		// Create a default context
		let mut ctx = self.setup_ctx().map_err(|e| {
			e.downcast::<Error>()
				.map(crate::err::into_types_error)
				.unwrap_or_else(|e| TypesError::internal(e.to_string()))
		})?;

		// Start an execution context
		ctx.attach_session(sess).map_err(crate::err::into_types_error)?;

		// Store the query variables
		if let Some(vars) = vars {
			ctx.attach_variables(vars.into()).map_err(crate::err::into_types_error)?;
		}

		// Propagate the resolved tenant identity onto the externally-supplied
		// transaction so the emitted [`crate::observe::TransactionEvent`]
		// carries the active session's namespace, database, user, etc.
		if let Some(identity) = ctx.tenant_identity() {
			tx.set_tenant_identity(Arc::clone(identity));
		}

		// Set the transaction in the context
		ctx.set_transaction(tx);

		// Process all statements with the transaction
		Executor::execute_plan_with_transaction(self, ctx.freeze(), opt, ast.into()).await.map_err(
			|e| {
				e.downcast::<Error>()
					.map(crate::err::into_types_error)
					.unwrap_or_else(|e| TypesError::internal(e.to_string()))
			},
		)
	}

	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn execute_import<S>(
		&self,
		sess: &Session,
		vars: Option<PublicVariables>,
		query: S,
	) -> Result<Vec<QueryResult>>
	where
		S: Stream<Item = Result<Bytes>>,
	{
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);

		// Check if anonymous actors can execute queries when auth is enabled
		// TODO(sgirones): Check this as part of the authorisation layer
		self.check_anon(sess).map_err(|_| {
			Error::from(IamError::NotAllowed {
				actor: "anonymous".to_string(),
				action: "process".to_string(),
				resource: "query".to_string(),
			})
		})?;

		// Create a new query options
		let opt = self.setup_options(sess);

		// Create a default context
		let mut ctx = self.setup_ctx()?;
		// Start an execution context
		ctx.attach_session(sess)?;
		// Store the query variables
		if let Some(vars) = vars {
			ctx.attach_variables(vars.into())?;
		}
		// Process all statements

		let parser_settings = ParserSettings {
			files_enabled: ctx.get_capabilities().allows_experimental(&ExperimentalTarget::Files),
			surrealism_enabled: ctx
				.get_capabilities()
				.allows_experimental(&ExperimentalTarget::Surrealism),
			..Default::default()
		};
		let mut statements_stream = StatementStream::new_with_settings(parser_settings);
		let mut buffer = BytesMut::new();
		let mut parse_size = 4096;
		let mut bytes_stream = pin!(query);
		let mut complete = false;
		let mut filling = true;

		let stream = futures::stream::poll_fn(move |cx| {
			loop {
				// fill the buffer to at least parse_size when filling is required.
				while filling {
					let bytes = ready!(bytes_stream.as_mut().poll_next(cx));
					let bytes = match bytes {
						Some(Err(e)) => return Poll::Ready(Some(Err(e))),
						Some(Ok(x)) => x,
						None => {
							complete = true;
							filling = false;
							break;
						}
					};

					buffer.extend_from_slice(&bytes);
					filling = buffer.len() < parse_size
				}

				// if we finished streaming we can parse with complete so that the parser can be
				// sure of it's results.
				if complete {
					return match statements_stream.parse_complete(&mut buffer) {
						Err(e) => {
							Poll::Ready(Some(Err(anyhow::Error::new(Error::InvalidQuery(e)))))
						}
						Ok(None) => Poll::Ready(None),
						Ok(Some(x)) => Poll::Ready(Some(Ok(x))),
					};
				}

				// otherwise try to parse a single statement.
				match statements_stream.parse_partial(&mut buffer) {
					Err(e) => {
						return Poll::Ready(Some(Err(anyhow::Error::new(Error::InvalidQuery(e)))));
					}
					Ok(Some(x)) => return Poll::Ready(Some(Ok(x))),
					Ok(None) => {
						// Couldn't parse a statement for sure.
						if buffer.len() >= parse_size && parse_size < u32::MAX as usize {
							// the buffer already contained more or equal to parse_size bytes
							// this means we are trying to parse a statement of more then buffer
							// size. so we need to increase the buffer size.
							parse_size = (parse_size + 1).next_power_of_two();
						}
						// start filling the buffer again.
						filling = true;
					}
				}
			}
		});

		Executor::execute_stream(self, Arc::new(ctx), opt, true, stream).await
	}

	/// Execute a pre-parsed SQL query
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn process(
		&self,
		ast: Ast,
		sess: &Session,
		vars: Option<PublicVariables>,
	) -> std::result::Result<Vec<QueryResult>, TypesError> {
		//TODO: Insert planner here.
		self.process_plan(ast.into(), sess, vars).await
	}

	pub(crate) async fn process_plan(
		&self,
		plan: LogicalPlan,
		sess: &Session,
		vars: Option<PublicVariables>,
	) -> Result<Vec<QueryResult>, TypesError> {
		// Check if the session has expired
		if sess.expired() {
			return Err(TypesError::not_allowed(
				"The session has expired".to_string(),
				AuthError::SessionExpired,
			));
		}

		// Check if anonymous actors can execute queries when auth is enabled
		// TODO(sgirones): Check this as part of the authorisation layer
		if let Err(e) = self.check_anon(sess) {
			return Err(TypesError::not_allowed(
				format!("Anonymous access not allowed: {e}"),
				AuthError::NotAllowed {
					actor: "anonymous".to_owned(),
					action: "process".to_owned(),
					resource: "query".to_owned(),
				},
			));
		}

		// Create a new query options
		let opt = self.setup_options(sess);

		// Create a default context
		let mut ctx = self.setup_ctx().map_err(|e| {
			e.downcast::<Error>()
				.map(crate::err::into_types_error)
				.unwrap_or_else(|e| TypesError::internal(e.to_string()))
		})?;

		// Start an execution context
		ctx.attach_session(sess).map_err(crate::err::into_types_error)?;

		// Store the query variables
		if let Some(vars) = vars {
			ctx.attach_variables(vars.into()).map_err(crate::err::into_types_error)?;
		}

		// Process all statements
		Executor::execute_plan(self, ctx.freeze(), opt, plan).await.map_err(|e| {
			e.downcast::<Error>()
				.map(crate::err::into_types_error)
				.unwrap_or_else(|e| TypesError::internal(e.to_string()))
		})
	}

	/// Evaluates a SQL [`Value`] without checking authenticating config
	/// This is used in very specific cases, where we do not need to check
	/// whether authentication is enabled, or guest access is disabled.
	/// For example, this is used when processing a record access SIGNUP or
	/// SIGNIN clause, which still needs to work without guest access.
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub(crate) async fn evaluate(
		&self,
		val: &Expr,
		sess: &Session,
		vars: Option<PublicVariables>,
	) -> Result<PublicValue> {
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);
		// Create a new memory stack
		let mut stack = TreeStack::new();
		// Create a new query options
		let opt = self.setup_options(sess);
		// Create a default context
		let mut ctx = self.setup_ctx()?;
		// Set the global query timeout
		if let Some(timeout) = self.dynamic_configuration.get_query_timeout() {
			ctx.add_timeout(timeout)?;
		}
		// Setup the notification channel
		ctx.add_notifications(self.notification_channel.as_ref());

		let txn_type = if val.read_only() {
			TransactionType::Read
		} else {
			TransactionType::Write
		};
		// Start a new transaction. Tenant identity is attached up-front so the
		// emitted [`crate::observe::TransactionEvent`] carries the session's
		// namespace, database, user, etc.
		let txn = self
			.transaction(txn_type, Optimistic)
			.await?
			.with_tenant_identity(Some(Arc::new(crate::observe::TenantIdentity::from_session(
				sess,
			))))
			.enclose();
		// Store the transaction
		ctx.set_transaction(Arc::clone(&txn));

		// Start an execution context
		ctx.attach_session(sess)?;
		// Store the query variables
		if let Some(vars) = vars {
			ctx.attach_public_variables(vars)?;
		}

		// Freeze the context
		let ctx = ctx.freeze();
		// Compute the value
		let res =
			stack.enter(|stk| val.compute(stk, &ctx, &opt, None)).finish().await.catch_return();
		// Store any data
		if res.is_ok() && txn_type == TransactionType::Write {
			// If the compute was successful, then commit if writeable
			txn.commit().await?;
		} else {
			// Cancel if the compute was an error, or if readonly
			txn.cancel().await?;
		};
		// Return result
		convert_value_to_public_value(res?)
	}

	/// Performs a database import from SQL
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn import(&self, sql: &str, sess: &Session) -> Result<Vec<QueryResult>> {
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);
		// Execute the SQL import
		self.execute(sql, sess, None).await.map_err(|e| anyhow::anyhow!(e))
	}

	/// Performs a database import from SQL
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn import_stream<S>(&self, sess: &Session, stream: S) -> Result<Vec<QueryResult>>
	where
		S: Stream<Item = Result<Bytes>>,
	{
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);
		// Execute the SQL import
		self.execute_import(sess, None, stream).await
	}

	/// Performs a full database export as SQL
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn export(
		&self,
		sess: &Session,
		chn: Sender<Vec<u8>>,
	) -> Result<impl Future<Output = Result<()>>> {
		// Create a default export config
		let cfg = super::export::Config::default();
		self.export_with_config(sess, chn, cfg).await
	}

	/// Performs a full database export as SQL
	#[instrument(level = "debug", target = "surrealdb::core::kvs::ds", skip_all)]
	pub async fn export_with_config(
		&self,
		sess: &Session,
		chn: Sender<Vec<u8>>,
		cfg: export::Config,
	) -> Result<impl Future<Output = Result<()>> + 'static> {
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);
		// Retrieve the provided NS and DB
		let (ns, db) = crate::iam::check::check_ns_db(sess)?;
		// Create a new readonly transaction
		let txn = self.transaction(Read, Optimistic).await?;
		let batch_size = self.config.export_batch_size;
		// Return an async export job
		Ok(async move {
			// Process the export
			let res = txn.export(&ns, &db, cfg, batch_size, chn).await;
			txn.cancel().await?;
			res
		})
	}

	/// Checks the required permissions level for this session
	#[instrument(level = "trace", target = "surrealdb::core::kvs::ds", skip(self, sess))]
	#[allow(clippy::needless_pass_by_value)] // Public API: ergonomic for callers passing `ResourceKind::X.on_db(ns, db)` inline.
	pub fn check(&self, sess: &Session, action: Action, resource: Resource) -> Result<()> {
		// Check if the session has expired
		ensure!(!sess.expired(), Error::ExpiredSession);
		// Skip auth for Anonymous users if auth is disabled
		let skip_auth = !self.is_auth_enabled() && sess.au.is_anon();
		if !skip_auth {
			sess.au.is_allowed(action, &resource)?;
		}
		// All ok
		Ok(())
	}

	pub fn setup_options(&self, sess: &Session) -> Options {
		Options::new(&self.config)
			.with_ns(sess.ns())
			.with_db(sess.db())
			.with_auth(Arc::clone(&sess.au))
	}

	pub fn setup_ctx(&self) -> Result<Context> {
		let mut ctx = Context::from_ds(
			self.id,
			self.auth_enabled,
			self.dynamic_configuration.clone(),
			self.dynamic_configuration.get_query_timeout(),
			self.slow_log.clone(),
			Arc::clone(&self.capabilities),
			self.index_stores.clone(),
			self.index_builder.clone(),
			self.sequences.clone(),
			Arc::clone(&self.cache),
			Arc::clone(&self.function_registry),
			#[cfg(feature = "http")]
			Arc::clone(&self.http_client),
			#[cfg(storage)]
			self.temporary_directory.clone(),
			self.buckets.clone(),
			Arc::clone(&self.config),
			#[cfg(feature = "surrealism")]
			Arc::clone(&self.surrealism_cache),
		)?;
		// Setup the notification channel
		ctx.add_notifications(self.notification_channel.as_ref());
		Ok(ctx)
	}

	/// check for disallowed anonymous users
	pub fn check_anon(&self, sess: &Session) -> Result<(), IamError> {
		if self.auth_enabled && sess.au.is_anon() && !self.capabilities.allows_guest_access() {
			Err(IamError::NotAllowed {
				actor: "anonymous".to_string(),
				action: String::new(),
				resource: String::new(),
			})
		} else {
			Ok(())
		}
	}

	pub async fn process_use(
		&self,
		ctx: Option<&Context>,
		session: &mut Session,
		namespace: Option<String>,
		database: Option<String>,
	) -> std::result::Result<QueryResult, TypesError> {
		let new_tx = || async {
			self.transaction(Write, Optimistic)
				.await
				.map_err(|err| TypesError::internal(err.to_string()))
		};
		let commit_tx = |txn: Transaction| async move {
			txn.commit().await.map_err(|err| TypesError::internal(err.to_string()))
		};

		let query_result = QueryResultBuilder::started_now();
		match (namespace, database) {
			(Some(ns), Some(db)) => {
				let tx = new_tx().await?;
				tx.ensure_ns_db(ctx, &ns, &db)
					.await
					.map_err(|err| TypesError::internal(err.to_string()))?;
				commit_tx(tx).await?;
				session.ns = Some(ns);
				session.db = Some(db);
			}
			(Some(ns), None) => {
				let tx = new_tx().await?;
				tx.get_or_add_ns(ctx, &ns)
					.await
					.map_err(|err| TypesError::internal(err.to_string()))?;
				commit_tx(tx).await?;
				session.ns = Some(ns);
			}
			(None, Some(db)) => {
				let Some(ns) = session.ns.clone() else {
					return Err(TypesError::validation(
						"Cannot use database without namespace".to_string(),
						None,
					));
				};
				let tx = new_tx().await?;
				tx.ensure_ns_db(ctx, &ns, &db)
					.await
					.map_err(|err| TypesError::internal(err.to_string()))?;
				commit_tx(tx).await?;
				session.db = Some(db);
			}
			(None, None) => {
				session.ns = None;
				session.db = None;
			}
		}

		let value = PublicValue::from_t(object! {
			namespace: session.ns.clone(),
			database: session.db.clone(),
		});

		Ok(query_result.finish_with_result(Ok(value)))
	}

	/// Get a db model by name.
	///
	/// TODO: This should not be public, but it is used in `surrealdb/src/api/engine/local/mod.rs`.
	pub async fn get_db_model(
		&self,
		ns: &str,
		db: &str,
		model_name: &str,
		model_version: &str,
	) -> Result<Option<Arc<crate::catalog::MlModelDefinition>>> {
		let tx = self.transaction(Read, Optimistic).await?;
		let db = tx.expect_db_by_name(ns, db).await?;
		let model = tx
			.get_db_model(db.namespace_id, db.database_id, model_name, model_version, None)
			.await?;
		tx.cancel().await?;
		Ok(model)
	}

	/// Invoke an API handler.
	///
	/// TODO: This should not need to be public, but it is used in `src/net/api.rs`.
	pub async fn invoke_api_handler(
		&self,
		ns: &str,
		db: &str,
		path: &str,
		session: &Session,
		mut req: ApiRequest,
	) -> Result<ApiResponse> {
		let tx = Arc::new(self.transaction(TransactionType::Write, LockType::Optimistic).await?);

		let db = tx.ensure_ns_db(None, ns, db).await?;

		let apis = tx.all_db_apis(db.namespace_id, db.database_id, None).await?;
		let segments: Vec<&str> = path.split('/').filter(|x| !x.is_empty()).collect();

		let res = match ApiDefinition::find_definition(apis.as_ref(), &segments, req.method) {
			Some((api, params)) => {
				debug!(
					request_id = %req.request_id,
					path = %path,
					"API definition found, dispatching to process_api_request"
				);
				req.params = params.try_into()?;

				let opt = self.setup_options(session);

				let mut ctx = self.setup_ctx()?;
				ctx.set_transaction(Arc::clone(&tx));
				ctx.attach_session(session)?;
				let ctx = &ctx.freeze();

				process_api_request(ctx, &opt, api, req).await
			}
			None => {
				trace!(
					request_id = %req.request_id,
					path = %path,
					"No API definition found for path"
				);
				tx.cancel().await?;
				return Ok(ApiResponse::from_error(ApiError::NotFound, req.request_id.clone()));
			}
		};

		// Handle committing or cancelling the transaction
		if res.is_ok() {
			tx.commit().await?;
		} else {
			tx.cancel().await?;
		}

		res
	}

	pub async fn put_ml_model(
		&self,
		session: &Session,
		name: &str,
		version: &str,
		description: &str,
		data: Vec<u8>,
	) -> Result<()> {
		let ns = session.ns.as_ref().context("Namespace is required")?;
		let db = session.db.as_ref().context("Database is required")?;

		self.check(session, Action::Edit, ResourceKind::Model.on_db(ns, db))?;

		// Calculate the hash of the model file
		let hash = crate::obs::hash(&data);
		// Calculate the path of the model file
		let path = get_model_path(ns, db, name, version, &hash);
		// Insert the file data in to the store
		crate::obs::put(&path, data).await?;
		// Insert the model in to the database
		let model = DefineModelStatement {
			name: name.to_string().into(),
			version: version.to_string().into(),
			comment: Expr::Literal(Literal::String(description.into())),
			hash: hash.into(),
			kind: Default::default(),
			permissions: Default::default(),
		};

		let q = LogicalPlan {
			expressions: vec![TopLevelExpr::Expr(Expr::Define(Box::new(DefineStatement::Model(
				model,
			))))],
		};

		self.process_plan(q, session, None).await.map_err(|e| anyhow::anyhow!(e))?;

		Ok(())
	}

	pub fn config(&self) -> Arc<CommonConfig> {
		Arc::clone(&self.config)
	}

	#[cfg(feature = "http")]
	pub fn http_client(&self) -> Arc<HttpClient> {
		Arc::clone(&self.http_client)
	}
}

#[cfg(test)]
mod test {
	use std::collections::BTreeMap;
	use std::future::pending;

	use super::*;
	use crate::catalog::providers::{
		CatalogProvider, DatabaseProvider, NamespaceProvider, TableProvider,
	};
	use crate::iam::verify::verify_root_creds;
	use crate::kvs::testing::{
		RetryableConflictSite, inject_retryable_conflict, retryable_conflict_count,
	};
	use crate::types::{PublicValue, PublicVariables};
	use crate::val::TableName;

	async fn new_index_compaction_test_ds() -> Result<(Datastore, Session)> {
		let ds = Datastore::new("memory").await?;
		let session = Session::owner().with_ns("test").with_db("test");
		let txn = ds.transaction(Write, Pessimistic).await?;
		txn.ensure_ns_db(None, "test", "test").await?;
		txn.commit().await?;
		Ok((ds, session))
	}

	async fn execute_all(ds: &Datastore, session: &Session, sql: &str) -> Result<()> {
		for result in ds.execute(sql, session, None).await? {
			result.result?;
		}
		Ok(())
	}

	async fn index_key_base(ds: &Datastore, table: &str, index: &str) -> Result<IndexKeyBase> {
		let txn = ds.transaction(Read, Optimistic).await?;
		let ns = txn.get_ns_by_name("test", None).await?.unwrap();
		let db = txn.get_db_by_name("test", "test", None).await?.unwrap();
		let table = TableName::from(table);
		let ix =
			txn.get_tb_index(ns.namespace_id, db.database_id, &table, index, None).await?.unwrap();
		txn.cancel().await?;
		Ok(IndexKeyBase::new(ns.namespace_id, db.database_id, table, ix.index_id))
	}

	async fn assert_index_compaction_commit_retry(
		site: RetryableConflictSite,
		table: &str,
		index: &str,
		sql: &str,
	) -> Result<()> {
		let (ds, session) = new_index_compaction_test_ds().await?;
		execute_all(&ds, &session, sql).await?;
		let ikb = index_key_base(&ds, table, index).await?;
		let node_id = ds.id();
		let _guard = inject_retryable_conflict(site, node_id);

		ds.process_index_compaction(&ikb, CancellationToken::new()).await?;

		assert_eq!(retryable_conflict_count(site, node_id), 0);
		Ok(())
	}

	const COUNT_COMPACTION_SQL: &str = "
		DEFINE TABLE user SCHEMALESS;
		DEFINE INDEX count_idx ON user COUNT;
		CREATE user:1 SET name = 'one' RETURN NONE;
		CREATE user:2 SET name = 'two' RETURN NONE;
	";

	const FULLTEXT_COMPACTION_SQL: &str = "
		DEFINE ANALYZER simple TOKENIZERS blank FILTERS lowercase;
		DEFINE TABLE doc SCHEMALESS;
		DEFINE INDEX ft_idx ON doc FIELDS text FULLTEXT ANALYZER simple BM25 HIGHLIGHTS;
		CREATE doc:1 SET text = 'alpha beta' RETURN NONE;
		CREATE doc:2 SET text = 'beta gamma' RETURN NONE;
	";

	const HNSW_COMPACTION_SQL: &str = "
		DEFINE TABLE vec SCHEMALESS;
		DEFINE INDEX hnsw_idx ON vec FIELDS vector HNSW DIMENSION 2 DIST EUCLIDEAN TYPE F32 EFC 16 M 4;
		CREATE vec:1 SET vector = [1, 2] RETURN NONE;
		CREATE vec:2 SET vector = [2, 3] RETURN NONE;
	";

	#[tokio::test]
	async fn count_index_compaction_retries_commit_conflict() -> Result<()> {
		assert_index_compaction_commit_retry(
			RetryableConflictSite::CountCompaction,
			"user",
			"count_idx",
			COUNT_COMPACTION_SQL,
		)
		.await
	}

	#[tokio::test]
	async fn fulltext_index_compaction_retries_commit_conflict() -> Result<()> {
		assert_index_compaction_commit_retry(
			RetryableConflictSite::FullTextCompaction,
			"doc",
			"ft_idx",
			FULLTEXT_COMPACTION_SQL,
		)
		.await
	}

	#[tokio::test]
	async fn hnsw_index_compaction_retries_commit_conflict() -> Result<()> {
		assert_index_compaction_commit_retry(
			RetryableConflictSite::HnswCompaction,
			"vec",
			"hnsw_idx",
			HNSW_COMPACTION_SQL,
		)
		.await
	}

	#[tokio::test]
	async fn index_compaction_retries_queue_cleanup_commit_conflict() -> Result<()> {
		let (ds, session) = new_index_compaction_test_ds().await?;
		execute_all(&ds, &session, COUNT_COMPACTION_SQL).await?;
		let site = RetryableConflictSite::IndexCompactionQueueCleanup;
		let node_id = ds.id();
		let _guard = inject_retryable_conflict(site, node_id);

		let (_, errors) = Datastore::index_compaction(
			Arc::new(ds),
			Duration::from_secs(1),
			CancellationToken::new(),
		)
		.await?;

		assert_eq!(errors, 0);
		assert_eq!(retryable_conflict_count(site, node_id), 0);
		Ok(())
	}

	#[tokio::test]
	async fn archive_node_for_shutdown_reports_success() {
		let outcome = archive_node_for_shutdown(Duration::from_secs(60), Ok(()));

		assert_eq!(outcome, ShutdownNodeDeleteOutcome::Archived);
	}

	#[tokio::test]
	async fn archive_node_for_shutdown_reports_failure() {
		let outcome = archive_node_for_shutdown(
			Duration::from_secs(60),
			Err(anyhow::anyhow!("delete failed")),
		);

		assert_eq!(outcome, ShutdownNodeDeleteOutcome::Failed);
	}

	#[tokio::test]
	async fn archive_node_for_shutdown_reports_timeout() {
		let outcome = archive_node_for_shutdown(
			Duration::from_millis(1),
			Err(anyhow::Error::new(Error::QueryTimedout(Duration::from_millis(1).into()))),
		);

		assert_eq!(outcome, ShutdownNodeDeleteOutcome::TimedOut);
	}

	#[tokio::test]
	async fn node_tx_step_cancels_after_timeout() {
		let ds = Datastore::new("memory").await.unwrap();
		let txn = ds.transaction(Write, Optimistic).await.unwrap();
		let timeout_duration = Duration::from_millis(10);

		let err = await_node_tx_step(
			&txn,
			Instant::now() + timeout_duration,
			timeout_duration,
			None,
			pending::<Result<()>>(),
		)
		.await
		.unwrap_err();

		assert!(matches!(err.downcast_ref::<Error>(), Some(Error::QueryTimedout(_))));
		assert!(txn.closed());
	}

	#[tokio::test]
	async fn node_tx_step_cancels_after_cancellation() {
		let ds = Datastore::new("memory").await.unwrap();
		let txn = ds.transaction(Write, Optimistic).await.unwrap();
		let canceller = CancellationToken::new();
		canceller.cancel();

		let err = await_node_tx_step(
			&txn,
			Instant::now() + Duration::from_secs(60),
			Duration::from_secs(60),
			Some(&canceller),
			pending::<Result<()>>(),
		)
		.await
		.unwrap_err();

		assert!(matches!(err.downcast_ref::<Error>(), Some(Error::QueryCancelled)));
		assert!(txn.closed());
	}

	#[tokio::test]
	async fn node_tx_step_cancels_after_error() {
		let ds = Datastore::new("memory").await.unwrap();
		let txn = ds.transaction(Write, Optimistic).await.unwrap();

		let err = await_node_tx_step(
			&txn,
			Instant::now() + Duration::from_secs(60),
			Duration::from_secs(60),
			None,
			async { Err::<(), _>(anyhow::anyhow!("step failed")) },
		)
		.await
		.unwrap_err();

		assert_eq!(err.to_string(), "step failed");
		assert!(txn.closed());
	}

	#[tokio::test]
	async fn node_tx_step_success_leaves_transaction_open() {
		let ds = Datastore::new("memory").await.unwrap();
		let txn = ds.transaction(Write, Optimistic).await.unwrap();

		await_node_tx_step(
			&txn,
			Instant::now() + Duration::from_secs(60),
			Duration::from_secs(60),
			None,
			async { Ok::<_, anyhow::Error>(()) },
		)
		.await
		.unwrap();

		assert!(!txn.closed());
		txn.commit().await.unwrap();
		assert!(txn.closed());
	}

	#[tokio::test]
	async fn test_setup_superuser() {
		let ds = Datastore::new("memory").await.unwrap();
		let username = "root";
		let password = "root";

		// Setup the initial user if there are no root users
		{
			let txn = ds.transaction(Read, Optimistic).await.unwrap();
			assert_eq!(txn.all_root_users(None).await.unwrap().len(), 0);
			txn.cancel().await.unwrap();
		}
		ds.initialise_credentials(username, password).await.unwrap();
		{
			let txn = ds.transaction(Read, Optimistic).await.unwrap();
			assert_eq!(txn.all_root_users(None).await.unwrap().len(), 1);
			txn.cancel().await.unwrap();
		}
		verify_root_creds(&ds, username, password).await.unwrap();

		// Do not setup the initial root user if there are root users:
		// Test the scenario by making sure the custom password doesn't change.
		let sql = "DEFINE USER root ON ROOT PASSWORD 'test' ROLES OWNER";
		let sess = Session::owner();
		ds.execute(sql, &sess, None).await.unwrap();
		let pass_hash = {
			let txn = ds.transaction(Read, Optimistic).await.unwrap();
			let res = txn.expect_root_user(username).await.unwrap().hash.clone();
			txn.cancel().await.unwrap();
			res
		};

		ds.initialise_credentials(username, password).await.unwrap();
		{
			let txn = ds.transaction(Read, Optimistic).await.unwrap();
			assert_eq!(pass_hash, txn.expect_root_user(username).await.unwrap().hash.clone());
			txn.cancel().await.unwrap();
		}
	}

	#[tokio::test]
	pub async fn very_deep_query() -> Result<()> {
		use reblessive::{Stack, Stk};

		use crate::expr::{BinaryOperator, Expr, Literal};
		use crate::kvs::Datastore;
		use crate::val::{Number, Value};

		// build query manually to bypass query limits.
		let mut stack = Stack::new();
		async fn build_query(stk: &mut Stk, depth: usize) -> Expr {
			if depth == 0 {
				Expr::Binary {
					left: Box::new(Expr::Literal(Literal::Integer(1))),
					op: BinaryOperator::Add,
					right: Box::new(Expr::Literal(Literal::Integer(1))),
				}
			} else {
				let q = stk.run(|stk| build_query(stk, depth - 1)).await;
				Expr::Binary {
					left: Box::new(q),
					op: BinaryOperator::Add,
					right: Box::new(Expr::Literal(Literal::Integer(1))),
				}
			}
		}
		let val = stack.enter(|stk| build_query(stk, 1000)).finish();

		let dbs = Datastore::builder()
			.with_capabilities(Capabilities::all())
			.build_with_path("memory")
			.await
			.unwrap();

		let opt = Options::new(&dbs.config())
			.with_ns(Some("test".into()))
			.with_db(Some("test".into()))
			.with_max_computation_depth(u32::MAX);

		// Create a default context
		let mut ctx = dbs.setup_ctx()?;
		// Start a new transaction
		let txn = dbs.transaction(TransactionType::Read, Optimistic).await?.enclose();
		// Store the transaction
		ctx.set_transaction(Arc::clone(&txn));
		// Freeze the context
		let ctx = ctx.freeze();
		// Compute the value
		let mut stack = reblessive::tree::TreeStack::new();
		let res = stack
			.enter(|stk| val.compute(stk, &ctx, &opt, None))
			.finish()
			.await
			.catch_return()
			.unwrap();
		assert_eq!(res, Value::Number(Number::Int(1002)));
		txn.cancel().await?;
		Ok(())
	}

	#[tokio::test]
	async fn cross_transaction_caching_uuids_updated() -> Result<()> {
		let (send, _recv) = crate::channel::bounded(crate::cnf::NOTIFICATIONS_CHANNEL_SIZE);
		let ds = Datastore::builder()
			.with_capabilities(Capabilities::all())
			.with_notify(send)
			.build_with_path("memory")
			.await?;
		let cache = ds.get_cache();
		let ses = Session::owner().with_ns("test").with_db("test").with_rt(true);

		let db = {
			let txn = ds.transaction(TransactionType::Write, LockType::Pessimistic).await?;
			let db = txn.ensure_ns_db(None, "test", "test").await?;
			txn.commit().await?;
			db
		};

		// Define the table, set the initial uuids
		let (initial, initial_live_query_version) = {
			let sql = r"DEFINE TABLE test;".to_owned();
			let res = &mut ds.execute(&sql, &ses, None).await?;
			assert_eq!(res.len(), 1);
			res.remove(0).result.unwrap();
			// Obtain the initial uuids
			let txn = ds.transaction(TransactionType::Read, LockType::Pessimistic).await?;
			let tb = TableName::from("test");
			let initial = txn.get_tb(db.namespace_id, db.database_id, &tb, None).await?.unwrap();
			let initial_live_query_version =
				cache.get_live_queries_version(db.namespace_id, db.database_id, &tb)?;
			txn.cancel().await?;
			(initial, initial_live_query_version)
		};

		// Define some resources to refresh the UUIDs
		let lqid = {
			let sql = r"
		DEFINE FIELD test ON test;
		DEFINE EVENT test ON test WHEN {} THEN {};
		DEFINE TABLE view AS SELECT * FROM test;
		DEFINE INDEX test ON test FIELDS test;
		LIVE SELECT * FROM test;
	"
			.to_owned();
			let res = &mut ds.execute(&sql, &ses, None).await?;
			assert_eq!(res.len(), 5);
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
			let lqid = res.remove(0).result?;
			assert!(matches!(lqid, PublicValue::Uuid(_)));
			lqid
		};

		// Obtain the uuids after definitions
		let (after_define, after_define_live_query_version) = {
			let txn = ds.transaction(TransactionType::Read, LockType::Pessimistic).await?;
			let tb = TableName::from("test");
			let after_define =
				txn.get_tb(db.namespace_id, db.database_id, &tb, None).await?.unwrap();
			let after_define_live_query_version =
				cache.get_live_queries_version(db.namespace_id, db.database_id, &tb)?;
			txn.cancel().await?;
			// Compare uuids after definitions
			assert_ne!(initial.cache_indexes_ts, after_define.cache_indexes_ts);
			assert_ne!(initial.cache_tables_ts, after_define.cache_tables_ts);
			assert_ne!(initial.cache_events_ts, after_define.cache_events_ts);
			assert_ne!(initial.cache_fields_ts, after_define.cache_fields_ts);
			assert_ne!(initial_live_query_version, after_define_live_query_version);
			(after_define, after_define_live_query_version)
		};

		// Remove the defined resources to refresh the UUIDs
		{
			let sql = r"
		REMOVE FIELD test ON test;
		REMOVE EVENT test ON test;
		REMOVE TABLE view;
		REMOVE INDEX test ON test;
		KILL $lqid;
	"
			.to_owned();
			let vars =
				PublicVariables::from(BTreeMap::from_iter(map! { "lqid".to_string() => lqid }));
			let res = &mut ds.execute(&sql, &ses, Some(vars)).await?;
			assert_eq!(res.len(), 5);
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
			res.remove(0).result.unwrap();
		}
		// Obtain the uuids after definitions
		{
			let txn = ds.transaction(TransactionType::Read, LockType::Pessimistic).await?;
			let tb = TableName::from("test");
			let after_remove =
				txn.get_tb(db.namespace_id, db.database_id, &tb, None).await?.unwrap();
			let after_remove_live_query_version =
				cache.get_live_queries_version(db.namespace_id, db.database_id, &tb)?;
			txn.cancel().await?;
			// Compare uuids after definitions
			assert_ne!(after_define.cache_fields_ts, after_remove.cache_fields_ts);
			assert_ne!(after_define.cache_events_ts, after_remove.cache_events_ts);
			assert_ne!(after_define.cache_tables_ts, after_remove.cache_tables_ts);
			assert_ne!(after_define.cache_indexes_ts, after_remove.cache_indexes_ts);
			assert_ne!(after_define_live_query_version, after_remove_live_query_version);
		}
		//
		Ok(())
	}
}
