//! `surreal migrate-record-ids` — rewrite legacy 3.0.x / 3.1.0-beta
//! record-id keys (records, indexes, and graph edges) under the
//! unified disc-10 lex layout.
//!
//! See [`surrealdb_core::kvs::migrate_record_ids`] for the migration
//! semantics and rationale. This CLI is a thin wrapper: validate the
//! path, open the datastore, call
//! [`surrealdb_core::kvs::Datastore::migrate_record_ids`], print a
//! per-category summary.

use anyhow::Result;
use clap::Args;
use surrealdb_core::kvs::{Datastore, TransactionBuilderFactory};
use tracing::info;

#[derive(Args, Debug)]
pub struct MigrateRecordIdsCommandArguments {
	#[arg(help = "Database path used for storing data")]
	#[arg(env = "SURREAL_PATH", index = 1)]
	#[arg(default_value = "memory")]
	path: String,
}

/// Run the migration end-to-end. Designed to be called offline against
/// a datastore that no live server is currently writing to — concurrent
/// writes during migration would race the per-table rewrites and could
/// leave the database in a half-migrated state (still recoverable by
/// re-running the tool).
pub async fn init<F: TransactionBuilderFactory>(
	args: MigrateRecordIdsCommandArguments,
) -> Result<()> {
	// Validate that the datastore path is one this binary knows how to open.
	F::path_valid(&args.path)?;

	info!("Opening datastore at {}", args.path);
	let ds = Datastore::new(&args.path).await?;
	let stats = ds.migrate_record_ids().await?;

	if stats.already_migrated {
		println!("Record-id encoding is already up to date — nothing to do.");
		return Ok(());
	}

	println!("Record-id encoding migration complete.");
	println!("  Tables scanned:       {}", stats.tables_scanned);
	println!("  Records inspected:    {}", stats.records_inspected);
	println!("  Records rewritten:    {}", stats.records_rewritten);
	println!("  Index keys inspected: {}", stats.index_keys_inspected);
	println!("  Index keys rewritten: {}", stats.index_keys_rewritten);
	println!("  Graph keys inspected: {}", stats.graph_keys_inspected);
	println!("  Graph keys rewritten: {}", stats.graph_keys_rewritten);
	Ok(())
}
