use anyhow::{Result, ensure};
use surrealdb_types::ToSql;

use crate::catalog::providers::TableProvider;
use crate::catalog::{RecordType, Relation, TableType};
use crate::ctx::FrozenContext;
use crate::dbs::Options;
use crate::doc::{Document, Extras};
use crate::err::Error;
use crate::expr::Dir;
use crate::expr::paths::{IN, OUT};

impl Document {
	/// Stores edge data for relation records in the graph database.
	///
	/// This function handles the persistence of graph edges when a relation record is created
	/// or updated. It stores four graph keys that enable bidirectional traversal:
	/// - Left pointer edge: from the `in` record pointing to this relation
	/// - Left inner edge: from this relation pointing to the `in` record
	/// - Right inner edge: from this relation pointing to the `out` record
	/// - Right pointer edge: from the `out` record pointing to this relation
	///
	/// For enforced relations, it validates that both the `in` and `out` records exist
	/// before creating the edges. It also marks the record metadata as an edge type and
	/// stores the `in` and `out` fields on the document.
	pub(super) async fn store_edges_data(
		&mut self,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<()> {
		// Get the table
		let tb = self.doc_ctx.tb()?;
		// Check if the table is DROP
		if tb.drop {
			return Ok(());
		}
		// Store the record edges
		if let Extras::Relate(l, r, _) = &self.extras {
			// Get the namespace id
			let ns = self.doc_ctx.ns().namespace_id;
			// Get the database id
			let db = self.doc_ctx.db().database_id;
			// Get the record id
			let rid = self.id()?;
			// Get the transaction
			let txn = ctx.tx();
			// For enforced relations, ensure that the edges exist
			if matches!(
				tb.table_type,
				TableType::Relation(Relation {
					enforced: true,
					..
				})
			) {
				// Check that the `in` record exists
				ensure!(
					txn.record_exists(ns, db, &l.table, &l.key, opt.version).await?,
					Error::IdNotFound {
						rid: l.to_sql(),
					}
				);
				// Check that the `out` record exists
				ensure!(
					txn.record_exists(ns, db, &r.table, &r.key, opt.version).await?,
					Error::IdNotFound {
						rid: r.to_sql(),
					}
				);
			}
			// Store the left pointer edge
			let key1 = crate::key::graph::new(ns, db, &l.table, &l.key, Dir::Out, &rid);
			// Store the left inner edge
			let key2 = crate::key::graph::new(ns, db, &rid.table, &rid.key, Dir::In, l);
			// Store the right inner edge
			let key3 = crate::key::graph::new(ns, db, &rid.table, &rid.key, Dir::Out, r);
			// Store the right pointer edge
			let key4 = crate::key::graph::new(ns, db, &r.table, &r.key, Dir::In, &rid);
			// Store the edges
			futures::try_join!(
				txn.set(&key1, &()),
				txn.set(&key2, &()),
				txn.set(&key3, &()),
				txn.set(&key4, &()),
			)?;
			// Mark this record as an edge type in its metadata
			self.current.doc.set_record_type(RecordType::Edge);
			self.current.doc.to_mut().put(&IN, l.clone().into());
			self.current.doc.to_mut().put(&OUT, r.clone().into());
		}
		// Carry on
		Ok(())
	}
}
