use std::collections::HashMap;

use crate::cf::{TableMutation, TableMutations};
use crate::doc::CursorValue;
use crate::expr::Idiom;
use crate::expr::statements::DefineTableStatement;
use crate::expr::thing::Thing;
use crate::kvs::{KVKey, Key};
use anyhow::Result;

// PreparedWrite is a tuple of (versionstamp key, key prefix, key suffix, serialized table mutations).
// The versionstamp key is the key that contains the current versionstamp and might be used by the
// specific transaction implementation to make the versionstamp unique and monotonic.
// The key prefix and key suffix are used to construct the key for the table mutations.
// The consumer of this library should write KV pairs with the following format:
// key = key_prefix + versionstamp + key_suffix
// value = serialized table mutations
type PreparedWrite = (Vec<u8>, Vec<u8>, Vec<u8>, crate::kvs::Val);

#[non_exhaustive]
pub struct Writer {
	buf: Buffer,
}

#[non_exhaustive]
pub struct Buffer {
	pub b: HashMap<ChangeKey, TableMutations>,
}

#[derive(Hash, Eq, PartialEq, Debug)]
#[non_exhaustive]
pub struct ChangeKey {
	pub ns: String,
	pub db: String,
	pub tb: String,
}

impl Buffer {
	pub fn new() -> Self {
		Self {
			b: HashMap::new(),
		}
	}

	pub fn push(&mut self, ns: String, db: String, tb: String, m: TableMutation) {
		let tb2 = tb.clone();
		let ms = self
			.b
			.entry(ChangeKey {
				ns,
				db,
				tb,
			})
			.or_insert(TableMutations::new(tb2));
		ms.1.push(m);
	}
}

// Writer is a helper for writing table mutations to a transaction.
impl Writer {
	pub(crate) fn new() -> Self {
		Self {
			buf: Buffer::new(),
		}
	}

	#[expect(clippy::too_many_arguments)]
	pub(crate) fn record_cf_change(
		&mut self,
		ns: &str,
		db: &str,
		tb: &str,
		id: Thing,
		previous: CursorValue,
		current: CursorValue,
		store_difference: bool,
	) {
		if current.as_ref().is_some() {
			self.buf.push(
				ns.to_string(),
				db.to_string(),
				tb.to_string(),
				match store_difference {
					true => {
						if previous.as_ref().is_none() {
							TableMutation::Set(id, current.into_owned())
						} else {
							// We intentionally record the patches in reverse (current -> previous)
							// because we cannot otherwise resolve operations such as "replace" and "remove".
							let patches_to_create_previous =
								current.diff(&previous, Idiom::default());
							TableMutation::SetWithDiff(
								id,
								current.into_owned(),
								patches_to_create_previous,
							)
						}
					}
					false => TableMutation::Set(id, current.into_owned()),
				},
			);
		} else {
			self.buf.push(
				ns.to_string(),
				db.to_string(),
				tb.to_string(),
				match store_difference {
					true => TableMutation::DelWithOriginal(id, previous.into_owned()),
					false => TableMutation::Del(id),
				},
			);
		}
	}

	pub(crate) fn define_table(&mut self, ns: &str, db: &str, tb: &str, dt: &DefineTableStatement) {
		self.buf.push(
			ns.to_string(),
			db.to_string(),
			tb.to_string(),
			TableMutation::Def(dt.to_owned()),
		)
	}

	// get returns all the mutations buffered for this transaction,
	// that are to be written onto the key composed of the specified prefix + the current timestamp + the specified suffix.
	pub(crate) fn get(&self) -> Result<Vec<PreparedWrite>> {
		let mut r = Vec::<(Vec<u8>, Vec<u8>, Vec<u8>, crate::kvs::Val)>::new();
		// Get the current timestamp
		for (
			ChangeKey {
				ns,
				db,
				tb,
			},
			mutations,
		) in self.buf.b.iter()
		{
			let ts_key: Key = crate::key::database::vs::new(ns, db).encode_key()?;
			let tc_key_prefix: Key = crate::key::change::versionstamped_key_prefix(ns, db)?;
			let tc_key_suffix: Key = crate::key::change::versionstamped_key_suffix(tb.as_str());
			let value = revision::to_vec(mutations)?;

			r.push((ts_key, tc_key_prefix, tc_key_suffix, value))
		}
		Ok(r)
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use crate::cf::{ChangeSet, DatabaseMutation, TableMutation, TableMutations};
	use crate::expr::Datetime;
	use crate::expr::changefeed::ChangeFeed;
	use crate::expr::id::Id;
	use crate::expr::statements::show::ShowSince;
	use crate::expr::statements::{
		DefineDatabaseStatement, DefineNamespaceStatement, DefineTableStatement,
	};
	use crate::expr::thing::Thing;
	use crate::expr::value::Value;
	use crate::kvs::{Datastore, LockType::*, Transaction, TransactionType::*};
	use crate::vs::VersionStamp;

	const DONT_STORE_PREVIOUS: bool = false;

	const NS: &str = "myns";
	const DB: &str = "mydb";
	const TB: &str = "mytb";

	#[tokio::test]
	async fn changefeed_read_write() {
		let ts = Datetime::default();
		let ds = init(false).await;

		// Let the db remember the timestamp for the current versionstamp
		// so that we can replay change feeds from the timestamp later.
		ds.changefeed_process_at(None, ts.0.timestamp().try_into().unwrap()).await.unwrap();

		//
		// Write things to the table.
		//

		let mut tx1 = ds.transaction(Write, Optimistic).await.unwrap().inner();
		let thing_a = Thing {
			tb: TB.to_owned(),
			id: Id::from("A"),
		};
		let value_a: Value = "a".into();
		let previous = Value::None;
		tx1.record_change(
			NS,
			DB,
			TB,
			&thing_a,
			previous.clone().into(),
			value_a.into(),
			DONT_STORE_PREVIOUS,
		);
		tx1.complete_changes(true).await.unwrap();
		tx1.commit().await.unwrap();

		let mut tx2 = ds.transaction(Write, Optimistic).await.unwrap().inner();
		let thing_c = Thing {
			tb: TB.to_owned(),
			id: Id::from("C"),
		};
		let value_c: Value = "c".into();
		tx2.record_change(
			NS,
			DB,
			TB,
			&thing_c,
			previous.clone().into(),
			value_c.into(),
			DONT_STORE_PREVIOUS,
		);
		tx2.complete_changes(true).await.unwrap();
		tx2.commit().await.unwrap();

		let mut tx3 = ds.transaction(Write, Optimistic).await.unwrap().inner();
		let thing_b = Thing {
			tb: TB.to_owned(),
			id: Id::from("B"),
		};
		let value_b: Value = "b".into();
		tx3.record_change(
			NS,
			DB,
			TB,
			&thing_b,
			previous.clone().into(),
			value_b.into(),
			DONT_STORE_PREVIOUS,
		);
		let thing_c2 = Thing {
			tb: TB.to_owned(),
			id: Id::from("C"),
		};
		let value_c2: Value = "c2".into();
		tx3.record_change(
			NS,
			DB,
			TB,
			&thing_c2,
			previous.clone().into(),
			value_c2.into(),
			DONT_STORE_PREVIOUS,
		);
		tx3.complete_changes(true).await.unwrap();
		tx3.commit().await.unwrap();

		// Note that we committed tx1, tx2, and tx3 in this order so far.
		// Therefore, the change feeds should give us
		// the mutations in the commit order, which is tx1, tx3, then tx2.

		let start: u64 = 0;

		let tx4 = ds.transaction(Write, Optimistic).await.unwrap();
		let r = crate::cf::read(&tx4, NS, DB, Some(TB), ShowSince::Versionstamp(start), Some(10))
			.await
			.unwrap();
		tx4.commit().await.unwrap();

		let want: Vec<ChangeSet> = vec![
			ChangeSet(
				VersionStamp::from_u64(2),
				DatabaseMutation(vec![TableMutations(
					TB.to_string(),
					vec![TableMutation::Set(
						Thing::from((TB.to_string(), "A".to_string())),
						Value::from("a"),
					)],
				)]),
			),
			ChangeSet(
				VersionStamp::from_u64(3),
				DatabaseMutation(vec![TableMutations(
					TB.to_string(),
					vec![TableMutation::Set(
						Thing::from((TB.to_string(), "C".to_string())),
						Value::from("c"),
					)],
				)]),
			),
			ChangeSet(
				VersionStamp::from_u64(4),
				DatabaseMutation(vec![TableMutations(
					TB.to_string(),
					vec![
						TableMutation::Set(
							Thing::from((TB.to_string(), "B".to_string())),
							Value::from("b"),
						),
						TableMutation::Set(
							Thing::from((TB.to_string(), "C".to_string())),
							Value::from("c2"),
						),
					],
				)]),
			),
		];

		assert_eq!(r, want);

		let tx5 = ds.transaction(Write, Optimistic).await.unwrap();
		// gc_all needs to be committed before we can read the changes
		crate::cf::gc_range(&tx5, NS, DB, VersionStamp::from_u64(4)).await.unwrap();
		// We now commit tx5, which should persist the gc_all resullts
		tx5.commit().await.unwrap();

		// Now we should see the gc_all results
		let tx6 = ds.transaction(Write, Optimistic).await.unwrap();
		let r = crate::cf::read(&tx6, NS, DB, Some(TB), ShowSince::Versionstamp(start), Some(10))
			.await
			.unwrap();
		tx6.commit().await.unwrap();

		let want: Vec<ChangeSet> = vec![ChangeSet(
			VersionStamp::from_u64(4),
			DatabaseMutation(vec![TableMutations(
				TB.to_string(),
				vec![
					TableMutation::Set(
						Thing::from((TB.to_string(), "B".to_string())),
						Value::from("b"),
					),
					TableMutation::Set(
						Thing::from((TB.to_string(), "C".to_string())),
						Value::from("c2"),
					),
				],
			)]),
		)];
		assert_eq!(r, want);

		// Now we should see the gc_all results
		ds.changefeed_process_at(None, (ts.0.timestamp() + 5).try_into().unwrap()).await.unwrap();

		let tx7 = ds.transaction(Write, Optimistic).await.unwrap();
		let r = crate::cf::read(&tx7, NS, DB, Some(TB), ShowSince::Timestamp(ts), Some(10))
			.await
			.unwrap();
		tx7.commit().await.unwrap();
		assert_eq!(r, want);
	}

	#[test_log::test(tokio::test)]
	async fn scan_picks_up_from_offset() {
		// Given we have 2 entries in change feeds
		let ds = init(false).await;
		ds.changefeed_process_at(None, 5).await.unwrap();
		let _id1 = record_change_feed_entry(
			ds.transaction(Write, Optimistic).await.unwrap(),
			"First".to_string(),
		)
		.await;
		ds.changefeed_process_at(None, 10).await.unwrap();
		let mut tx = ds.transaction(Write, Optimistic).await.unwrap().inner();
		let vs1 = tx.get_versionstamp_from_timestamp(5, NS, DB).await.unwrap().unwrap();
		let vs2 = tx.get_versionstamp_from_timestamp(10, NS, DB).await.unwrap().unwrap();
		tx.cancel().await.unwrap();
		let _id2 = record_change_feed_entry(
			ds.transaction(Write, Optimistic).await.unwrap(),
			"Second".to_string(),
		)
		.await;

		// When we scan from the versionstamp between the changes
		let r = change_feed_vs(ds.transaction(Write, Optimistic).await.unwrap(), &vs2).await;

		// Then there is only 1 change
		assert_eq!(r.len(), 1);
		assert!(r[0].0 >= vs2, "{:?}", r);

		// And scanning with previous offset includes both values (without table definitions)
		let r = change_feed_vs(ds.transaction(Write, Optimistic).await.unwrap(), &vs1).await;
		assert_eq!(r.len(), 2);
	}

	async fn change_feed_vs(tx: Transaction, vs: &VersionStamp) -> Vec<ChangeSet> {
		let r = crate::cf::read(
			&tx,
			NS,
			DB,
			Some(TB),
			ShowSince::Versionstamp(vs.into_u64_lossy()),
			Some(10),
		)
		.await
		.unwrap();
		tx.cancel().await.unwrap();
		r
	}

	async fn record_change_feed_entry(tx: Transaction, id: String) -> Thing {
		let thing = Thing {
			tb: TB.to_owned(),
			id: Id::from(id),
		};
		let value_a: Value = "a".into();
		let previous = Value::None.into();
		tx.lock().await.record_change(
			NS,
			DB,
			TB,
			&thing,
			previous,
			value_a.into(),
			DONT_STORE_PREVIOUS,
		);
		tx.lock().await.complete_changes(true).await.unwrap();
		tx.commit().await.unwrap();
		thing
	}

	async fn init(store_diff: bool) -> Datastore {
		let dns = DefineNamespaceStatement {
			name: crate::expr::Ident(NS.to_string()),
			..Default::default()
		};
		let ddb = DefineDatabaseStatement {
			name: crate::expr::Ident(DB.to_string()),
			changefeed: Some(ChangeFeed {
				expiry: Duration::from_secs(10),
				store_diff,
			}),
			..Default::default()
		};
		let dtb = DefineTableStatement {
			name: TB.into(),
			changefeed: Some(ChangeFeed {
				expiry: Duration::from_secs(10 * 60),
				store_diff,
			}),
			..Default::default()
		};

		let ds = Datastore::new("memory").await.unwrap();

		//
		// Create the ns, db, and tb to let the GC and the timestamp-to-versionstamp conversion
		// work.
		//

		let mut tx = ds.transaction(Write, Optimistic).await.unwrap().inner();
		let ns_root = crate::key::root::ns::new(NS);
		tx.put(&ns_root, &dns, None).await.unwrap();
		let db_root = crate::key::namespace::db::new(NS, DB);
		tx.put(&db_root, &ddb, None).await.unwrap();
		let tb_root = crate::key::database::tb::new(NS, DB, TB);
		tx.put(&tb_root, &dtb, None).await.unwrap();
		tx.commit().await.unwrap();
		ds
	}
}
