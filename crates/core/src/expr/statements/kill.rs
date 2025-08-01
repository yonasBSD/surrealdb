use crate::dbs::{Action, Notification, Options};
use crate::doc::CursorDoc;
use crate::err::Error;
use crate::expr::Value;
use crate::{ctx::Context, expr::FlowResultExt as _, expr::Uuid};
use anyhow::{Result, bail};

use reblessive::tree::Stk;
use revision::revisioned;
use serde::{Deserialize, Serialize};
use std::fmt;

#[revisioned(revision = 1)]
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub struct KillStatement {
	// Uuid of Live Query
	// or Param resolving to Uuid of Live Query
	pub id: Value,
}

impl KillStatement {
	/// Process this type returning a computed simple Value
	pub(crate) async fn compute(
		&self,
		stk: &mut Stk,
		ctx: &Context,
		opt: &Options,
		_doc: Option<&CursorDoc>,
	) -> Result<Value> {
		// Is realtime enabled?
		opt.realtime()?;
		// Valid options?
		opt.valid_for_db()?;
		// Resolve live query id
		let lid = match self.id.compute(stk, ctx, opt, None).await.catch_return()?.cast_to::<Uuid>()
		{
			Err(_) => {
				bail!(Error::KillStatement {
					value: self.id.to_string(),
				})
			}
			Ok(id) => id,
		};
		// Get the Node ID
		let nid = opt.id()?;
		// Get the LIVE ID
		let lid = lid.0;
		// Get the transaction
		let txn = ctx.tx();
		// Fetch the live query key
		let key = crate::key::node::lq::new(nid, lid);
		// Fetch the live query key if it exists
		match txn.get(&key, None).await? {
			Some(val) => {
				// Delete the node live query
				let key = crate::key::node::lq::new(nid, lid);
				txn.clr(&key).await?;
				// Delete the table live query
				let key = crate::key::table::lq::new(&val.ns, &val.db, &val.tb, lid);
				txn.clr(&key).await?;
				// Refresh the table cache for lives
				if let Some(cache) = ctx.get_cache() {
					cache.new_live_queries_version(&val.ns, &val.db, &val.tb);
				}
				// Clear the cache
				txn.clear();
			}
			None => {
				bail!(Error::KillStatement {
					value: self.id.to_string(),
				});
			}
		}
		if let Some(chn) = opt.sender.as_ref() {
			chn.send(Notification {
				id: lid.into(),
				action: Action::Killed,
				record: Value::None,
				result: Value::None,
			})
			.await?;
		}
		// Return the query id
		Ok(Value::None)
	}
}

impl fmt::Display for KillStatement {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "KILL {}", self.id)
	}
}
