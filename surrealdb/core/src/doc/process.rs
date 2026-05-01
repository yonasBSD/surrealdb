use reblessive::tree::Stk;

use super::IgnoreError;
use crate::catalog::Record;
use crate::ctx::FrozenContext;
use crate::dbs::{Operable, Options, Processable, Statement, Workable};
use crate::doc::Document;
use crate::err::Error;
use crate::val::Value;

impl Document {
	#[cfg_attr(
		feature = "trace-doc-ops",
		instrument(level = "trace", name = "Document::process", skip_all)
	)]
	pub(crate) async fn process(
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		stm: &Statement<'_>,
		Processable {
			doc_ctx,
			record_strategy,
			generate,
			rid,
			val,
			ir,
		}: Processable,
	) -> Result<Value, IgnoreError> {
		// Check current context
		if ctx.is_done(None).await? {
			// Don't process the document
			return Err(IgnoreError::Ignore);
		}
		// Setup a new workable
		let ins = match val {
			Operable::Value(v) => (v, Workable::Normal),
			Operable::Insert(v, o) => (v, Workable::Insert(o)),
			Operable::Relate(f, v, w, o) => (v, Workable::Relate(f, w, o)),
			Operable::Count(count) => {
				(Record::new(Value::from(count)).into_read_only(), Workable::Normal)
			}
		};
		// Setup a new document
		let mut doc =
			Document::new(doc_ctx, rid, ir, generate, ins.0, ins.1, false, record_strategy);
		// Process the statement. We do not use `?` here because we
		// must inspect `doc.mutated` even on `IgnoreError::Ignore`
		// returns (e.g. `Output::None`, post-write
		// `check_output_permissions` denials, `opt.import`) so the
		// affected-row counter reflects rows that were actually
		// written even when the per-document value is suppressed.
		let res = match stm {
			Statement::Select {
				stmt,
				omit,
				..
			} => doc.select(stk, ctx, opt, stmt, omit).await,
			Statement::Create(_) => doc.create(stk, ctx, opt, stm).await,
			Statement::Upsert(_) => doc.upsert(stk, ctx, opt, stm).await,
			Statement::Update(_) => doc.update(stk, ctx, opt, stm).await,
			Statement::Relate(_) => doc.relate(stk, ctx, opt, stm).await,
			Statement::Delete(_) => doc.delete(stk, ctx, opt, stm).await,
			Statement::Insert(stm) => doc.insert(stk, ctx, opt, stm).await,
			stm => {
				return Err(IgnoreError::from(anyhow::Error::new(Error::unreachable(
					format_args!("Unexpected statement type: {stm:?}"),
				))));
			}
		};
		// Bump the per-statement affected-row counter when a real KV
		// write happened. The flag is set inside `store_record_data`
		// / `purge` after the KV op succeeds, so pre-mutation
		// `Ignore` paths (`check_record_exists`,
		// `check_where_condition`, permission gates, `ctx.is_done`)
		// and `set_record` no-ops suppressed by `!self.changed()`
		// leave it `false` and never inflate the count. We skip the
		// bump on hard errors because the surrounding transaction
		// will be rolled back. SELECT statements never call
		// `store_record_data` / `purge`, so `doc.mutated` stays
		// `false` for them.
		if doc.mutated
			&& !matches!(res, Err(IgnoreError::Error(_)))
			&& let Some(counters) = ctx.statement_counters()
		{
			counters.record_affected();
		}
		res
	}
}
