use super::{FlowResultExt, Ident, Kind};
use crate::ctx::MutableContext;
use crate::{ctx::Context, dbs::Options, doc::CursorDoc, err::Error, expr::value::Value};
use anyhow::{Result, bail};
use reblessive::tree::Stk;
use revision::revisioned;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) const TOKEN: &str = "$surrealdb::private::sql::Closure";

#[revisioned(revision = 1)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Serialize, Deserialize, Hash)]
#[serde(rename = "$surrealdb::private::sql::Closure")]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub struct Closure {
	pub args: Vec<(Ident, Kind)>,
	pub returns: Option<Kind>,
	pub body: Value,
}

impl Closure {
	pub(crate) async fn compute(
		&self,
		stk: &mut Stk,
		ctx: &Context,
		opt: &Options,
		doc: Option<&CursorDoc>,
		args: Vec<Value>,
	) -> Result<Value> {
		let mut ctx = MutableContext::new_isolated(ctx);
		for (i, (name, kind)) in self.args.iter().enumerate() {
			match (kind, args.get(i)) {
				(Kind::Option(_), None) => continue,
				(_, None) => {
					bail!(Error::InvalidArguments {
						name: "ANONYMOUS".to_string(),
						message: format!("Expected a value for ${}", name),
					})
				}
				(kind, Some(val)) => {
					if let Ok(val) = val.to_owned().coerce_to_kind(kind) {
						ctx.add_value(name.to_string(), val.into());
					} else {
						bail!(Error::InvalidArguments {
							name: "ANONYMOUS".to_string(),
							message: format!(
								"Expected a value of type '{kind}' for argument ${}",
								name
							),
						});
					}
				}
			}
		}

		let ctx = ctx.freeze();
		let result = self.body.compute(stk, &ctx, opt, doc).await.catch_return()?;
		if let Some(returns) = &self.returns {
			result
				.coerce_to_kind(returns)
				.map_err(|e| Error::ReturnCoerce {
					name: "ANONYMOUS".to_string(),
					error: Box::new(e),
				})
				.map_err(anyhow::Error::new)
		} else {
			Ok(result)
		}
	}
}

impl fmt::Display for Closure {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str("|")?;
		for (i, (name, kind)) in self.args.iter().enumerate() {
			if i > 0 {
				f.write_str(", ")?;
			}
			write!(f, "${name}: ")?;
			match kind {
				k @ Kind::Either(_) => write!(f, "<{}>", k)?,
				k => write!(f, "{}", k)?,
			}
		}
		f.write_str("|")?;
		if let Some(returns) = &self.returns {
			write!(f, " -> {returns}")?;
		}
		write!(f, " {}", self.body)
	}
}
