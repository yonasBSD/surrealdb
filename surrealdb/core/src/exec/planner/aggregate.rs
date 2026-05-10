//! Aggregation planning for the planner.
//!
//! Handles GROUP BY, aggregate function extraction, and the `AggregateExtractor` visitor.

use std::sync::Arc;

use super::Planner;
use super::util::{derive_field_name, idiom_to_field_name};
use crate::err::Error;
use crate::exec::operators::{
	AggregateExprInfo, AggregateField, ExtractedAggregate, aggregate_field_name,
};
use crate::expr::field::{Field, Fields};
use crate::expr::part::Part;
use crate::expr::visit::{MutVisitor, VisitMut};
use crate::expr::{Expr, Function, FunctionCall, Idiom, Literal};

/// Build a nested output path from an idiom by walking its [`Part`]s
/// directly so a single [`Part::Field`] whose identifier contains a dot
/// (e.g. `` AS `foo.bar` ``) stays a flat `["foo.bar"]` key rather than
/// being split on `.`.
///
/// Mirrors the behaviour of `idiom_to_field_path` in the projection
/// planner so both pipelines agree on output field names:
///
/// - Graph-traversal aliases (`` ->friends->person AS buddy ``) are detected before simplification
///   and collapse to the alias identifier.
/// - Execution-only parts (array filters, indices, method calls, etc.) are dropped via
///   [`Idiom::simplify`].
/// - Simplified paths that still contain non-[`Part::Field`] components fall back to the simplified
///   SQL form so the streaming path produces the same flat key the compute-only path would.
fn alias_output_path(idiom: &Idiom) -> Vec<String> {
	use surrealdb_types::ToSql;

	// Graph traversals with an inline alias collapse to a single flat
	// field name (the alias identifier), matching `idiom_to_field_name`.
	// Delegate to `idiom_to_field_name` rather than recursing into
	// `alias_output_path`, because a multi-part inline alias (e.g.
	// `->x AS foo.bar` where the alias is parsed as `[Field(foo),
	// Field(bar)]`) must flatten to a single `"foo.bar"` key to match
	// `idiom_to_field_path`, not nest into `["foo", "bar"]`.
	for part in idiom.0.iter() {
		if let Part::Lookup(lookup) = part
			&& lookup.alias.is_some()
		{
			return vec![idiom_to_field_name(idiom)];
		}
	}

	let simplified = idiom.simplify();
	let mut parts = Vec::with_capacity(simplified.0.len());
	for part in simplified.0.iter() {
		match part {
			Part::Field(name) => parts.push(name.as_str().to_owned()),
			// Unaliased graph traversals become their own output key (e.g.
			// `->knows` or `<-foo<-bar`), matching `idiom_to_field_path`'s
			// `Part::Lookup` arm. Without this, `->knows.name` would
			// collapse to the flat `"->knows.name"` key here while the
			// projection planner would nest into `{ "->knows": { name: _ } }`.
			Part::Lookup(lookup) => parts.push(lookup.to_sql()),
			// Other unsupported parts (e.g. `Part::Start` for parameter
			// starts) fall back to a single flat key derived from the
			// simplified SQL form, matching `idiom_to_field_path`'s
			// fallback arm.
			_ => return vec![simplified.to_sql()],
		}
	}
	if parts.is_empty() {
		return vec![simplified.to_sql()];
	}
	parts
}

// ============================================================================
// impl Planner — Aggregation
// ============================================================================

impl<'ctx> Planner<'ctx> {
	/// Plan aggregation fields from SELECT expression and GROUP BY.
	///
	/// Returns the aggregate fields and the physical expressions for group keys.
	#[allow(clippy::type_complexity)]
	pub(crate) async fn plan_aggregation(
		&self,
		fields: &Fields,
		group_by: &[crate::expr::idiom::Idiom],
	) -> Result<(Vec<AggregateField>, Vec<Arc<dyn crate::exec::PhysicalExpr>>), Error> {
		use surrealdb_types::ToSql;

		// Build alias -> expression map from SELECT fields
		let mut alias_to_expr: std::collections::HashMap<String, Expr> =
			std::collections::HashMap::new();
		match fields {
			Fields::Value(selector) => {
				if let Some(alias) = &selector.alias {
					alias_to_expr.insert(alias.to_sql(), selector.expr.clone());
				}
			}
			Fields::Select(field_list) => {
				for field in field_list {
					if let Field::Single(selector) = field
						&& let Some(alias) = &selector.alias
					{
						alias_to_expr.insert(alias.to_sql(), selector.expr.clone());
					}
				}
			}
		}

		// Build group-by expressions, expanding aliases
		let mut group_by_exprs = Vec::with_capacity(group_by.len());
		for idiom in group_by {
			let idiom_str = idiom.to_sql();
			let expr = if let Some(select_expr) = alias_to_expr.get(&idiom_str) {
				select_expr.clone()
			} else {
				Expr::Idiom(idiom.clone())
			};
			let physical_expr = self.physical_expr(expr).await?;
			group_by_exprs.push(physical_expr);
		}

		match fields {
			Fields::Value(selector) => {
				let group_key_index =
					find_group_key_index(&selector.expr, selector.alias.as_ref(), group_by);
				let is_group_key = group_key_index.is_some();

				let (aggregate_expr_info, fallback_expr) = if is_group_key {
					(None, None)
				} else {
					self.extract_aggregate_info(selector.expr.clone()).await?
				};

				Ok((
					vec![AggregateField::new(
						String::new(),
						is_group_key,
						group_key_index,
						aggregate_expr_info,
						fallback_expr,
					)],
					group_by_exprs,
				))
			}

			Fields::Select(field_list) => {
				let mut aggregates = Vec::with_capacity(field_list.len());

				for field in field_list {
					match field {
						Field::All => {
							return Err(Error::Query {
								message: "Incorrect selector for aggregate selection, expression `*` within in selector cannot be aggregated in a group."
									.to_string(),
							});
						}
						Field::Single(selector) => {
							// For an explicit alias, walk the idiom parts
							// so `AS foo.bar` nests as `[foo, bar]` while
							// `` AS `foo.bar` `` stays a flat single key.
							// For an unaliased idiom expression (e.g.
							// `SELECT address.city ...`), walk the source
							// idiom's parts to preserve the same nesting
							// structure. Other unaliased expressions
							// derive a flat name.
							let output_path = if let Some(alias) = &selector.alias {
								alias_output_path(alias)
							} else if let Expr::Idiom(idiom) = &selector.expr {
								alias_output_path(idiom)
							} else {
								vec![derive_field_name(&selector.expr)]
							};

							let group_key_index = find_group_key_index(
								&selector.expr,
								selector.alias.as_ref(),
								group_by,
							);
							let is_group_key = group_key_index.is_some();

							let (aggregate_expr_info, fallback_expr) = if is_group_key {
								(None, None)
							} else {
								self.extract_aggregate_info(selector.expr.clone()).await?
							};

							aggregates.push(AggregateField::with_output_path(
								output_path,
								is_group_key,
								group_key_index,
								aggregate_expr_info,
								fallback_expr,
							));
						}
					}
				}

				Ok((aggregates, group_by_exprs))
			}
		}
	}

	/// Extract aggregate function information from an expression.
	///
	/// Uses `AggregateExtractor` to walk the expression tree. If no aggregates
	/// are found, uses implicit `array::group` aggregation.
	///
	/// Takes `expr` by value. When no aggregate functions are found, the visitor
	/// leaves the expression unchanged, so we can use it directly for the
	/// implicit `array::group` fallback without an extra clone.
	#[allow(clippy::type_complexity)]
	#[allow(clippy::clone_on_ref_ptr)] // Several paths clone `Arc<dyn AggregateFunction>` from concrete registry entries
	pub(crate) async fn extract_aggregate_info(
		&self,
		mut expr: Expr,
	) -> Result<(Option<AggregateExprInfo>, Option<Arc<dyn crate::exec::PhysicalExpr>>), Error> {
		let registry = self.function_registry();

		let mut extractor = AggregateExtractor::new(registry);
		let _ = extractor.visit_mut_expr(&mut expr);

		if let Some(err) = extractor.error {
			return Err(err);
		}

		if extractor.aggregates.is_empty() {
			// No aggregates found — the visitor left expr unchanged
			let argument_expr = self.physical_expr(expr).await?;
			let array_group = registry
				.get_aggregate("array::group")
				.expect("array::group should always be registered")
				.clone();
			return Ok((
				Some(AggregateExprInfo {
					aggregates: vec![ExtractedAggregate {
						function: array_group,
						argument_expr,
						extra_args: vec![],
					}],
					post_expr: None,
				}),
				None,
			));
		}

		let mut extracted_aggregates = Vec::new();
		for (name, call) in extractor.aggregates {
			let func = if name.as_str() == "count" {
				registry.get_count_aggregate(!call.arguments.is_empty())
			} else {
				Arc::clone(registry.get_aggregate(&name).expect("aggregate function should exist"))
			};

			let mut args = call.arguments.into_iter();
			let argument_expr = if let Some(first_arg) = args.next() {
				self.physical_expr(first_arg).await
			} else {
				self.physical_expr(Expr::Literal(Literal::None)).await
			}?;

			let mut extra_args = Vec::new();
			for arg in args {
				extra_args.push(self.physical_expr(arg).await?);
			}

			extracted_aggregates.push(ExtractedAggregate {
				function: func,
				argument_expr,
				extra_args,
			});
		}

		// expr has been modified by the visitor (aggregate calls replaced with
		// placeholder idioms like `_a0`)
		let is_direct_single_aggregate = extracted_aggregates.len() == 1 && {
			use surrealdb_types::ToSql;
			matches!(&expr, Expr::Idiom(i) if i.to_sql() == "_a0")
		};

		let post_expr = if is_direct_single_aggregate {
			None
		} else {
			Some(self.physical_expr(expr).await?)
		};

		Ok((
			Some(AggregateExprInfo {
				aggregates: extracted_aggregates,
				post_expr,
			}),
			None,
		))
	}
}

// ============================================================================
// Free Functions
// ============================================================================

/// Find the index of the group-by key for an expression.
pub(super) fn find_group_key_index(
	expr: &Expr,
	alias: Option<&Idiom>,
	group_by: &[crate::expr::idiom::Idiom],
) -> Option<usize> {
	use surrealdb_types::ToSql;

	if let Expr::Idiom(idiom) = expr
		&& let Some(idx) = group_by.iter().position(|g| g.to_sql() == idiom.to_sql())
	{
		return Some(idx);
	}

	if let Some(alias) = alias
		&& let Some(idx) = group_by.iter().position(|g| g.to_sql() == alias.to_sql())
	{
		return Some(idx);
	}

	None
}

// ============================================================================
// AggregateExtractor Visitor
// ============================================================================

/// Visitor that extracts aggregate functions from an expression.
struct AggregateExtractor<'a> {
	registry: &'a crate::exec::function::FunctionRegistry,
	aggregates: Vec<(String, FunctionCall)>,
	aggregate_count: usize,
	inside_aggregate: bool,
	error: Option<Error>,
}

impl<'a> AggregateExtractor<'a> {
	fn new(registry: &'a crate::exec::function::FunctionRegistry) -> Self {
		Self {
			registry,
			aggregates: Vec::new(),
			aggregate_count: 0,
			inside_aggregate: false,
			error: None,
		}
	}

	fn contains_aggregate_call(&self, expr: &Expr) -> bool {
		if let Expr::FunctionCall(func_call) = expr
			&& let Function::Normal(name) = &func_call.receiver
		{
			return self.registry.get_aggregate(name.as_str()).is_some();
		}
		false
	}
}

impl MutVisitor for AggregateExtractor<'_> {
	type Error = std::convert::Infallible;

	fn visit_mut_expr(&mut self, expr: &mut Expr) -> Result<(), Self::Error> {
		if self.error.is_some() {
			return Ok(());
		}

		if let Expr::FunctionCall(func_call) = expr
			&& let Function::Normal(name) = &func_call.receiver
		{
			if name.as_str() == "array::distinct"
				&& !func_call.arguments.is_empty()
				&& self.contains_aggregate_call(&func_call.arguments[0])
			{
				return expr.visit_mut(self);
			}

			if self.registry.get_aggregate(name.as_str()).is_some() {
				if self.inside_aggregate {
					self.error = Some(Error::Query {
						message: "Nested aggregate functions are not supported".to_string(),
					});
					return Ok(());
				}

				self.inside_aggregate = true;
				for arg in &mut func_call.arguments {
					arg.visit_mut(self)?;
				}
				self.inside_aggregate = false;

				if self.error.is_some() {
					return Ok(());
				}

				let field_name = aggregate_field_name(self.aggregate_count);
				self.aggregates.push((name.clone(), func_call.as_ref().clone()));
				self.aggregate_count += 1;

				*expr = Expr::Idiom(Idiom::field(field_name));
				return Ok(());
			}
		}

		expr.visit_mut(self)
	}

	fn visit_mut_function_call(&mut self, f: &mut FunctionCall) -> Result<(), Self::Error> {
		if self.error.is_some() {
			return Ok(());
		}
		for arg in &mut f.arguments {
			self.visit_mut_expr(arg)?;
		}
		Ok(())
	}

	fn visit_mut_select(
		&mut self,
		_s: &mut crate::expr::statements::SelectStatement,
	) -> Result<(), Self::Error> {
		Ok(())
	}

	fn visit_mut_create(
		&mut self,
		_s: &mut crate::expr::statements::CreateStatement,
	) -> Result<(), Self::Error> {
		Ok(())
	}

	fn visit_mut_update(
		&mut self,
		_s: &mut crate::expr::statements::UpdateStatement,
	) -> Result<(), Self::Error> {
		Ok(())
	}

	fn visit_mut_delete(
		&mut self,
		_s: &mut crate::expr::statements::DeleteStatement,
	) -> Result<(), Self::Error> {
		Ok(())
	}
}
