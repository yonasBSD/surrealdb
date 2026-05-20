use std::sync::Arc;

use anyhow::Result;
use reblessive::tree::Stk;

use crate::catalog::Permission;
use crate::ctx::{Context, FrozenContext};
use crate::dbs::Options;
use crate::doc::{CursorDoc, Document};
use crate::expr::FlowResultExt as _;
use crate::iam::{Action, AuthLimit};

impl Document {
	/// Checks if reduction is required
	///
	/// This function checks if reduction is required for a document based on the following
	/// criteria:
	/// - The document has an ID and is not a temporary document
	/// - The current actor needs permission to be processed
	#[inline]
	pub(crate) fn reduction_required(&self, ctx: &FrozenContext, opt: &Options) -> Result<bool> {
		// Check if this record exists
		if self.id.is_none() {
			return Ok(false);
		}
		// Are permissions being skipped?
		if !ctx.check_perms(opt, Action::View)? {
			return Ok(false);
		}
		// Reduction is required
		Ok(true)
	}

	/// Reduces `self.current` based on field-level select permissions and
	/// returns a reference to the materialised reduced view. Caches the
	/// result in `self.current_reduced` so repeated calls in the same
	/// pipeline are cheap; callers that mutate `self.current.doc` are
	/// responsible for invalidating the cache (e.g.
	/// `process_record_data` clears it after applying the data clause).
	///
	/// When reduction is not required (owner sessions / perms disabled)
	/// the function short-circuits and returns `&mut self.current` so
	/// callers can use one borrow regardless of whether reduction kicked
	/// in.
	pub(crate) async fn reduce_current(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<&mut CursorDoc> {
		// Check if we need to reduce the document
		if self.reduction_required(ctx, opt)? {
			// Compute the reduced document if not yet done
			if self.current_reduced.is_none() {
				self.current_reduced =
					Some(self.reduce_document(stk, ctx, opt, &self.current).await?);
			}
			// Return the reduced document which was just populated above
			self.current_reduced
				.as_mut()
				.ok_or_else(|| anyhow::anyhow!("current_reduced should be set"))
		} else {
			Ok(&mut self.current)
		}
	}

	/// Reduces `self.initial` based on field-level select permissions and
	/// returns a reference to the materialised reduced view. Mirrors
	/// [`Self::reduce_current`] but for the pre-mutation document — used
	/// by `RETURN BEFORE` / `RETURN DIFF` / `RETURN <fields>` output
	/// paths, and by the LIVE-query DELETE branch where the visible
	/// payload is the pre-delete record.
	///
	/// Caches the result in `self.initial_reduced`. `self.initial` is
	/// immutable after the document is constructed, so callers don't
	/// need to invalidate this cache once it's been populated for the
	/// row.
	pub(crate) async fn reduce_initial(
		&mut self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
	) -> Result<&mut CursorDoc> {
		// Check if we need to reduce the document
		if self.reduction_required(ctx, opt)? {
			// Compute the reduced document if not yet done
			if self.initial_reduced.is_none() {
				self.initial_reduced =
					Some(self.reduce_document(stk, ctx, opt, &self.initial).await?);
			}
			// Return the reduced document which was just populated above
			self.initial_reduced
				.as_mut()
				.ok_or_else(|| anyhow::anyhow!("initial_reduced should be set"))
		} else {
			Ok(&mut self.initial)
		}
	}

	/// Reduces an arbitrary [`CursorDoc`] (typically a fresh local — not
	/// one of `self.initial` / `self.current`) and returns the owned
	/// reduced view. When reduction is not required this just clones
	/// `full`, so callers can write
	///
	/// ```ignore
	/// let local = self.reduce_to_owned(stk, ctx, opt, &self.current).await?;
	/// // …mutate `local` without touching the cache…
	/// ```
	///
	/// without having to repeat the `reduction_required` check at every
	/// call site. Used by `lq_compute` (live-query payload projection),
	/// which needs a transient reduced view that does not pollute
	/// `self.{current,initial}_reduced` (the per-subscription doc is
	/// then mutated independently of the cached views).
	pub(crate) async fn reduce_to_owned(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		full: &CursorDoc,
	) -> Result<CursorDoc> {
		if self.reduction_required(ctx, opt)? {
			self.reduce_document(stk, ctx, opt, full).await
		} else {
			Ok(full.clone())
		}
	}

	/// Reduce-the-fields kernel. Iterates the table's field definitions
	/// and cuts each field from a clone of `full.doc` based on its
	/// `PERMISSIONS FOR select` clause. The four public entry points
	/// ([`Self::reduce_current`], [`Self::reduce_initial`],
	/// [`Self::reduce_to_owned`]) layer caching / source-picking on top.
	async fn reduce_document(
		&self,
		stk: &mut Stk,
		ctx: &FrozenContext,
		opt: &Options,
		full: &CursorDoc,
	) -> Result<CursorDoc> {
		// The document to be reduced
		let mut reduced = full.doc.clone();
		// Loop over each field in document
		for fd in self.doc_ctx.fd()?.iter() {
			// SECURITY: apply the field's AUTH LIMIT before evaluating
			// PERMISSIONS FOR select so the predicate runs under the
			// definer's downgraded auth, not the caller's. Mirrors the
			// pluck.rs / field.rs paths.
			let opt = AuthLimit::try_from(&fd.auth_limit)?.limit_opt(opt);
			// Loop over each field in document
			for k in reduced.as_ref().each(&fd.name).iter() {
				// Process the field permissions
				match &fd.select_permission {
					Permission::Full => (),
					Permission::None => reduced.to_mut().cut(k),
					Permission::Specific(e) => {
						// Disable permissions
						let opt = &opt.new_with_perms(false);
						// Get the initial value
						let val = Arc::new(full.doc.as_ref().pick(k));
						// Configure the context
						let mut ctx = Context::new_child(ctx);
						ctx.add_value("value", val);
						let ctx = ctx.freeze();
						// Process the PERMISSION clause
						if !stk
							.run(|stk| e.compute(stk, &ctx, opt, Some(full)))
							.await
							.catch_return()?
							.is_truthy()
						{
							reduced.to_mut().cut(k);
						}
					}
				}
			}
		}
		// Ok
		Ok(CursorDoc::new(full.rid.clone(), full.ir.clone(), reduced))
	}
}
