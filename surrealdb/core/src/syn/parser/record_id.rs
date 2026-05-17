use std::ops::Bound;

use reblessive::Stk;
use surrealdb_strand::Strand;
use surrealdb_types::{Number, ToSql};

use super::{ParseResult, Parser};
use crate::sql::lookup::LookupSubject;
use crate::sql::{Param, RecordIdKeyGen, RecordIdKeyLit, RecordIdKeyRangeLit, RecordIdLit};
use crate::syn::error::bail;
use crate::syn::lexer::compound::{self, NumberKind};
use crate::syn::parser::mac::{expected, expected_whitespace, unexpected};
use crate::syn::token::{Span, Token, TokenKind, t};
use crate::val::DecimalExt;

impl Parser<'_> {
	pub(crate) async fn parse_record_id_or_range(
		&mut self,
		stk: &mut Stk,
		ident: Strand,
	) -> ParseResult<RecordIdLit> {
		let ident: crate::val::TableName = ident.into();
		expected_whitespace!(self, t!(":"));

		// If self starts with a range operator self is a range with no start bound
		if self.eat_whitespace(t!("..")) {
			// Check for inclusive
			let end = if self.eat_whitespace(t!("=")) {
				let id = stk.run(|stk| self.parse_record_id_key(stk)).await?;
				Bound::Included(id)
			} else if let Some(peek) = self.peek_whitespace()
				&& Self::kind_starts_record_id_key(peek.kind)
			{
				let id = stk.run(|stk| self.parse_record_id_key(stk)).await?;
				Bound::Excluded(id)
			} else {
				Bound::Unbounded
			};
			return Ok(RecordIdLit {
				table: ident,
				key: RecordIdKeyLit::Range(Box::new(RecordIdKeyRangeLit {
					start: Bound::Unbounded,
					end,
				})),
			});
		}

		// Didn't eat range yet so we need to parse the id.
		let beg = if let Some(peek) = self.peek_whitespace()
			&& Self::kind_starts_record_id_key(peek.kind)
		{
			let v = stk.run(|stk| self.parse_record_id_key(stk)).await?;

			// check for exclusive
			if self.eat_whitespace(t!(">")) {
				Bound::Excluded(v)
			} else {
				Bound::Included(v)
			}
		} else {
			Bound::Unbounded
		};

		// Check if self is actually a range.
		// If we already ate the exclusive it must be a range.
		if self.eat_whitespace(t!("..")) {
			let end = if self.eat_whitespace(t!("=")) {
				let id = stk.run(|stk| self.parse_record_id_key(stk)).await?;
				Bound::Included(id)
			} else if let Some(peek) = self.peek_whitespace()
				&& Self::kind_starts_record_id_key(peek.kind)
			{
				let id = stk.run(|stk| self.parse_record_id_key(stk)).await?;
				Bound::Excluded(id)
			} else {
				Bound::Unbounded
			};
			Ok(RecordIdLit {
				table: ident,
				key: RecordIdKeyLit::Range(Box::new(RecordIdKeyRangeLit {
					start: beg,
					end,
				})),
			})
		} else {
			let id = match beg {
				Bound::Unbounded => {
					if let Some(token) = self.peek_whitespace()
						&& token.kind == t!("$param")
					{
						let param = self.next_token_value::<Param>()?;
						bail!("Unexpected token `$param` expected a record-id key",
								@token.span => "Record-id's can be create from a param with `type::record(\"{}\",{})`", ident, param.to_sql());
					}

					// we haven't matched anything so far so we still want any type of id.
					unexpected!(self, self.peek(), "a record-id key")
				}
				Bound::Excluded(_) => {
					// we have matched a bounded id but we don't see an range operator.
					unexpected!(self, self.peek(), "the range operator `..`")
				}
				// We previously converted the `Id` value to `Value` so it's safe to unwrap here.
				Bound::Included(v) => v,
			};
			Ok(RecordIdLit {
				table: ident,
				key: id,
			})
		}
	}

	pub(crate) async fn parse_id_range(
		&mut self,
		stk: &mut Stk,
	) -> ParseResult<RecordIdKeyRangeLit> {
		let beg = if let Some(peek) = self.peek_whitespace()
			&& Self::kind_starts_record_id_key(peek.kind)
		{
			let v = stk.run(|stk| self.parse_record_id_key(stk)).await?;

			// check for exclusive
			if self.eat_whitespace(t!(">")) {
				Bound::Excluded(v)
			} else {
				Bound::Included(v)
			}
		} else {
			Bound::Unbounded
		};

		expected!(self, t!(".."));

		let end = if self.eat_whitespace(t!("=")) {
			let id = stk.run(|stk| self.parse_record_id_key(stk)).await?;
			Bound::Included(id)
		} else if let Some(peek) = self.peek_whitespace()
			&& Self::kind_starts_record_id_key(peek.kind)
		{
			let id = stk.run(|stk| self.parse_record_id_key(stk)).await?;
			Bound::Excluded(id)
		} else {
			Bound::Unbounded
		};

		Ok(RecordIdKeyRangeLit {
			start: beg,
			end,
		})
	}

	pub(crate) async fn parse_lookup_subject(
		&mut self,
		stk: &mut Stk,
		supports_referencing_field: bool,
	) -> ParseResult<LookupSubject> {
		let table: crate::val::TableName = self.parse_ident_str()?.into();
		if self.eat_whitespace(t!(":")) {
			let range = self.parse_id_range(stk).await?;
			let referencing_field =
				self.parse_referencing_field(supports_referencing_field).await?;

			Ok(LookupSubject::Range {
				table,
				range,
				referencing_field,
			})
		} else {
			Ok(LookupSubject::Table {
				table,
				referencing_field: self.parse_referencing_field(supports_referencing_field).await?,
			})
		}
	}

	pub(crate) async fn parse_referencing_field(
		&mut self,
		supports_referencing_field: bool,
	) -> ParseResult<Option<String>> {
		if supports_referencing_field && self.eat(t!("FIELD")) {
			Ok(Some(self.parse_ident()?.into_string()))
		} else {
			Ok(None)
		}
	}

	pub(crate) async fn parse_record_id(&mut self, stk: &mut Stk) -> ParseResult<RecordIdLit> {
		let ident = self.parse_ident()?;
		self.parse_record_id_from_ident(stk, ident).await
	}

	pub(crate) async fn parse_record_id_from_ident(
		&mut self,
		stk: &mut Stk,
		ident: Strand,
	) -> ParseResult<RecordIdLit> {
		expected!(self, t!(":"));

		let id = stk.run(|ctx| self.parse_record_id_key(ctx)).await?;

		Ok(RecordIdLit {
			table: ident.into(),
			key: id,
		})
	}

	pub(crate) async fn parse_record_id_key(
		&mut self,
		stk: &mut Stk,
	) -> ParseResult<RecordIdKeyLit> {
		let Some(token) = self.peek_whitespace() else {
			bail!("Unexpected whitespace after record-id table", @self.peek().span)
		};
		match token.kind {
			t!("u'") | t!("u\"") => Ok(RecordIdKeyLit::Uuid(self.next_token_value()?)),
			t!("{") => {
				self.pop_peek();
				// object record id
				let object = self.parse_object(stk, token.span).await?;
				Ok(RecordIdKeyLit::Object(object))
			}
			t!("[") => {
				self.pop_peek();
				// array record id
				let array = self.parse_array(stk, token.span).await?;
				Ok(RecordIdKeyLit::Array(array))
			}
			t!("+") | t!("-") => {
				self.pop_peek();
				self.parse_numeric_record_id_key(token).await
			}
			TokenKind::Digits => self.parse_digits_record_id_key(token).await,
			t!("ULID") => {
				let token = self.pop_peek();
				if self.eat(t!("(")) {
					expected!(self, t!(")"));
					Ok(RecordIdKeyLit::Generate(RecordIdKeyGen::Ulid))
				} else {
					let slice = self.span_str(token.span);
					Ok(RecordIdKeyLit::String(slice.into()))
				}
			}
			t!("UUID") => {
				let token = self.pop_peek();
				if self.eat(t!("(")) {
					expected!(self, t!(")"));
					Ok(RecordIdKeyLit::Generate(RecordIdKeyGen::Uuid))
				} else {
					let slice = self.span_str(token.span);
					Ok(RecordIdKeyLit::String(slice.into()))
				}
			}
			t!("RAND") => {
				let token = self.pop_peek();
				if self.eat(t!("(")) {
					expected!(self, t!(")"));
					Ok(RecordIdKeyLit::Generate(RecordIdKeyGen::Rand))
				} else {
					let slice = self.span_str(token.span);
					Ok(RecordIdKeyLit::String(slice.into()))
				}
			}
			_ => {
				let ident: Strand = if self.settings.flexible_record_id {
					self.parse_flexible_ident()?.into()
				} else {
					self.parse_ident()?
				};
				Ok(RecordIdKeyLit::String(ident))
			}
		}
	}

	/// Parse a record-id key starting from a `Digits` token in either
	/// `flexible_record_id` mode (where ident-like suffixes are also strings)
	/// or strict mode (full numeric grammar via the compound lexer).
	///
	/// In flexible mode the parser must distinguish:
	///
	///   * `D . D <suffix>` → Float / Decimal (with `f` / `dec` suffix)
	///   * `D . D`          → Float
	///   * `D <suffix>`     → Float / Decimal
	///   * `D <ident>`      → flexible-ident string (e.g. `1abc`, `1ns`, `1e10`)
	///   * `D`              → Integer (with string fallback for overflows)
	///
	/// `f` and `dec` are recognised here so that the canonical `to_sql()`
	/// output for non-integer record-id keys (e.g. `1.5f`, `3dec`) round-trips
	/// through statement-context parsing — matching the value-context
	/// equivalent in [`Parser::parse_flexible_digit_record_id_key_value`].
	/// Exponent forms (`1.5e10`) remain flexible-ident strings: `Display::fmt`
	/// for `f64` never emits exponent notation for finite floats, so the
	/// round-trip path doesn't need them.
	///
	/// This function must not call any other parser methods that advance
	/// the lexer's `last_offset` before invoking
	/// [`Self::parse_numeric_record_id_key`], because that helper's
	/// [`compound::number_kind`] call asserts the start token is the last
	/// consumed token.
	async fn parse_digits_record_id_key(&mut self, token: Token) -> ParseResult<RecordIdKeyLit> {
		if self.settings.flexible_record_id {
			// In flexible mode we cannot use [`compound::number_kind`] directly
			// because the look-ahead needed to distinguish `1abc` (flexible
			// string ID) from `1.5` (float literal) advances the lexer's
			// `last_offset` past the next token, which breaks `lex_compound`'s
			// "start was the last consumed token" assertion. Instead we peek
			// manually and stitch the relevant token spans together — mirroring
			// `parse_flexible_digit_record_id_key_value` in `syn/parser/value.rs`.
			let dot = self.peek_whitespace1().filter(|t| t.kind == t!("."));
			let after_dot = if dot.is_some() {
				self.peek_whitespace2().filter(|t| t.kind == TokenKind::Digits)
			} else {
				None
			};

			if let Some(after_dot_tok) = after_dot {
				// `D . D` — pop the three tokens before looking at any suffix
				// so we stay within the token buffer's capacity.
				let mantissa_span = token.span.covers(after_dot_tok.span);
				self.pop_peek();
				self.pop_peek();
				self.pop_peek();

				let suffix = self.peek_whitespace().and_then(|t| match t.kind {
					TokenKind::Identifier => match self.span_str(t.span) {
						"f" => Some((t, NumberKind::Float)),
						"dec" => Some((t, NumberKind::Decimal)),
						_ => None,
					},
					_ => None,
				});

				return if let Some((suf, kind)) = suffix {
					let span = token.span.covers(suf.span);
					let s = self.span_str(span);
					let key = decode_suffixed_numeric_record_id_key_lit(s, &kind, span)?;
					self.pop_peek();
					Ok(key)
				} else {
					let s = self.span_str(mantissa_span);
					let f: f64 = s.parse().map_err(|e| {
						crate::syn::error::syntax_error!(
							"Failed to parse float record-id key: {e}",
							@mantissa_span
						)
					})?;
					if !f.is_finite() {
						bail!("NaN and ±Infinity are not valid record-id keys", @mantissa_span);
					}
					Ok(RecordIdKeyLit::Number(Number::Float(f)))
				};
			}

			// No `D . D` pattern. Check whether the bare digits carry a numeric
			// suffix (`1f`, `3dec`) — otherwise fall through to flexible-ident
			// or plain-integer handling.
			let suffix = self.peek_whitespace1().and_then(|t| match t.kind {
				TokenKind::Identifier => match self.span_str(t.span) {
					"f" => Some((t, NumberKind::Float)),
					"dec" => Some((t, NumberKind::Decimal)),
					_ => None,
				},
				_ => None,
			});

			if let Some((suf, kind)) = suffix {
				let span = token.span.covers(suf.span);
				let s = self.span_str(span);
				let key = decode_suffixed_numeric_record_id_key_lit(s, &kind, span)?;
				self.pop_peek();
				self.pop_peek();
				return Ok(key);
			}

			if let Some(next) = self.peek_whitespace1()
				&& (Self::kind_is_identifier(next.kind)
					|| next.kind == TokenKind::NaN
					|| next.kind == TokenKind::Infinity)
			{
				let ident = self.parse_flexible_ident()?;
				return Ok(RecordIdKeyLit::String(ident.into()));
			}

			self.pop_peek();
			let digits_str = self.span_str(token.span);
			return Ok(match digits_str.parse::<i64>() {
				Ok(n) => RecordIdKeyLit::Number(Number::Int(n)),
				Err(_) => RecordIdKeyLit::String(digits_str.into()),
			});
		}

		// Strict mode: full integer / float / decimal support via the compound lexer.
		self.pop_peek();
		self.parse_numeric_record_id_key(token).await
	}

	/// Parse a numeric record-id key, accepting integers, floats, and
	/// decimals. The lexer's [`compound::number_kind`] consumes the full
	/// numeric literal (mantissa, exponent, `f` / `dec` suffix); the parser
	/// then dispatches by [`NumberKind`]. NaN and ±∞ are rejected as not
	/// valid record-id keys. Integers that don't fit in `i64` fall back to
	/// a string record-id key (legacy behaviour).
	async fn parse_numeric_record_id_key(&mut self, start: Token) -> ParseResult<RecordIdKeyLit> {
		let token = self.lex_compound(start, compound::number_kind)?;
		let span = token.span;
		let number_str = compound::prepare_number_str(self.span_str(span));
		match token.value {
			NumberKind::Integer => {
				// Fallback to string for integers that don't fit in i64 — preserves
				// the legacy parser behaviour where huge digits are treated as a
				// string record ID (e.g. ULID-like keys that happen to be all digits).
				match number_str.parse::<i64>() {
					Ok(i) => Ok(RecordIdKeyLit::Number(Number::Int(i))),
					Err(_) => Ok(RecordIdKeyLit::String(number_str.into_owned().into())),
				}
			}
			NumberKind::Float => {
				let bytes = number_str.as_bytes();
				let f = if bytes[0] == b'N' {
					f64::NAN
				} else if bytes[0] == b'-' && bytes.get(1) == Some(&b'I') {
					f64::NEG_INFINITY
				} else if bytes[0] == b'I' || (bytes[0] == b'+' && bytes.get(1) == Some(&b'I')) {
					f64::INFINITY
				} else {
					number_str.trim_end_matches('f').parse::<f64>().map_err(
						|e| crate::syn::error::syntax_error!("Failed to parse number: {e}", @span),
					)?
				};
				if !f.is_finite() {
					bail!("NaN and ±Infinity are not valid record-id keys", @span)
				}
				Ok(RecordIdKeyLit::Number(Number::Float(f)))
			}
			NumberKind::Decimal => {
				let stripped = number_str.trim_end_matches("dec");
				let d = if stripped.contains(['e', 'E']) {
					rust_decimal::Decimal::from_scientific(stripped).map_err(
						|e| crate::syn::error::syntax_error!("Failed to parse decimal: {e}", @span),
					)?
				} else {
					rust_decimal::Decimal::from_str_normalized(stripped).map_err(
						|e| crate::syn::error::syntax_error!("Failed to parse decimal: {e}", @span),
					)?
				};
				Ok(RecordIdKeyLit::Number(Number::Decimal(d)))
			}
		}
	}
}

/// Decode a suffixed numeric record-id key literal (e.g. `"1.5f"` for Float,
/// `"3dec"` for Decimal). The caller is responsible for having matched the
/// suffix in the token stream; this helper strips the suffix and parses the
/// numeric mantissa. NaN / ±∞ are rejected. Mirrors
/// `decode_suffixed_numeric_record_id_key` in `syn/parser/value.rs`, just
/// returning the SQL/expression `RecordIdKeyLit` instead of the public
/// `PublicRecordIdKey`.
fn decode_suffixed_numeric_record_id_key_lit(
	s: &str,
	kind: &NumberKind,
	span: Span,
) -> ParseResult<RecordIdKeyLit> {
	match kind {
		NumberKind::Float => {
			let trimmed = s.trim_end_matches('f');
			let f: f64 = trimmed.parse().map_err(|e| {
				crate::syn::error::syntax_error!(
					"Failed to parse float record-id key: {e}",
					@span
				)
			})?;
			if !f.is_finite() {
				bail!("NaN and ±Infinity are not valid record-id keys", @span);
			}
			Ok(RecordIdKeyLit::Number(Number::Float(f)))
		}
		NumberKind::Decimal => {
			let trimmed = s.trim_end_matches("dec");
			let d = rust_decimal::Decimal::from_str_normalized(trimmed).map_err(|e| {
				crate::syn::error::syntax_error!(
					"Failed to parse decimal record-id key: {e}",
					@span
				)
			})?;
			Ok(RecordIdKeyLit::Number(Number::Decimal(d)))
		}
		NumberKind::Integer => {
			unreachable!("integer kind is never matched with a `f` / `dec` suffix")
		}
	}
}

#[cfg(test)]
mod tests {
	use reblessive::Stack;

	use super::*;
	use crate::sql::{Expr, Literal};
	use crate::syn::parser::ParserSettings;
	use crate::{sql, syn};

	fn record(i: &str) -> ParseResult<RecordIdLit> {
		let mut parser = Parser::new(i.as_bytes());
		let mut stack = Stack::new();
		stack.enter(|ctx| async move { parser.parse_record_id(ctx).await }).finish()
	}

	fn record_strict(i: &str) -> ParseResult<RecordIdLit> {
		// `flexible_record_id = false` so the parser commits to numeric
		// parsing for digit-prefixed keys and we can exercise the
		// float/decimal literal paths.
		let mut parser = Parser::new_with_settings(
			i.as_bytes(),
			ParserSettings {
				flexible_record_id: false,
				..ParserSettings::default()
			},
		);
		let mut stack = Stack::new();
		stack.enter(|ctx| async move { parser.parse_record_id(ctx).await }).finish()
	}

	#[test]
	fn record_normal() {
		let sql = "test:id";
		let res = record(sql);
		let out = res.unwrap();
		assert_eq!("test:id", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::String("id".into()),
			}
		);
	}

	#[test]
	fn record_integer() {
		let sql = "test:001";
		let res = record(sql);
		let out = res.unwrap();
		assert_eq!("test:1", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Int(1)),
			}
		);
	}

	#[test]
	fn record_integer_min() {
		let sql = format!("test:{}", i64::MIN);
		let res = record(&sql);
		let out = res.unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Int(i64::MIN)),
			}
		);
	}

	#[test]
	fn record_integer_max() {
		let sql = format!("test:{}", i64::MAX);
		let res = record(&sql);
		let out = res.unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Int(i64::MAX)),
			}
		);
	}

	#[test]
	fn record_float_key() {
		let out = record_strict("test:1.5").unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Float(1.5)),
			}
		);
	}

	#[test]
	fn record_float_with_f_suffix() {
		let out = record_strict("test:1.5f").unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Float(1.5)),
			}
		);
	}

	#[test]
	fn record_decimal_key() {
		let out = record_strict("test:1.5dec").unwrap();
		let RecordIdKeyLit::Number(Number::Decimal(d)) = out.key else {
			panic!("expected Decimal key, got: {:?}", out.key);
		};
		use crate::val::DecimalExt;
		assert_eq!(d, rust_decimal::Decimal::from_str_normalized("1.5").unwrap());
	}

	#[test]
	fn record_negative_float_key() {
		// `-` prefix uses the compound numeric path regardless of flexible mode.
		let out = record("test:-2.25").unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Float(-2.25)),
			}
		);
	}

	#[test]
	fn record_nan_inf_rejected() {
		// Strict mode: an overflowing float literal like `1e500` becomes
		// `f64::INFINITY` at parse time. The parser must reject it rather
		// than silently produce an infinite-valued record id.
		let res = record_strict("test:1e500");
		assert!(res.is_err(), "expected rejection for 1e500, got: {res:?}");
	}

	#[test]
	fn record_integer_more_then_max() {
		let max_str = format!("{}", (i64::MAX as u64) + 1);
		let sql = format!("test:{}", max_str);
		let res = record(&sql);
		let out = res.unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::String(max_str.into()),
			}
		);
	}

	#[test]
	fn record_integer_more_then_min() {
		let min_str = format!("-{}", (i64::MAX as u64) + 2);
		let sql = format!("test:{}", min_str);
		let res = record(&sql);
		let out = res.unwrap();
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::String(min_str.into()),
			}
		);
	}

	#[test]
	fn record_string() {
		let sql = "r'test:001'";
		let res = syn::expr(sql).unwrap();
		let sql::Expr::Literal(sql::Literal::RecordId(out)) = res else {
			panic!()
		};
		assert_eq!("test:1", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Int(1)),
			}
		);

		let sql = "r'test:001'";
		let res = syn::expr(sql).unwrap();
		let sql::Expr::Literal(sql::Literal::RecordId(out)) = res else {
			panic!()
		};
		assert_eq!("test:1", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Number(Number::Int(1)),
			}
		);
	}

	#[test]
	fn record_quoted_backtick() {
		let sql = "`test`:`id`";
		let res = record(sql);
		let out = res.unwrap();
		assert_eq!("test:id", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::String("id".into()),
			}
		);
	}

	#[test]
	fn record_quoted_brackets() {
		let sql = "⟨test⟩:⟨id⟩";
		let res = record(sql);
		let out = res.unwrap();
		assert_eq!("test:id", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::String("id".into()),
			}
		);
	}

	#[test]
	fn record_object() {
		let sql = "test:{ location: 'GBR', year: 2022 }";
		let res = record(sql);
		let out = res.unwrap();
		assert_eq!("test:{ location: 'GBR', year: 2022 }", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Object(vec![
					sql::literal::ObjectEntry {
						key: "location".into(),
						value: sql::Expr::Literal(sql::Literal::String(Strand::new_static("GBR")))
					},
					sql::literal::ObjectEntry {
						key: "year".into(),
						value: sql::Expr::Literal(sql::Literal::Integer(2022)),
					},
				])
			}
		);
	}

	#[test]
	fn record_array() {
		let sql = "test:['GBR', 2022]";
		let res = record(sql);
		let out = res.unwrap();
		assert_eq!("test:['GBR', 2022]", out.to_sql());
		assert_eq!(
			out,
			RecordIdLit {
				table: "test".into(),
				key: RecordIdKeyLit::Array(vec![
					sql::Expr::Literal(sql::Literal::String(Strand::new_static("GBR"))),
					sql::Expr::Literal(sql::Literal::Integer(2022)),
				])
			}
		);
	}

	#[test]
	fn weird_things() {
		use crate::sql;

		fn assert_ident_parses_correctly(ident: &str) {
			let thing = format!("t:{}", ident);
			let mut parser = Parser::new_with_settings(
				thing.as_bytes(),
				ParserSettings {
					flexible_record_id: true,
					..Default::default()
				},
			);
			let mut stack = Stack::new();
			let r = stack
				.enter(|ctx| async move { parser.parse_record_id(ctx).await })
				.finish()
				.unwrap_or_else(|_| panic!("failed on {}", ident))
				.key;
			assert_eq!(r, RecordIdKeyLit::String(ident.to_string().into()),);

			let mut parser = Parser::new(thing.as_bytes());
			let r = stack
				.enter(|ctx| async move { parser.parse_expr_inherit(ctx).await })
				.finish()
				.unwrap_or_else(|_| panic!("failed on {}", ident));

			assert_eq!(
				r,
				Expr::Literal(Literal::RecordId(sql::RecordIdLit {
					table: "t".into(),
					key: RecordIdKeyLit::String(ident.to_string().into())
				}))
			)
		}

		assert_ident_parses_correctly("123abc");
		assert_ident_parses_correctly("123d");
		assert_ident_parses_correctly("123de");
		// `123dec` and `123f` are NOT idents — they're the suffixed numeric
		// record-id forms `Number::Decimal` / `Number::Float` `ToSql` emits.
		// `1e23dec` / `1e23f` stay as flexible-ident strings because the leading
		// `1` + identifier `e23dec` / `e23f` doesn't match the `D <suffix>` shape
		// (the suffix is consumed as part of the trailing identifier).
		assert_ident_parses_correctly("1e23dec");
		assert_ident_parses_correctly("1e23f");
		assert_ident_parses_correctly("1ns");
		assert_ident_parses_correctly("1ns1");
		assert_ident_parses_correctly("1ns1h");
		assert_ident_parses_correctly("000e8");
		assert_ident_parses_correctly("000e8bla");

		assert_ident_parses_correctly("y123");
		assert_ident_parses_correctly("w123");
		assert_ident_parses_correctly("d123");
		assert_ident_parses_correctly("h123");
		assert_ident_parses_correctly("m123");
		assert_ident_parses_correctly("s123");
		assert_ident_parses_correctly("ms123");
		assert_ident_parses_correctly("us123");
		assert_ident_parses_correctly("ns123");
		assert_ident_parses_correctly("dec123");
		assert_ident_parses_correctly("f123");
		assert_ident_parses_correctly("e123");

		assert_ident_parses_correctly("ulid");
		assert_ident_parses_correctly("uuid");
		assert_ident_parses_correctly("rand");
	}

	// ---- flexible-mode suffixed numeric record-id keys (comment #25 / 44ba5a536 mirror) ----
	//
	// `Number::Float::to_sql()` emits `1.5f` (and `1f` for integer-valued floats);
	// `Number::Decimal::to_sql()` emits `1.5dec` / `3dec`. The flexible-mode
	// statement-context parser must accept these so a record-id key serialised
	// via `to_sql()` round-trips back through `parse_record_id`.

	fn record_flexible(i: &str) -> ParseResult<RecordIdLit> {
		let mut parser = Parser::new_with_settings(
			i.as_bytes(),
			ParserSettings {
				flexible_record_id: true,
				..ParserSettings::default()
			},
		);
		let mut stack = Stack::new();
		stack.enter(|ctx| async move { parser.parse_record_id(ctx).await }).finish()
	}

	#[test]
	fn flexible_float_with_dot_and_f_suffix() {
		let out = record_flexible("a:1.5f").unwrap();
		assert_eq!(out.table.as_str(), "a");
		assert_eq!(out.key, RecordIdKeyLit::Number(Number::Float(1.5)));
	}

	#[test]
	fn flexible_float_bare_integer_with_f_suffix() {
		// `to_sql` for `Float(1.0)` emits `1f` — flexible mode must accept it.
		let out = record_flexible("a:1f").unwrap();
		assert_eq!(out.key, RecordIdKeyLit::Number(Number::Float(1.0)));
	}

	#[test]
	fn flexible_decimal_with_dec_suffix() {
		let out = record_flexible("a:3dec").unwrap();
		let RecordIdKeyLit::Number(Number::Decimal(d)) = out.key else {
			panic!("expected Decimal key, got: {:?}", out.key);
		};
		assert_eq!(d, rust_decimal::Decimal::from(3));
	}

	#[test]
	fn flexible_decimal_with_dot_and_dec_suffix() {
		// `0.1` isn't bit-exact in f64, so it stays in the Decimal slot.
		let out = record_flexible("a:0.1dec").unwrap();
		let RecordIdKeyLit::Number(Number::Decimal(d)) = out.key else {
			panic!("expected Decimal key, got: {:?}", out.key);
		};
		assert_eq!(d, rust_decimal::Decimal::from_str_normalized("0.1").unwrap());
	}

	#[test]
	fn flexible_negative_float_with_f_suffix() {
		// `-` prefix routes through the strict-mode `parse_numeric_record_id_key`
		// path; it already handled `f`/`dec` suffixes — this test just guards
		// against regressions while the flexible-mode path changes.
		let out = record_flexible("a:-1.5f").unwrap();
		assert_eq!(out.key, RecordIdKeyLit::Number(Number::Float(-1.5)));
	}

	#[test]
	fn flexible_negative_decimal_with_dec_suffix() {
		let out = record_flexible("a:-3dec").unwrap();
		let RecordIdKeyLit::Number(Number::Decimal(d)) = out.key else {
			panic!("expected Decimal key, got: {:?}", out.key);
		};
		assert_eq!(d, rust_decimal::Decimal::from(-3));
	}

	#[test]
	fn flexible_ident_only_suffixes_stay_strings() {
		// `1ns` is a Duration suffix in the flexible-ident grammar — not a
		// numeric record-id suffix. The `D <ident>` fall-through preserves it.
		assert_eq!(record_flexible("a:1ns").unwrap().key, RecordIdKeyLit::String("1ns".into()));
		// `1abc` is a plain flexible-ident string.
		assert_eq!(record_flexible("a:1abc").unwrap().key, RecordIdKeyLit::String("1abc".into()));
		// `1e10` is an exponent form; flexible mode keeps it as a string because
		// `Display::fmt` for `f64` never emits exponent notation for finite
		// floats, so the round-trip path doesn't need it.
		assert_eq!(record_flexible("a:1e10").unwrap().key, RecordIdKeyLit::String("1e10".into()));
	}

	#[test]
	fn flexible_full_value_round_trip_via_to_sql() {
		// Build the same record-id values the formatter emits, then re-parse.
		for (input, expected) in [
			("a:1.5f", RecordIdKeyLit::Number(Number::Float(1.5))),
			("a:1f", RecordIdKeyLit::Number(Number::Float(1.0))),
			("a:3dec", RecordIdKeyLit::Number(Number::Decimal(rust_decimal::Decimal::from(3)))),
			(
				"a:0.1dec",
				RecordIdKeyLit::Number(Number::Decimal(
					rust_decimal::Decimal::from_str_normalized("0.1").unwrap(),
				)),
			),
		] {
			let out = record_flexible(input).unwrap_or_else(|e| panic!("{input}: {e:?}"));
			assert_eq!(out.key, expected, "input = {input}");
		}
	}
}
