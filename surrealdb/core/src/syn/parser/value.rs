use std::collections::BTreeMap;
use std::ops::Bound;

use reblessive::Stk;

use super::{ParseResult, Parser};
use crate::syn::error::bail;
use crate::syn::lexer::Lexer;
use crate::syn::lexer::compound::{self, NumberKind, Numeric};
use crate::syn::parser::mac::{expected, expected_whitespace};
use crate::syn::parser::{enter_object_recursion, unexpected};
use crate::syn::token::{Span, Token, TokenKind, t};
use crate::types::{
	PublicArray, PublicDuration, PublicFile, PublicGeometry, PublicNumber, PublicObject,
	PublicRange, PublicRecordId, PublicRecordIdKey, PublicSet, PublicTable, PublicUuid,
	PublicValue,
};
use crate::val::DecimalExt;

trait ValueParseFunc {
	async fn parse(parser: &mut Parser<'_>, stk: &mut Stk) -> ParseResult<PublicValue>;
}

struct SurrealQL;
struct Json;

impl ValueParseFunc for SurrealQL {
	async fn parse(parser: &mut Parser<'_>, stk: &mut Stk) -> ParseResult<PublicValue> {
		parser.parse_value(stk).await
	}
}

impl ValueParseFunc for Json {
	async fn parse(parser: &mut Parser<'_>, stk: &mut Stk) -> ParseResult<PublicValue> {
		parser.parse_json(stk).await
	}
}

impl Parser<'_> {
	/// Parse a complete value which cannot contain non-literal expressions.
	pub async fn parse_value(&mut self, stk: &mut Stk) -> ParseResult<PublicValue> {
		let token = self.peek();
		let res = match token.kind {
			t!("NONE") => {
				self.pop_peek();
				PublicValue::None
			}
			t!("NULL") => {
				self.pop_peek();
				PublicValue::Null
			}
			TokenKind::NaN => {
				self.pop_peek();
				PublicValue::Number(PublicNumber::Float(f64::NAN))
			}
			TokenKind::Infinity => {
				self.pop_peek();
				PublicValue::Number(PublicNumber::Float(f64::INFINITY))
			}
			t!("true") => {
				self.pop_peek();
				PublicValue::Bool(true)
			}
			t!("false") => {
				self.pop_peek();
				PublicValue::Bool(false)
			}
			t!("{") => {
				let open = self.pop_peek().span;

				if self.eat(t!("}")) {
					return Ok(PublicValue::Object(PublicObject::new()));
				}

				// First, check if it's an empty set. `{,}` is an empty set.
				if self.eat(t!(",")) {
					self.expect_closing_delimiter(t!("}"), open)?;
					return Ok(PublicValue::Set(PublicSet::new()));
				}

				enter_object_recursion!(this = self => {
					if let t!("\"")
					| t!("'")
					| TokenKind::Identifier
					| TokenKind::Digits
					| TokenKind::Keyword(_)
					| TokenKind::Language(_)
					| TokenKind::Algorithm(_)
					| TokenKind::Distance(_)
					| TokenKind::VectorType(_) = this.peek().kind
						&& let Some(x) = this
							.speculate(stk, async |stk, this| {
								let key = this.parse_object_key()?;
								if !this.eat(t!(":")) {
									return Ok(None);
								}
								let value = stk.run(|stk| this.parse_value(stk)).await?;
								let mut res = BTreeMap::new();
								res.insert(key, value);

								if this.eat(t!(",")) {
									this.parse_value_object::<SurrealQL>(stk, open, res).await.map(Some)
								} else {
									this.expect_closing_delimiter(t!("}"), open)?;
									Ok(Some(PublicObject::from(res)))
								}
							})
							.await?
					{
						if let Some(x) = PublicGeometry::try_from_object(&x) {
							return Ok(PublicValue::Geometry(x));
						} else {
							return Ok(PublicValue::Object(x));
						}
					}

					// It must be a set: `{1, 2, 3}` or `{value}`
					let set = this.parse_value_set::<SurrealQL>(stk, token.span).await?;
					PublicValue::Set(set)
				})
			}
			t!("[") => {
				self.pop_peek();
				enter_object_recursion!(this = self => {
					this.parse_value_array::<SurrealQL>(stk, token.span)
						.await
						.map(PublicValue::Array)?
				})
			}
			t!("\"") | t!("'") => {
				let strand = self.parse_string_lit()?;
				if self.settings.legacy_strands {
					self.reparse_json_legacy_strand(stk, strand).await
				} else {
					PublicValue::String(strand)
				}
			}
			t!("d\"") | t!("d'") => PublicValue::Datetime(self.next_token_value()?),
			t!("u\"") | t!("u'") => PublicValue::Uuid(self.next_token_value()?),
			t!("b\"") | t!("b'") => PublicValue::Bytes(self.next_token_value()?),
			t!("f\"") | t!("f'") => {
				if !self.settings.files_enabled {
					unexpected!(self, token, "the experimental files feature to be enabled");
				}

				let file = self.next_token_value::<PublicFile>()?;
				PublicValue::File(file)
			}
			t!("/") => {
				let regex = self.next_token_value()?;
				PublicValue::Regex(regex)
			}
			t!("(") => {
				let open = self.pop_peek().span;
				let peek = self.peek();
				match peek.kind {
					t!("+") | t!("-") | TokenKind::Digits => {
						let before = peek.span;
						let number = self.next_token_value::<Numeric>()?;
						let number_span = before.covers(self.last_span());
						if self.peek().kind == t!(",") {
							let x = match number {
								Numeric::Duration(_) | Numeric::Decimal(_) => {
									bail!("Unexpected token, expected a non-decimal, non-NaN, number",
										@number_span => "Coordinate numbers can't be NaN or a decimal");
								}
								Numeric::Float(x) if x.is_nan() => {
									bail!("Unexpected token, expected a non-decimal, non-NaN, number",
										@number_span => "Coordinate numbers can't be NaN or a decimal");
								}
								Numeric::Float(x) => x,
								Numeric::Integer(x) => x.into_int(number_span)? as f64,
							};

							self.pop_peek();

							let y = self.next_token_value::<f64>()?;
							self.expect_closing_delimiter(t!(")"), open)?;
							PublicValue::Geometry(PublicGeometry::Point(geo::Point::new(x, y)))
						} else {
							self.expect_closing_delimiter(t!(")"), open)?;

							match number {
								Numeric::Float(x) => PublicValue::Number(PublicNumber::Float(x)),
								Numeric::Integer(x) => {
									PublicValue::Number(PublicNumber::Int(x.into_int(number_span)?))
								}
								Numeric::Decimal(x) => {
									PublicValue::Number(PublicNumber::Decimal(x))
								}
								Numeric::Duration(duration) => {
									PublicValue::Duration(PublicDuration::from(duration))
								}
							}
						}
					}
					_ => {
						enter_object_recursion!(this = self => {
							let res = stk.run(|stk| this.parse_value(stk)).await?;
							this.expect_closing_delimiter(t!(")"), open)?;
							res
						})
					}
				}
			}
			t!("..") => {
				self.pop_peek();
				match self.peek_whitespace().map(|x| x.kind) {
					Some(t!("=")) => {
						self.pop_peek();
						enter_object_recursion!(this = self => {
							let v = stk.run(|stk| this.parse_value(stk)).await?;
							PublicValue::Range(Box::new(PublicRange {
								start: Bound::Unbounded,
								end: Bound::Included(v),
							}))
						})
					}
					Some(x) if Self::kind_starts_expression(x) => {
						enter_object_recursion!(this = self => {
							let v = stk.run(|stk| this.parse_value(stk)).await?;
							PublicValue::Range(Box::new(PublicRange {
								start: Bound::Unbounded,
								end: Bound::Excluded(v),
							}))
						})
					}
					_ => PublicValue::Range(Box::new(PublicRange {
						start: Bound::Unbounded,
						end: Bound::Unbounded,
					})),
				}
			}
			t!("-") | t!("+") | TokenKind::Digits => {
				self.pop_peek();
				let compound = self.lex_compound(token, compound::numeric)?;
				match compound.value {
					Numeric::Duration(x) => PublicValue::Duration(PublicDuration::from(x)),
					Numeric::Integer(x) => {
						PublicValue::Number(PublicNumber::Int(x.into_int(compound.span)?))
					}
					Numeric::Float(x) => PublicValue::Number(PublicNumber::Float(x)),
					Numeric::Decimal(x) => PublicValue::Number(PublicNumber::Decimal(x)),
				}
			}
			_ => self
				.parse_value_record_id_inner::<SurrealQL>(stk)
				.await
				.map(PublicValue::RecordId)?,
		};

		match self.peek_whitespace().map(|x| x.kind) {
			Some(t!(">")) => {
				self.pop_peek();
				expected_whitespace!(self, t!(".."));
				match self.peek_whitespace().map(|x| x.kind) {
					Some(t!("=")) => {
						self.pop_peek();
						enter_object_recursion!(this = self => {
							let v = stk.run(|stk| this.parse_value(stk)).await?;
							Ok(PublicValue::Range(Box::new(PublicRange {
								start: Bound::Excluded(res),
								end: Bound::Included(v),
							})))
						})
					}
					Some(x) if Self::kind_starts_expression(x) => {
						enter_object_recursion!(this = self => {
							let v = stk.run(|stk| this.parse_value(stk)).await?;
							Ok(PublicValue::Range(Box::new(PublicRange {
								start: Bound::Excluded(res),
								end: Bound::Excluded(v),
							})))
						})
					}
					_ => Ok(PublicValue::Range(Box::new(PublicRange {
						start: Bound::Excluded(res),
						end: Bound::Unbounded,
					}))),
				}
			}
			Some(t!("..")) => {
				self.pop_peek();

				match self.peek_whitespace().map(|x| x.kind) {
					Some(t!("=")) => {
						self.pop_peek();
						enter_object_recursion!(this = self => {
							let v = stk.run(|stk| this.parse_value(stk)).await?;
							Ok(PublicValue::Range(Box::new(PublicRange {
								start: Bound::Included(res),
								end: Bound::Included(v),
							})))
						})
					}
					Some(x) if Self::kind_starts_expression(x) => {
						enter_object_recursion!(this = self => {
							let v = stk.run(|stk| this.parse_value(stk)).await?;
							Ok(PublicValue::Range(Box::new(PublicRange {
								start: Bound::Included(res),
								end: Bound::Excluded(v),
							})))
						})
					}
					_ => Ok(PublicValue::Range(Box::new(PublicRange {
						start: Bound::Included(res),
						end: Bound::Unbounded,
					}))),
				}
			}
			_ => Ok(res),
		}
	}

	pub async fn parse_json(&mut self, stk: &mut Stk) -> ParseResult<PublicValue> {
		let token = self.peek();
		match token.kind {
			t!("NULL") => {
				self.pop_peek();
				Ok(PublicValue::Null)
			}
			t!("true") => {
				self.pop_peek();
				Ok(PublicValue::Bool(true))
			}
			t!("false") => {
				self.pop_peek();
				Ok(PublicValue::Bool(false))
			}
			t!("{") => {
				let open = self.pop_peek().span;

				if self.eat(t!("}")) {
					return Ok(PublicValue::Object(PublicObject::new()));
				}

				enter_object_recursion!(this = self => {
					this.parse_value_object::<Json>(stk, open, BTreeMap::new())
						.await
						.map(PublicValue::Object)
				})
			}
			t!("[") => {
				self.pop_peek();
				enter_object_recursion!(this = self => {
					this.parse_value_array::<Json>(stk, token.span).await.map(PublicValue::Array)
				})
			}
			t!("\"") | t!("'") => {
				let strand = self.parse_string_lit()?;
				if self.settings.legacy_strands {
					Ok(self.reparse_json_legacy_strand(stk, strand).await)
				} else {
					Ok(PublicValue::String(strand))
				}
			}
			t!("-") | t!("+") | TokenKind::Digits => {
				self.pop_peek();
				let compound = self.lex_compound(token, compound::numeric)?;
				match compound.value {
					Numeric::Duration(x) => Ok(PublicValue::Duration(PublicDuration::from(x))),
					Numeric::Integer(x) => {
						Ok(PublicValue::Number(PublicNumber::Int(x.into_int(compound.span)?)))
					}
					Numeric::Float(x) => Ok(PublicValue::Number(PublicNumber::Float(x))),
					Numeric::Decimal(x) => Ok(PublicValue::Number(PublicNumber::Decimal(x))),
				}
			}
			_ => {
				match self.parse_value_record_id_inner::<Json>(stk).await.map(PublicValue::RecordId)
				{
					Ok(x) => Ok(x),
					Err(err) => {
						tracing::debug!("Error parsing record id: {err:?}");
						self.parse_value_table().await.map(PublicValue::Table)
					}
				}
			}
		}
	}

	async fn reparse_json_legacy_strand(&mut self, stk: &mut Stk, strand: String) -> PublicValue {
		if let Ok(x) = Parser::new(strand.as_bytes()).parse_value_record_id(stk).await {
			return PublicValue::RecordId(x);
		}

		if let Ok(x) = Lexer::lex_datetime(&strand) {
			return PublicValue::Datetime(x);
		}

		if let Ok(x) = Lexer::lex_uuid(&strand) {
			return PublicValue::Uuid(x);
		}

		PublicValue::String(strand)
	}

	async fn parse_value_object<VP>(
		&mut self,
		stk: &mut Stk,
		start: Span,
		mut obj: BTreeMap<String, PublicValue>,
	) -> ParseResult<PublicObject>
	where
		VP: ValueParseFunc,
	{
		loop {
			if self.eat(t!("}")) {
				return Ok(PublicObject::from(obj));
			}
			let key = self.parse_object_key()?;
			expected!(self, t!(":"));
			let value = stk.run(|ctx| VP::parse(self, ctx)).await?;
			obj.insert(key, value);

			if !self.eat(t!(",")) {
				self.expect_closing_delimiter(t!("}"), start)?;
				return Ok(PublicObject::from(obj));
			}
		}
	}

	async fn parse_value_set<VP>(&mut self, stk: &mut Stk, start: Span) -> ParseResult<PublicSet>
	where
		VP: ValueParseFunc,
	{
		let mut set = PublicSet::new();
		loop {
			if self.eat(t!("}")) {
				return Ok(set);
			}

			let value = stk.run(|stk| VP::parse(self, stk)).await?;
			set.insert(value);

			if !self.eat(t!(",")) {
				if set.len() <= 1 {
					// Single-element object: `{value}`
					// We could parse this in SQON, but in SurrealQL this is a block statement.
					// So we instead throw an error and require the user to add a trailing
					// comma for a set.
					unexpected!(
						self,
						self.peek(),
						"`,`",
						=> "Sets with a single value must have at least a single comma"
					);
				}

				self.expect_closing_delimiter(t!("}"), start)?;

				return Ok(set);
			}
		}
	}

	async fn parse_value_array<VP>(
		&mut self,
		stk: &mut Stk,
		start: Span,
	) -> ParseResult<PublicArray>
	where
		VP: ValueParseFunc,
	{
		let mut array = Vec::new();
		loop {
			if self.eat(t!("]")) {
				return Ok(PublicArray::from(array));
			}
			let value = stk.run(|stk| VP::parse(self, stk)).await?;
			array.push(value);

			if !self.eat(t!(",")) {
				self.expect_closing_delimiter(t!("]"), start)?;
				return Ok(PublicArray::from(array));
			}
		}
	}

	async fn parse_value_table(&mut self) -> ParseResult<PublicTable> {
		let table = self.parse_ident()?.into_string();
		Ok(PublicTable::new(table))
	}

	pub async fn parse_value_record_id(&mut self, stk: &mut Stk) -> ParseResult<PublicRecordId> {
		self.parse_value_record_id_inner::<SurrealQL>(stk).await
	}

	async fn parse_value_record_id_inner<VP>(
		&mut self,
		stk: &mut Stk,
	) -> ParseResult<PublicRecordId>
	where
		VP: ValueParseFunc,
	{
		let table = self.parse_ident()?.into_string();
		expected!(self, t!(":"));
		let peek = self.peek();
		let key = match peek.kind {
			t!("u'") | t!("u\"") => PublicRecordIdKey::Uuid(self.next_token_value::<PublicUuid>()?),
			t!("{") => {
				let peek = self.pop_peek();
				enter_object_recursion!(this = self => {
					PublicRecordIdKey::Object(
						this.parse_value_object::<VP>(stk, peek.span, BTreeMap::new()).await?,
					)
				})
			}
			t!("[") => {
				let peek = self.pop_peek();
				enter_object_recursion!(this = self => {
					PublicRecordIdKey::Array(this.parse_value_array::<VP>(stk, peek.span).await?)
				})
			}
			t!("+") | t!("-") => {
				self.pop_peek();
				self.parse_value_numeric_record_id_key(peek)?
			}
			TokenKind::Digits => {
				if self.settings.flexible_record_id {
					self.parse_flexible_digit_record_id_key_value(peek)?
				} else {
					self.pop_peek();
					self.parse_value_numeric_record_id_key(peek)?
				}
			}
			_ => {
				let ident = if self.settings.flexible_record_id {
					self.parse_flexible_ident()?
				} else {
					self.parse_ident()?.into_string()
				};
				PublicRecordIdKey::String(ident)
			}
		};

		Ok(PublicRecordId::new(table, key))
	}

	/// Parse a numeric record-id key starting from a sign (`+` / `-`) or
	/// `Digits` token. Uses the compound number lexer, so floats (`1.5`,
	/// `1.5f`), decimals (`3dec`, `1.5dec`), and exponent forms (`1.5e10`)
	/// all round-trip — matching the strict-mode behaviour of
	/// [`Parser::parse_record_id_key`]. NaN / ±∞ are rejected because they
	/// can't be valid record-id keys.
	fn parse_value_numeric_record_id_key(
		&mut self,
		start: Token,
	) -> ParseResult<PublicRecordIdKey> {
		let token = self.lex_compound(start, compound::number_kind)?;
		let span = token.span;
		let number_str = compound::prepare_number_str(self.span_str(span));
		match token.value {
			NumberKind::Integer => match number_str.parse::<i64>() {
				Ok(i) => Ok(PublicRecordIdKey::Number(i)),
				Err(_) => Ok(PublicRecordIdKey::String(number_str.into_owned())),
			},
			NumberKind::Float => {
				let bytes = number_str.as_bytes();
				let f = if bytes[0] == b'N' {
					f64::NAN
				} else if bytes[0] == b'-' && bytes.get(1) == Some(&b'I') {
					f64::NEG_INFINITY
				} else if bytes[0] == b'I' || (bytes[0] == b'+' && bytes.get(1) == Some(&b'I')) {
					f64::INFINITY
				} else {
					number_str.trim_end_matches('f').parse::<f64>().map_err(|e| {
						crate::syn::error::syntax_error!(
							"Failed to parse float record-id key: {e}",
							@span
						)
					})?
				};
				if !f.is_finite() {
					bail!("NaN and ±Infinity are not valid record-id keys", @span);
				}
				Ok(PublicRecordIdKey::Float(f))
			}
			NumberKind::Decimal => {
				let stripped = number_str.trim_end_matches("dec");
				let d = if stripped.contains(['e', 'E']) {
					rust_decimal::Decimal::from_scientific(stripped).map_err(|e| {
						crate::syn::error::syntax_error!(
							"Failed to parse decimal record-id key: {e}",
							@span
						)
					})?
				} else {
					rust_decimal::Decimal::from_str_normalized(stripped).map_err(|e| {
						crate::syn::error::syntax_error!(
							"Failed to parse decimal record-id key: {e}",
							@span
						)
					})?
				};
				Ok(PublicRecordIdKey::Decimal(d))
			}
		}
	}

	/// Parse a digit-prefixed record-id key in flexible-record-id mode. The
	/// parser must distinguish:
	///
	///   * `D . D <suffix>` → Float / Decimal (with `f` / `dec` suffix)
	///   * `D . D`          → Float
	///   * `D <suffix>`     → Float / Decimal
	///   * `D <ident>`      → flexible-ident string (e.g. `1abc`, `1ns`, `1e10`)
	///   * `D`              → Integer
	///
	/// `f` and `dec` are recognised here so that the canonical `to_sql()`
	/// output for non-integer record-id keys (e.g. `1.5f`, `3dec`) round-trips
	/// through `parse_value`. Exponent forms (`1e10`) are intentionally still
	/// treated as flexible-ident strings in flexible mode — matching the
	/// statement-level [`Parser::parse_record_id_key`] convention — because
	/// `Display::fmt` for `f64` never emits exponent notation for finite
	/// floats, so the round-trip path doesn't need them.
	///
	/// `compound::number_kind` cannot be used directly here: the look-ahead
	/// required to detect the flexible-ident case advances the lexer past the
	/// start token, which would trip `lex_compound`'s "start was the last
	/// consumed token" assertion. Instead we stitch together the relevant
	/// token spans and parse the resulting string slice directly.
	///
	/// The peek depth is capped at two (the parser's token buffer holds at
	/// most three tokens). When the leading pattern is `D . D`, we commit by
	/// popping those three tokens before peeking the optional suffix.
	fn parse_flexible_digit_record_id_key_value(
		&mut self,
		start: Token,
	) -> ParseResult<PublicRecordIdKey> {
		let dot = self.peek_whitespace1().filter(|t| t.kind == t!("."));
		let after_dot = if dot.is_some() {
			self.peek_whitespace2().filter(|t| t.kind == TokenKind::Digits)
		} else {
			None
		};

		if let Some(after_dot_tok) = after_dot {
			// `D . D` — pop the three tokens before looking at any suffix to
			// keep us within the token buffer's capacity.
			let mantissa_span = start.span.covers(after_dot_tok.span);
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
				let span = start.span.covers(suf.span);
				let s = self.span_str(span);
				let key = decode_suffixed_numeric_record_id_key(s, &kind, span)?;
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
				Ok(PublicRecordIdKey::Float(f))
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
			let span = start.span.covers(suf.span);
			let s = self.span_str(span);
			let key = decode_suffixed_numeric_record_id_key(s, &kind, span)?;
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
			Ok(PublicRecordIdKey::String(ident))
		} else {
			self.pop_peek();
			let digits_str = self.span_str(start.span);
			Ok(match digits_str.parse::<i64>() {
				Ok(n) => PublicRecordIdKey::Number(n),
				Err(_) => PublicRecordIdKey::String(digits_str.to_owned()),
			})
		}
	}
}

/// Decode a suffixed numeric record-id key literal (e.g. `"1.5f"` for Float,
/// `"3dec"` for Decimal). The caller is responsible for having matched the
/// suffix in the token stream; this helper strips the suffix and parses the
/// numeric mantissa. NaN / ±∞ are rejected.
fn decode_suffixed_numeric_record_id_key(
	s: &str,
	kind: &NumberKind,
	span: Span,
) -> ParseResult<PublicRecordIdKey> {
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
			Ok(PublicRecordIdKey::Float(f))
		}
		NumberKind::Decimal => {
			let trimmed = s.trim_end_matches("dec");
			let d = rust_decimal::Decimal::from_str_normalized(trimmed).map_err(|e| {
				crate::syn::error::syntax_error!(
					"Failed to parse decimal record-id key: {e}",
					@span
				)
			})?;
			Ok(PublicRecordIdKey::Decimal(d))
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
	use crate::syn::parser::ParserSettings;

	/// Parse a record-id literal through `parse_value_record_id` with
	/// `flexible_record_id` set to `flexible`. Mirrors the entry point the
	/// language-tests framework uses when deserialising `[[test.results]]`
	/// `value =` strings, so the regression coverage here matches the
	/// `--results accept` round-trip path.
	fn parse_rid(input: &str, flexible: bool) -> ParseResult<PublicRecordId> {
		let mut parser = Parser::new_with_settings(
			input.as_bytes(),
			ParserSettings {
				flexible_record_id: flexible,
				..ParserSettings::default()
			},
		);
		let mut stack = Stack::new();
		stack.enter(|ctx| async move { parser.parse_value_record_id(ctx).await }).finish()
	}

	#[test]
	fn float_record_id_key_round_trips_in_flexible_mode() {
		let rid = parse_rid("a:1.5f", true).expect("`a:1.5f` should parse");
		assert_eq!(rid.table.as_str(), "a");
		assert_eq!(rid.key, PublicRecordIdKey::Float(1.5));
	}

	#[test]
	fn integer_suffixed_float_record_id_key_round_trips_in_flexible_mode() {
		// `to_sql` for `Float(1.0)` emits `1f` (no fractional part), so the
		// flexible parser must accept the bare-suffix form too.
		let rid = parse_rid("a:1f", true).expect("`a:1f` should parse");
		assert_eq!(rid.key, PublicRecordIdKey::Float(1.0));
	}

	#[test]
	fn decimal_record_id_key_round_trips_in_flexible_mode() {
		let rid = parse_rid("a:3dec", true).expect("`a:3dec` should parse");
		assert_eq!(rid.key, PublicRecordIdKey::Decimal(rust_decimal::Decimal::from(3)));
	}

	#[test]
	fn decimal_record_id_key_with_mantissa_round_trips_in_flexible_mode() {
		let rid = parse_rid("a:1.5dec", true).expect("`a:1.5dec` should parse");
		let PublicRecordIdKey::Decimal(d) = rid.key else {
			panic!("expected Decimal key, got {:?}", rid.key);
		};
		assert_eq!(d, rust_decimal::Decimal::from_str_normalized("1.5").unwrap());
	}

	#[test]
	fn negative_float_record_id_key_in_flexible_mode() {
		let rid = parse_rid("a:-1.5f", true).expect("`a:-1.5f` should parse");
		assert_eq!(rid.key, PublicRecordIdKey::Float(-1.5));
	}

	#[test]
	fn negative_decimal_record_id_key_in_flexible_mode() {
		let rid = parse_rid("a:-3dec", true).expect("`a:-3dec` should parse");
		assert_eq!(rid.key, PublicRecordIdKey::Decimal(rust_decimal::Decimal::from(-3)));
	}

	#[test]
	fn flexible_ident_record_id_key_preserved() {
		// `1abc`, `1ns`, and exponent-shaped idents must still parse as
		// flexible-ident strings — the suffix-detection change must not
		// hijack them.
		for ident in ["1abc", "1ns", "1e10"] {
			let rid = parse_rid(&format!("a:{ident}"), true)
				.unwrap_or_else(|_| panic!("`a:{ident}` should parse"));
			assert_eq!(
				rid.key,
				PublicRecordIdKey::String(ident.to_string()),
				"unexpected key for `a:{ident}`",
			);
		}
	}

	#[test]
	fn plain_integer_record_id_key_still_parses() {
		let rid = parse_rid("a:1", true).unwrap();
		assert_eq!(rid.key, PublicRecordIdKey::Number(1));

		let rid = parse_rid("a:-1", true).unwrap();
		assert_eq!(rid.key, PublicRecordIdKey::Number(-1));
	}

	#[test]
	fn bare_float_record_id_key_in_flexible_mode() {
		let rid = parse_rid("a:1.5", true).unwrap();
		assert_eq!(rid.key, PublicRecordIdKey::Float(1.5));
	}

	#[test]
	fn nan_and_inf_rejected_as_record_id_key() {
		// Strict mode goes through `compound::number_kind` which lifts
		// `1e500` to `f64::INFINITY`; that must be rejected rather than
		// silently produce an infinite-valued record id.
		assert!(parse_rid("a:1e500", false).is_err());
	}

	#[test]
	fn full_value_round_trips_float_and_decimal_record_id_keys() {
		// The bug surfaces when the framework writes a `value =` line of the
		// form `[{ id: a:1.5f, ... }]` after `--results accept`; the value
		// parser then has to reparse that string verbatim. Cover the same
		// shape so a regression at the value-parse level is caught here
		// rather than only in the language-test framework.
		let mut parser = Parser::new_with_settings(
			b"[{ id: a:1.5f, name: 'create-float' }, { id: a:3dec, name: 'create-decimal' }]",
			ParserSettings {
				flexible_record_id: true,
				..ParserSettings::default()
			},
		);
		let mut stack = Stack::new();
		let value = stack
			.enter(|ctx| async move { parser.parse_value(ctx).await })
			.finish()
			.expect("array of objects with float and decimal record-id keys should parse");
		let PublicValue::Array(arr) = value else {
			panic!("expected array, got {value:?}");
		};
		assert_eq!(arr.len(), 2);
	}
}
