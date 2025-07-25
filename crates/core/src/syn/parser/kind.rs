use std::collections::BTreeMap;

use reblessive::Stk;

use crate::{
	sql::{Duration, Idiom, Kind, Strand, Table, kind::Literal},
	syn::{
		error::bail,
		lexer::compound,
		parser::mac::expected,
		token::{Glued, Keyword, Span, TokenKind, t},
	},
};

use super::{ParseResult, Parser, mac::unexpected};

impl Parser<'_> {
	/// Parse a kind production.
	///
	/// # Parser State
	/// expects the first `<` to already be eaten
	pub(crate) async fn parse_kind(&mut self, ctx: &mut Stk, delim: Span) -> ParseResult<Kind> {
		let kind = self.parse_inner_kind(ctx).await?;
		self.expect_closing_delimiter(t!(">"), delim)?;
		Ok(kind)
	}

	/// Parse an inner kind, a kind without enclosing `<` `>`.
	pub(crate) async fn parse_inner_kind(&mut self, ctx: &mut Stk) -> ParseResult<Kind> {
		match self.parse_inner_single_kind(ctx).await? {
			Kind::Any => Ok(Kind::Any),
			Kind::Option(k) => Ok(Kind::Option(k)),
			first => {
				if self.peek_kind() == t!("|") {
					let mut kind = vec![first];
					while self.eat(t!("|")) {
						kind.push(ctx.run(|ctx| self.parse_concrete_kind(ctx)).await?);
					}
					let kind = Kind::Either(kind);
					let kind = kind.to_discriminated().unwrap_or(kind);
					Ok(kind)
				} else {
					Ok(first)
				}
			}
		}
	}

	/// Parse a single inner kind, a kind without enclosing `<` `>`.
	pub(super) async fn parse_inner_single_kind(&mut self, ctx: &mut Stk) -> ParseResult<Kind> {
		match self.peek_kind() {
			t!("ANY") => {
				self.pop_peek();
				Ok(Kind::Any)
			}
			t!("OPTION") => {
				self.pop_peek();

				let delim = expected!(self, t!("<")).span;
				let mut first = ctx.run(|ctx| self.parse_concrete_kind(ctx)).await?;
				if self.peek_kind() == t!("|") {
					let mut kind = vec![first];
					while self.eat(t!("|")) {
						kind.push(ctx.run(|ctx| self.parse_concrete_kind(ctx)).await?);
					}

					let kind = Kind::Either(kind);
					first = kind.to_discriminated().unwrap_or(kind);
				}
				self.expect_closing_delimiter(t!(">"), delim)?;
				Ok(Kind::Option(Box::new(first)))
			}
			_ => ctx.run(|ctx| self.parse_concrete_kind(ctx)).await,
		}
	}

	/// Parse a single kind which is not any, option, or either.
	async fn parse_concrete_kind(&mut self, ctx: &mut Stk) -> ParseResult<Kind> {
		if Self::token_can_be_literal_kind(self.peek_kind()) {
			let literal = self.parse_literal_kind(ctx).await?;
			return Ok(Kind::Literal(literal));
		}

		let next = self.next();
		match next.kind {
			t!("BOOL") => Ok(Kind::Bool),
			t!("NULL") => Ok(Kind::Null),
			t!("BYTES") => Ok(Kind::Bytes),
			t!("DATETIME") => Ok(Kind::Datetime),
			t!("DECIMAL") => Ok(Kind::Decimal),
			t!("DURATION") => Ok(Kind::Duration),
			t!("FLOAT") => Ok(Kind::Float),
			t!("INT") => Ok(Kind::Int),
			t!("NUMBER") => Ok(Kind::Number),
			t!("OBJECT") => Ok(Kind::Object),
			t!("POINT") => Ok(Kind::Point),
			t!("STRING") => Ok(Kind::String),
			t!("UUID") => Ok(Kind::Uuid),
			t!("RANGE") => Ok(Kind::Range),
			t!("REGEX") => Ok(Kind::Regex),
			t!("FUNCTION") => Ok(Kind::Function(Default::default(), Default::default())),
			t!("RECORD") => {
				let span = self.peek().span;
				if self.eat(t!("<")) {
					let mut tables = vec![self.next_token_value()?];
					while self.eat(t!("|")) {
						tables.push(self.next_token_value()?);
					}
					self.expect_closing_delimiter(t!(">"), span)?;
					Ok(Kind::Record(tables))
				} else {
					Ok(Kind::Record(Vec::new()))
				}
			}
			t!("GEOMETRY") => {
				let span = self.peek().span;
				if self.eat(t!("<")) {
					let mut kind = vec![self.parse_geometry_kind()?];
					while self.eat(t!("|")) {
						kind.push(self.parse_geometry_kind()?);
					}
					self.expect_closing_delimiter(t!(">"), span)?;
					Ok(Kind::Geometry(kind))
				} else {
					Ok(Kind::Geometry(Vec::new()))
				}
			}
			t!("ARRAY") => {
				let span = self.peek().span;
				if self.eat(t!("<")) {
					let kind = ctx.run(|ctx| self.parse_inner_kind(ctx)).await?;
					let size = self.eat(t!(",")).then(|| self.next_token_value()).transpose()?;
					self.expect_closing_delimiter(t!(">"), span)?;
					Ok(Kind::Array(Box::new(kind), size))
				} else {
					Ok(Kind::Array(Box::new(Kind::Any), None))
				}
			}
			t!("SET") => {
				let span = self.peek().span;
				if self.eat(t!("<")) {
					let kind = ctx.run(|ctx| self.parse_inner_kind(ctx)).await?;
					let size = self.eat(t!(",")).then(|| self.next_token_value()).transpose()?;
					self.expect_closing_delimiter(t!(">"), span)?;
					Ok(Kind::Set(Box::new(kind), size))
				} else {
					Ok(Kind::Set(Box::new(Kind::Any), None))
				}
			}
			t!("REFERENCES") => {
				if !self.settings.references_enabled {
					bail!(
						"Experimental capability `record_references` is not enabled",
						@self.last_span() => "Use of `REFERENCES` keyword is still experimental"
					)
				}

				let span = self.peek().span;
				let (table, path) = if self.eat(t!("<")) {
					let table: Option<Table> = Some(self.next_token_value()?);
					let path: Option<Idiom> = if self.eat(t!(",")) {
						Some(self.parse_local_idiom(ctx).await?)
					} else {
						None
					};

					self.expect_closing_delimiter(t!(">"), span)?;
					(table, path)
				} else {
					(None, None)
				};

				Ok(Kind::References(table, path))
			}
			t!("NONE") => {
				unexpected!(self, next, "a kind name.", => "to define a field that can be NONE, use option<type_name> instead.")
			}
			t!("FILE") => {
				let span = self.peek().span;
				if self.eat(t!("<")) {
					let mut buckets = vec![self.next_token_value()?];
					while self.eat(t!("|")) {
						buckets.push(self.next_token_value()?);
					}
					self.expect_closing_delimiter(t!(">"), span)?;
					Ok(Kind::File(buckets))
				} else {
					Ok(Kind::File(Vec::new()))
				}
			}
			_ => unexpected!(self, next, "a kind name"),
		}
	}

	/// Parse the kind of gemoetry
	fn parse_geometry_kind(&mut self) -> ParseResult<String> {
		let next = self.next();
		match next.kind {
			TokenKind::Keyword(
				x @ (Keyword::Feature
				| Keyword::Point
				| Keyword::Line
				| Keyword::Polygon
				| Keyword::MultiPoint
				| Keyword::MultiLine
				| Keyword::MultiPolygon
				| Keyword::Collection),
			) => Ok(x.as_str().to_ascii_lowercase()),
			_ => unexpected!(self, next, "a geometry kind name"),
		}
	}

	/// Parse a literal kind
	async fn parse_literal_kind(&mut self, ctx: &mut Stk) -> ParseResult<Literal> {
		let peek = self.peek();
		match peek.kind {
			t!("true") => {
				self.pop_peek();
				Ok(Literal::Bool(true))
			}
			t!("false") => {
				self.pop_peek();
				Ok(Literal::Bool(false))
			}
			t!("'") | t!("\"") | TokenKind::Glued(Glued::Strand) => {
				let s = self.next_token_value::<Strand>()?;
				Ok(Literal::String(s))
			}
			t!("+") | t!("-") | TokenKind::Glued(Glued::Number) => {
				self.next_token_value().map(Literal::Number)
			}
			TokenKind::Glued(Glued::Duration) => self.next_token_value().map(Literal::Duration),
			TokenKind::Digits => {
				self.pop_peek();
				let compound = self.lexer.lex_compound(peek, compound::numeric)?;
				let v = match compound.value {
					compound::Numeric::Number(x) => Literal::Number(x),
					compound::Numeric::Duration(x) => Literal::Duration(Duration(x)),
				};
				Ok(v)
			}
			t!("{") => {
				self.pop_peek();
				let mut obj = BTreeMap::new();
				while !self.eat(t!("}")) {
					let key = self.parse_object_key()?;
					expected!(self, t!(":"));
					let kind = ctx.run(|ctx| self.parse_inner_kind(ctx)).await?;
					obj.insert(key, kind);
					self.eat(t!(","));
				}
				Ok(Literal::Object(obj))
			}
			t!("[") => {
				self.pop_peek();
				let mut arr = Vec::new();
				while !self.eat(t!("]")) {
					let kind = ctx.run(|ctx| self.parse_inner_kind(ctx)).await?;
					arr.push(kind);
					self.eat(t!(","));
				}
				Ok(Literal::Array(arr))
			}
			_ => unexpected!(self, peek, "a literal kind"),
		}
	}

	fn token_can_be_literal_kind(t: TokenKind) -> bool {
		matches!(
			t,
			t!("true")
				| t!("false")
				| t!("'") | t!("\"")
				| t!("+") | t!("-")
				| TokenKind::Glued(Glued::Duration | Glued::Strand | Glued::Number)
				| TokenKind::Digits
				| t!("{") | t!("[")
		)
	}
}

#[cfg(test)]
mod tests {
	use reblessive::Stack;

	use super::*;
	use crate::sql::{Ident, table::Table};

	fn kind(i: &str) -> ParseResult<Kind> {
		let mut parser = Parser::new(i.as_bytes());
		let mut stack = Stack::new();
		stack.enter(|ctx| parser.parse_inner_kind(ctx)).finish()
	}

	#[test]
	fn kind_any() {
		let sql = "any";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("any", format!("{}", out));
		assert_eq!(out, Kind::Any);
	}

	#[test]
	fn kind_null() {
		let sql = "null";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("null", format!("{}", out));
		assert_eq!(out, Kind::Null);
	}

	#[test]
	fn kind_bool() {
		let sql = "bool";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("bool", format!("{}", out));
		assert_eq!(out, Kind::Bool);
	}

	#[test]
	fn kind_bytes() {
		let sql = "bytes";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("bytes", format!("{}", out));
		assert_eq!(out, Kind::Bytes);
	}

	#[test]
	fn kind_datetime() {
		let sql = "datetime";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("datetime", format!("{}", out));
		assert_eq!(out, Kind::Datetime);
	}

	#[test]
	fn kind_decimal() {
		let sql = "decimal";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("decimal", format!("{}", out));
		assert_eq!(out, Kind::Decimal);
	}

	#[test]
	fn kind_duration() {
		let sql = "duration";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("duration", format!("{}", out));
		assert_eq!(out, Kind::Duration);
	}

	#[test]
	fn kind_float() {
		let sql = "float";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("float", format!("{}", out));
		assert_eq!(out, Kind::Float);
	}

	#[test]
	fn kind_number() {
		let sql = "number";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("number", format!("{}", out));
		assert_eq!(out, Kind::Number);
	}

	#[test]
	fn kind_object() {
		let sql = "object";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("object", format!("{}", out));
		assert_eq!(out, Kind::Object);
	}

	#[test]
	fn kind_point() {
		let sql = "point";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("point", format!("{}", out));
		assert_eq!(out, Kind::Point);
	}

	#[test]
	fn kind_string() {
		let sql = "string";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("string", format!("{}", out));
		assert_eq!(out, Kind::String);
	}

	#[test]
	fn kind_uuid() {
		let sql = "uuid";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("uuid", format!("{}", out));
		assert_eq!(out, Kind::Uuid);
	}

	#[test]
	fn kind_either() {
		let sql = "int | float";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("int | float", format!("{}", out));
		assert_eq!(out, Kind::Either(vec![Kind::Int, Kind::Float]));
	}

	#[test]
	fn kind_record_any() {
		let sql = "record";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("record", format!("{}", out));
		assert_eq!(out, Kind::Record(vec![]));
	}

	#[test]
	fn kind_record_one() {
		let sql = "record<person>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("record<person>", format!("{}", out));
		assert_eq!(out, Kind::Record(vec![Table::from("person")]));
	}

	#[test]
	fn kind_record_many() {
		let sql = "record<person | animal>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("record<person | animal>", format!("{}", out));
		assert_eq!(out, Kind::Record(vec![Table::from("person"), Table::from("animal")]));
	}

	#[test]
	fn kind_geometry_any() {
		let sql = "geometry";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("geometry", format!("{}", out));
		assert_eq!(out, Kind::Geometry(vec![]));
	}

	#[test]
	fn kind_geometry_one() {
		let sql = "geometry<point>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("geometry<point>", format!("{}", out));
		assert_eq!(out, Kind::Geometry(vec![String::from("point")]));
	}

	#[test]
	fn kind_geometry_many() {
		let sql = "geometry<point | multipoint>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("geometry<point | multipoint>", format!("{}", out));
		assert_eq!(out, Kind::Geometry(vec![String::from("point"), String::from("multipoint")]));
	}

	#[test]
	fn kind_option_one() {
		let sql = "option<int>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("option<int>", format!("{}", out));
		assert_eq!(out, Kind::Option(Box::new(Kind::Int)));
	}

	#[test]
	fn kind_option_many() {
		let sql = "option<int | float>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("option<int | float>", format!("{}", out));
		assert_eq!(out, Kind::Option(Box::new(Kind::Either(vec![Kind::Int, Kind::Float]))));
	}

	#[test]
	fn kind_array_any() {
		let sql = "array";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("array", format!("{}", out));
		assert_eq!(out, Kind::Array(Box::new(Kind::Any), None));
	}

	#[test]
	fn kind_array_some() {
		let sql = "array<float>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("array<float>", format!("{}", out));
		assert_eq!(out, Kind::Array(Box::new(Kind::Float), None));
	}

	#[test]
	fn kind_array_some_size() {
		let sql = "array<float, 10>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("array<float, 10>", format!("{}", out));
		assert_eq!(out, Kind::Array(Box::new(Kind::Float), Some(10)));
	}

	#[test]
	fn kind_set_any() {
		let sql = "set";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("set", format!("{}", out));
		assert_eq!(out, Kind::Set(Box::new(Kind::Any), None));
	}

	#[test]
	fn kind_set_some() {
		let sql = "set<float>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("set<float>", format!("{}", out));
		assert_eq!(out, Kind::Set(Box::new(Kind::Float), None));
	}

	#[test]
	fn kind_set_some_size() {
		let sql = "set<float, 10>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("set<float, 10>", format!("{}", out));
		assert_eq!(out, Kind::Set(Box::new(Kind::Float), Some(10)));
	}

	#[test]
	fn kind_discriminated_object() {
		let sql = "{ status: 'ok', data: object } | { status: 'error', message: string }";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!(
			"{ data: object, status: 'ok' } | { message: string, status: 'error' }",
			format!("{}", out)
		);
		assert_eq!(
			out,
			Kind::Literal(Literal::DiscriminatedObject(
				"status".to_string(),
				vec![
					map! {
						"status".to_string() => Kind::Literal(Literal::String("ok".into())),
						"data".to_string() => Kind::Object,
					},
					map! {
						"status".to_string() => Kind::Literal(Literal::String("error".into())),
						"message".to_string() => Kind::String,
					},
				]
			))
		);
	}

	#[test]
	fn kind_union_literal_object() {
		let sql = "{ status: 'ok', data: object } | { status: string, message: string }";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!(
			"{ data: object, status: 'ok' } | { message: string, status: string }",
			format!("{}", out)
		);
		assert_eq!(
			out,
			Kind::Either(vec![
				Kind::Literal(Literal::Object(map! {
					"status".to_string() => Kind::Literal(Literal::String("ok".into())),
					"data".to_string() => Kind::Object,
				})),
				Kind::Literal(Literal::Object(map! {
					"status".to_string() => Kind::String,
					"message".to_string() => Kind::String,
				})),
			])
		);
	}

	#[test]
	fn file_record_any() {
		let sql = "file";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("file", format!("{}", out));
		assert_eq!(out, Kind::File(vec![]));
	}

	#[test]
	fn file_record_one() {
		let sql = "file<one>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("file<one>", format!("{}", out));
		assert_eq!(out, Kind::File(vec![Ident::from("one")]));
	}

	#[test]
	fn file_record_many() {
		let sql = "file<one | two>";
		let res = kind(sql);
		let out = res.unwrap();
		assert_eq!("file<one | two>", format!("{}", out));
		assert_eq!(out, Kind::File(vec![Ident::from("one"), Ident::from("two")]));
	}
}
