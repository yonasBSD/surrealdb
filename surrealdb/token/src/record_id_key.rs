use logos::Logos;

use crate::Joined;

#[derive(Logos, Clone, Copy, PartialEq, Eq, Debug)]
#[logos(extras = Joined)]
#[logos(subpattern backtick_ident = r"`([^`\\]|\\.)*`")]
#[logos(subpattern bracket_ident = r"⟨([^⟩\\]|\\.)*⟩")]
pub enum RecordIdKeyToken {
	#[token("..")]
	Range,
	#[regex("(?i)RAND")]
	Rand,
	#[regex("(?i)UUID")]
	Uuid,
	#[regex("(?i)ULID")]
	Ulid,
	#[token("{")]
	OpenBrace,
	#[token("[")]
	OpenBracket,
	#[regex(r#"u"([^"\\]|\\.)*""#)]
	#[regex(r#"u'([^'\\]|\\.)*'"#)]
	UuidString,
	#[regex(r#"(s)?"([^"\\]|\\.)*""#)]
	#[regex(r#"(s)?'([^'\\]|\\.)*'"#)]
	String,
	// `digits . digits` must outrank `digits` so `1.5` lexes as a single
	// `Float` rather than `Number(1)` leaving `.5` for the outer expression
	// parser (which then errors on the leading `5`). Logos breaks ties by
	// match length, so longest wins; the explicit priorities make intent
	// obvious and protect against future regex additions.
	//
	// `f` / `dec` suffixes are accepted on both fractional (`1.5f`, `1.5dec`)
	// and bare-integer (`1f`, `3dec`) forms so the canonical `to_sql()` output
	// of `Number::Float` / `Number::Decimal` round-trips back through the new
	// AST parser. The reject arms (callback = |_| None) skip the match when a
	// suffix would be followed by another identifier character (e.g. `1fa`,
	// `1deca`), letting Logos fall back to the `Identifier` regex so flexible-
	// mode strings like `t:1ns` / `t:123dec_extra` still parse as identifiers.
	#[regex(r"[+\-]?[0-9]+\.[0-9]+f?", priority = 5)]
	#[regex(r"[+\-]?[0-9]+f", priority = 5)]
	#[regex(r"[+\-]?[0-9]+(\.[0-9]+)?f[_a-zA-Z0-9]", priority = 6, callback = |_| None)]
	Float,
	#[regex(r"[+\-]?[0-9]+(\.[0-9]+)?dec", priority = 5)]
	#[regex(r"[+\-]?[0-9]+(\.[0-9]+)?dec[_a-zA-Z0-9]", priority = 6, callback = |_| None)]
	Decimal,
	#[regex(r"[+\-]?([0-9]+)", priority = 3)]
	Number,
	#[regex(r"(?&backtick_ident)")]
	#[regex(r"(?&bracket_ident)")]
	#[regex(r"[_0-9a-zA-Z]+")]
	Identifier,
}
