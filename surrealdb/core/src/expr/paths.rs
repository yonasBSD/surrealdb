use std::sync::LazyLock;

use surrealdb_strand::Strand;

use crate::expr::Part;

/// Single-field path for `"id"`: record primary key when picking from a value, and the
/// authenticated session user id (UUID) on the frozen-context `session` object.
pub static ID: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("id"))]);

/// Client IP address stored on the frozen-context `session` object (`session()` / batch metadata).
/// Accessible via the `session::ip()` function or the `$session.ip` parameter.
pub static IP: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("ip"))]);

/// Active namespace name on the frozen-context `session` object.
/// Accessible via the `session::ns()` function or the `$session.ns` parameter.
pub static NS: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("ns"))]);

/// Active database name on the frozen-context `session` object.
/// Accessible via the `session::db()` function or the `$session.db` parameter.
pub static DB: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("db"))]);

/// Access level string on the frozen-context `session` object.
/// Accessible via the `session::ac()` function or the `$session.ac` parameter.
pub static AC: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("ac"))]);

/// Auth-related payload on the frozen-context `session` object.
/// Accessible via the `session::rd()` function or the `$session.rd` parameter.
pub static RD: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("rd"))]);

/// Request origin string on the frozen-context `session` object.
/// Accessible via the `session::origin()` function or the `$session.or` parameter.
pub static OR: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("or"))]);

/// Auth token material on the frozen-context `session` object.
/// Accessible via the `session::token()` function or the `$session.tk` parameter.
pub static TK: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("tk"))]);

/// Incoming endpoint `in` field on graph edges (`->` / `RELATE` semantics).
pub static IN: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("in"))]);

/// Outgoing endpoint `out` field on graph edges (`->` / `RELATE` semantics).
pub static OUT: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(Strand::new_static("out"))]);
