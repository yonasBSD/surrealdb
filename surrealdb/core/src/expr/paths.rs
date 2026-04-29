use std::sync::LazyLock;

use crate::expr::Part;

pub const OBJ_PATH_ACCESS: &str = "ac";
pub const OBJ_PATH_AUTH: &str = "rd";
pub const OBJ_PATH_TOKEN: &str = "tk";

pub static ID: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("id".into())]);

pub static IP: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("ip".into())]);

pub static NS: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("ns".into())]);

pub static DB: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("db".into())]);

pub static AC: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(OBJ_PATH_ACCESS.into())]);

pub static RD: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(OBJ_PATH_AUTH.into())]);

pub static OR: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("or".into())]);

pub static TK: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field(OBJ_PATH_TOKEN.into())]);

pub static IN: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("in".into())]);

pub static OUT: LazyLock<[Part; 1]> = LazyLock::new(|| [Part::Field("out".into())]);
