//! Stores a DEFINE ACCESS ON DATABASE configuration
use crate::expr::statements::define::DefineAccessStatement;
use crate::key::category::Categorise;
use crate::key::category::Category;
use crate::kvs::KVKey;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(crate) struct Ac<'a> {
	__: u8,
	_a: u8,
	pub ns: &'a str,
	_b: u8,
	pub db: &'a str,
	_c: u8,
	_d: u8,
	_e: u8,
	pub ac: &'a str,
}

impl KVKey for Ac<'_> {
	type ValueType = DefineAccessStatement;
}

pub fn new<'a>(ns: &'a str, db: &'a str, ac: &'a str) -> Ac<'a> {
	Ac::new(ns, db, ac)
}

pub fn prefix(ns: &str, db: &str) -> Result<Vec<u8>> {
	let mut k = crate::key::database::all::new(ns, db).encode_key()?;
	k.extend_from_slice(b"!ac\x00");
	Ok(k)
}

pub fn suffix(ns: &str, db: &str) -> Result<Vec<u8>> {
	let mut k = crate::key::database::all::new(ns, db).encode_key()?;
	k.extend_from_slice(b"!ac\xff");
	Ok(k)
}

impl Categorise for Ac<'_> {
	fn categorise(&self) -> Category {
		Category::DatabaseAccess
	}
}

impl<'a> Ac<'a> {
	pub fn new(ns: &'a str, db: &'a str, ac: &'a str) -> Self {
		Self {
			__: b'/',
			_a: b'*',
			ns,
			_b: b'*',
			db,
			_c: b'!',
			_d: b'a',
			_e: b'c',
			ac,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn key() {
		#[rustfmt::skip]
		let val = Ac::new(
			"testns",
			"testdb",
			"testac",
		);
		let enc = Ac::encode_key(&val).unwrap();
		assert_eq!(enc, b"/*testns\0*testdb\0!actestac\0");
	}

	#[test]
	fn test_prefix() {
		let val = super::prefix("testns", "testdb").unwrap();
		assert_eq!(val, b"/*testns\0*testdb\0!ac\0");
	}

	#[test]
	fn test_suffix() {
		let val = super::suffix("testns", "testdb").unwrap();
		assert_eq!(val, b"/*testns\0*testdb\0!ac\xff");
	}
}
