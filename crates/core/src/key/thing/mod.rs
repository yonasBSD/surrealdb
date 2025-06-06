//! Stores a record document
use crate::expr::Id;
use crate::key::category::Categorise;
use crate::key::category::Category;
use crate::kvs::{KeyEncode, impl_key};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Thing<'a> {
	__: u8,
	_a: u8,
	pub ns: &'a str,
	_b: u8,
	pub db: &'a str,
	_c: u8,
	pub tb: &'a str,
	_d: u8,
	pub id: Id,
}
impl_key!(Thing<'a>);

pub fn new<'a>(ns: &'a str, db: &'a str, tb: &'a str, id: &Id) -> Thing<'a> {
	Thing::new(ns, db, tb, id.to_owned())
}

pub fn prefix(ns: &str, db: &str, tb: &str) -> Result<Vec<u8>> {
	let mut k = crate::key::table::all::new(ns, db, tb).encode()?;
	k.extend_from_slice(b"*\x00");
	Ok(k)
}

pub fn suffix(ns: &str, db: &str, tb: &str) -> Result<Vec<u8>> {
	let mut k = crate::key::table::all::new(ns, db, tb).encode()?;
	k.extend_from_slice(b"*\xff");
	Ok(k)
}

impl Categorise for Thing<'_> {
	fn categorise(&self) -> Category {
		Category::Thing
	}
}

impl<'a> Thing<'a> {
	pub fn new(ns: &'a str, db: &'a str, tb: &'a str, id: Id) -> Self {
		Self {
			__: b'/',
			_a: b'*',
			ns,
			_b: b'*',
			db,
			_c: b'*',
			tb,
			_d: b'*',
			id,
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::kvs::KeyDecode;
	use crate::syn;

	#[test]
	fn key() {
		use super::*;
		#[rustfmt::skip]
		let val = Thing::new(
			"testns",
			"testdb",
			"testtb",
			"testid".into(),
		);
		let enc = Thing::encode(&val).unwrap();
		assert_eq!(enc, b"/*testns\0*testdb\0*testtb\0*\0\0\0\x01testid\0");

		let dec = Thing::decode(&enc).unwrap();
		assert_eq!(val, dec);
	}
	#[test]
	fn key_complex() {
		use super::*;
		//
		let id1 = "foo:['test']";
		let thing = syn::thing(id1).expect("Failed to parse the ID");
		let id1 = thing.id.into();
		let val = Thing::new("testns", "testdb", "testtb", id1);
		let enc = Thing::encode(&val).unwrap();
		assert_eq!(enc, b"/*testns\0*testdb\0*testtb\0*\0\0\0\x03\0\0\0\x04test\0\x01");

		let dec = Thing::decode(&enc).unwrap();
		assert_eq!(val, dec);
		println!("---");
		let id2 = "foo:[u'f8e238f2-e734-47b8-9a16-476b291bd78a']";
		let thing = syn::thing(id2).expect("Failed to parse the ID");
		let id2 = thing.id.into();
		let val = Thing::new("testns", "testdb", "testtb", id2);
		let enc = Thing::encode(&val).unwrap();
		assert_eq!(enc, b"/*testns\0*testdb\0*testtb\0*\0\0\0\x03\0\0\0\x07\0\0\0\0\0\0\0\x10\xf8\xe2\x38\xf2\xe7\x34\x47\xb8\x9a\x16\x47\x6b\x29\x1b\xd7\x8a\x01");

		let dec = Thing::decode(&enc).unwrap();
		assert_eq!(val, dec);
		println!("---");
	}
}
