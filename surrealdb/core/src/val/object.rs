use std::collections::{BTreeMap, HashMap};
use std::ops::{Deref, DerefMut};

use anyhow::Result;
use http::{HeaderMap, HeaderName, HeaderValue};
use revision::revisioned;
use storekey::{BorrowDecode, Encode};
use surrealdb_types::{SqlFormat, ToSql, write_sql};

use crate::err::Error;
use crate::expr::literal::ObjectEntry;
use crate::fmt::EscapeObjectKey;
use crate::val::{IndexFormat, RecordId, Strand, Value};

/// Invariant: Keys never contain NUL bytes.
#[revisioned(revision = 1)]
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Hash, Encode, BorrowDecode)]
#[storekey(format = "()")]
#[storekey(format = "IndexFormat")]
pub(crate) struct Object(pub(crate) BTreeMap<Strand, Value>);

impl From<BTreeMap<&str, Value>> for Object {
	fn from(v: BTreeMap<&str, Value>) -> Self {
		Self(v.into_iter().map(|(key, val)| (key.into(), val)).collect())
	}
}

impl From<BTreeMap<String, Value>> for Object {
	fn from(v: BTreeMap<String, Value>) -> Self {
		Self(v.into_iter().map(|(k, val)| (k.into(), val)).collect())
	}
}

impl From<BTreeMap<Strand, Value>> for Object {
	fn from(v: BTreeMap<Strand, Value>) -> Self {
		Self(v)
	}
}

impl FromIterator<(String, Value)> for Object {
	fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
		Self(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
	}
}

impl FromIterator<(Strand, Value)> for Object {
	fn from_iter<T: IntoIterator<Item = (Strand, Value)>>(iter: T) -> Self {
		Self(BTreeMap::from_iter(iter))
	}
}

impl<'a> FromIterator<(&'a str, Value)> for Object {
	fn from_iter<T: IntoIterator<Item = (&'a str, Value)>>(iter: T) -> Self {
		Self(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
	}
}

impl From<BTreeMap<String, String>> for Object {
	fn from(v: BTreeMap<String, String>) -> Self {
		Self(
			v.into_iter()
				.map(|(k, v)| (Strand::from(k), Value::from(v)))
				.collect::<BTreeMap<Strand, Value>>(),
		)
	}
}

impl From<Vec<(String, Value)>> for Object {
	fn from(v: Vec<(String, Value)>) -> Self {
		Self(v.into_iter().map(|(k, val)| (k.into(), val)).collect())
	}
}

impl From<HashMap<&str, Value>> for Object {
	fn from(v: HashMap<&str, Value>) -> Self {
		Self(v.into_iter().map(|(key, val)| (key.into(), val)).collect())
	}
}

impl From<HashMap<String, Value>> for Object {
	fn from(v: HashMap<String, Value>) -> Self {
		Self(v.into_iter().map(|(k, val)| (k.into(), val)).collect())
	}
}

impl From<Option<Self>> for Object {
	fn from(v: Option<Self>) -> Self {
		v.unwrap_or_default()
	}
}

impl TryFrom<Object> for crate::types::PublicObject {
	type Error = anyhow::Error;

	fn try_from(s: Object) -> Result<Self, Self::Error> {
		s.0.into_iter()
			.map(|(k, v)| crate::types::PublicValue::try_from(v).map(|v| (k.into_string(), v)))
			.collect()
	}
}

impl From<crate::types::PublicObject> for Object {
	fn from(s: crate::types::PublicObject) -> Self {
		s.into_iter()
			.map(|(k, v)| (Strand::from(k), Value::from(v)))
			.collect::<BTreeMap<Strand, Value>>()
			.into()
	}
}

impl Deref for Object {
	type Target = BTreeMap<Strand, Value>;
	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl DerefMut for Object {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.0
	}
}

impl IntoIterator for Object {
	type Item = (Strand, Value);
	type IntoIter = std::collections::btree_map::IntoIter<Strand, Value>;
	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl TryInto<BTreeMap<String, String>> for Object {
	type Error = Error;
	fn try_into(self) -> Result<BTreeMap<String, String>, Self::Error> {
		self.into_iter().map(|(k, v)| Ok((k.into_string(), v.coerce_to()?))).collect()
	}
}

impl TryInto<HeaderMap> for Object {
	type Error = Error;
	fn try_into(self) -> Result<HeaderMap, Self::Error> {
		let mut headermap = HeaderMap::new();
		for (k, v) in self {
			let k: HeaderName = k.as_str().parse()?;
			let v: HeaderValue = v.coerce_to::<String>()?.parse()?;
			headermap.insert(k, v);
		}

		Ok(headermap)
	}
}

impl Object {
	/// Insert a key-value pair into the object.
	///
	/// The key is accepted as anything convertible to [`Strand`]
	/// (including `String`, `&str`, and `Strand`), which keeps call
	/// sites ergonomic.
	#[inline]
	pub fn insert(&mut self, key: impl Into<Strand>, value: Value) -> Option<Value> {
		self.0.insert(key.into(), value)
	}

	/// Look up a value by key.
	///
	/// Takes `&str`, so `&String` callers work transparently via deref
	/// coercion — avoiding the `Borrow<String>` trait bound that would
	/// otherwise be required on `Strand`.
	#[inline]
	pub fn get(&self, key: &str) -> Option<&Value> {
		self.0.get(key)
	}

	/// Look up a value by key for mutation.
	#[inline]
	pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
		self.0.get_mut(key)
	}

	/// Check whether the object contains a given key.
	#[inline]
	pub fn contains_key(&self, key: &str) -> bool {
		self.0.contains_key(key)
	}

	/// Remove and return the value for `key`.
	#[inline]
	pub fn remove(&mut self, key: &str) -> Option<Value> {
		self.0.remove(key)
	}

	/// Return the map entry for `key`, so callers can use the
	/// `Entry` API without manual interning.
	#[inline]
	pub fn entry(
		&mut self,
		key: impl Into<Strand>,
	) -> std::collections::btree_map::Entry<'_, Strand, Value> {
		self.0.entry(key.into())
	}

	/// Fetch the record id if there is one
	pub fn rid(&self) -> Option<RecordId> {
		match self.get("id") {
			Some(Value::RecordId(v)) => Some(v.clone()),
			_ => None,
		}
	}

	pub fn into_literal(self) -> Vec<ObjectEntry> {
		self.0
			.into_iter()
			.map(|(k, v)| ObjectEntry {
				key: k,
				value: v.into_literal(),
			})
			.collect()
	}
}

impl std::ops::Add for Object {
	type Output = Self;

	fn add(self, rhs: Self) -> Self::Output {
		let mut lhs = self;
		lhs.0.extend(rhs.0);
		lhs
	}
}

impl ToSql for Object {
	fn fmt_sql(&self, f: &mut String, sql_fmt: SqlFormat) {
		if self.is_empty() {
			return f.push_str("{  }");
		}

		if sql_fmt.is_pretty() {
			f.push('{');
		} else {
			f.push_str("{ ");
		}

		if !self.is_empty() {
			let inner_fmt = sql_fmt.increment();
			if sql_fmt.is_pretty() {
				f.push('\n');
				inner_fmt.write_indent(f);
			}
			for (i, (key, value)) in self.0.iter().enumerate() {
				if i > 0 {
					inner_fmt.write_separator(f);
				}
				write_sql!(f, sql_fmt, "{}: ", EscapeObjectKey(key.as_str()));
				value.fmt_sql(f, inner_fmt);
			}
			if sql_fmt.is_pretty() {
				f.push('\n');
				sql_fmt.write_indent(f);
			}
		}

		if sql_fmt.is_pretty() {
			f.push('}');
		} else {
			f.push_str(" }");
		}
	}
}
