use anyhow::Result;
use surrealdb_types::ToSql;

use crate::err::Error;
use crate::val::{RecordId, RecordIdKey, TableName, Value};

impl Value {
	pub(crate) fn generate(self, tb: TableName, retable: bool) -> Result<RecordId> {
		match self {
			// Numeric id — preserves Int/Float/Decimal verbatim. NaN/±∞ are
			// rejected via `RecordIdKey::from_number`.
			Value::Number(id) => {
				let key = RecordIdKey::from_number(id).ok_or_else(|| {
					anyhow::Error::new(Error::IdInvalid {
						value: Value::Number(id).to_sql(),
					})
				})?;
				Ok(RecordId {
					table: tb,
					key,
				})
			}
			// There is a string for the id field
			Value::String(id) if !id.is_empty() => Ok(RecordId {
				table: tb,
				key: id.into(),
			}),
			// There is an object for the id field
			Value::Object(id) => Ok(RecordId {
				table: tb,
				key: id.into(),
			}),
			// There is an array for the id field
			Value::Array(id) => Ok(RecordId {
				table: tb,
				key: id.into(),
			}),
			// There is a UUID for the id field
			Value::Uuid(id) => Ok(RecordId {
				table: tb,
				key: id.into(),
			}),
			// There is no record id field
			Value::None => Ok(RecordId {
				table: tb,
				key: RecordIdKey::rand(),
			}),
			// There is a record id defined
			Value::RecordId(id) => {
				if retable {
					// Let's re-table this record id
					Ok(RecordId {
						table: tb,
						key: id.key,
					})
				} else {
					// Let's use the specified record id
					if *tb == id.table {
						// The record is from the same table
						Ok(id)
					} else {
						// The record id is from another table
						Ok(RecordId {
							table: tb,
							key: id.key,
						})
					}
				}
			}
			// Any other value is wrong
			id => Err(anyhow::Error::new(Error::IdInvalid {
				value: id.to_sql(),
			})),
		}
	}
}
