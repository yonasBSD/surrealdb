mod convert;

use surrealdb_types::Value;

pub fn encode(v: Value) -> anyhow::Result<Vec<u8>> {
	// Convert public value to internal value for encoding
	let encoding = convert::from_value(v).map_err(|e| anyhow::anyhow!(e))?;
	let mut res = Vec::new();
	//TODO: Check if this can ever panic.
	ciborium::into_writer(&encoding, &mut res).expect("writing to vec should not fail");
	Ok(res)
}

pub fn decode(bytes: &[u8], recursion_limit: usize) -> anyhow::Result<Value> {
	let encoding = ciborium::de::from_reader_with_recursion_limit(bytes, recursion_limit)
		.map_err(|e| anyhow::anyhow!(e.to_string()))?;
	convert::to_value(encoding).map_err(|e| anyhow::anyhow!(e))
}
