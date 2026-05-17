/**
[test]
reason = "INSERT, CREATE, UPDATE, UPSERT must all canonicalize numeric record-ids identically. Float-literal targets `thing:1.5` work in the default (flexible) parser; integer and decimal record-ids work via both literal and value forms; cross-variant canonicalization (`t:1`, `t:1.0`, `t:1.0dec`) collapses to the same on-disk key regardless of which statement created them; NaN/±∞ are rejected uniformly across statements."

# --- 1. CREATE with literal int / float targets + value-form decimal ---
# Note: the `value =` literal parser (core's parse_value_record_id_inner)
# only accepts integer record-id keys, so float/decimal ids are asserted
# via full-equality `match` expressions — `match` is executed as a RETURN
# query, whose statement parser does accept float/decimal record-id keys.
[[test.results]]
value = "[{ id: a:2, name: 'create-int' }]"

[[test.results]]
match = "$result = [{ id: a:1.5, name: 'create-float' }]"

[[test.results]]
match = "$result = [{ id: a:3, name: 'create-decimal' }]"

[[test.results]]
# ORDER BY id over mixed canonical Number variants must now produce numeric
# order in every executor mode: Float(1.5) < Int(2) < Decimal(3)(==Int(3)).
match = "$result = [{ id: a:1.5, name: 'create-float' }, { id: a:2, name: 'create-int' }, { id: a:3, name: 'create-decimal' }]"

# --- 2. INSERT INTO ... { id: ... } cross-variant collapse ---
[[test.results]]
match = "$result = [{ id: b:1.5, name: 'insert-float' }]"

[[test.results]]
value = "[{ id: b:1, name: 'insert-int' }]"

[[test.results]]
match = "$error = /already exists/"
error = true

[[test.results]]
match = "$error = /already exists/"
error = true

[[test.results]]
match = "$result = [{ id: b:1.5, name: 'insert-float' }, { id: b:1, name: 'insert-int' }]"

# --- 3. UPSERT thing:<float> SET ... ---
[[test.results]]
match = "$result = [{ count: 1, id: c:1.5 }]"

[[test.results]]
match = "$result = [{ count: 2, id: c:1.5 }]"

[[test.results]]
match = "$result = [{ count: 2, id: c:1.5 }]"

# --- 4. UPDATE thing:<float> ---
[[test.results]]
match = "$result = [{ count: 99, id: c:1.5 }]"

[[test.results]]
match = "$result = [{ count: 99, id: c:1.5 }]"

# --- 5. NaN / ±Infinity rejection — uniform across statements ---
[[test.results]]
match = "$error = /NaN/"
error = true

[[test.results]]
match = "$error = /Infinity/"
error = true

[[test.results]]
match = "$error = /Infinity/"
error = true

*/

-- 1) CREATE: integer + float literal targets work in flexible parser mode;
--    decimal literal id requires the value-form `SET id = 3dec`.
-- ORDER BY id now produces numeric order across all executor modes because
-- `RecordIdKey::Number` is encoded under a single discriminant with a
-- lex-sortable payload (`Number::as_decimal_buf`) so storage byte order
-- matches `Number::cmp`.
CREATE a:2 SET name = 'create-int';
CREATE a:1.5 SET name = 'create-float';
CREATE a SET id = 3dec, name = 'create-decimal';
SELECT * FROM a ORDER BY id;

-- 2) INSERT INTO with object-form ids — cross-variant canonicalization
INSERT INTO b { id: 1.5, name: 'insert-float' };
INSERT INTO b { id: 1, name: 'insert-int' };
INSERT INTO b { id: 1.0, name: 'duplicate-of-1-float' };  -- canonicalizes → already exists
INSERT INTO b { id: 1.0dec, name: 'duplicate-of-1-dec' }; -- canonicalizes → already exists
SELECT * FROM b ORDER BY name;

-- 3) UPSERT with float literal target — second upsert hits the same row
UPSERT c:1.5 SET count = 1;
UPSERT c:1.5 SET count = 2;
SELECT * FROM c;

-- 4) UPDATE on the same record by literal float target
UPDATE c:1.5 SET count = 99;
SELECT * FROM c;

-- 5) NaN / Infinity rejected on every numeric construction path
INSERT INTO nan_test { id: NaN, name: 'fail' };
CREATE crash SET id = Infinity, name = 'fail';
UPSERT crash2 SET id = -Infinity, name = 'fail';
