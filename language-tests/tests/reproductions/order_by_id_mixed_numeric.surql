/**
[test]
reason = "ORDER BY id over a table with mixed numeric record-id variants (Int, Float, integer-valued Decimal canonicalized → Int) must produce numeric order across all planner strategies. Storage byte-order disagrees with numeric order because the canonical RecordIdKey encoding prefixes a type-discriminant byte (Int=2, Float=8, Decimal=9), so a Sort operator that's eliminated by trusting iterator order returns a different sequence than the in-memory compute path."

# 1) CREATE a:2 -> 'create-int'
[[test.results]]
value = "[{ id: a:2, name: 'create-int' }]"

# 2) CREATE a:1.5 -> 'create-float'
[[test.results]]
match = "$result = [{ id: a:1.5, name: 'create-float' }]"

# 3) CREATE a SET id = 3dec, name = 'create-decimal'
# Decimal(3) is integer-valued and canonicalizes to Int(3); the
# returned `id` value reflects the on-disk variant.
[[test.results]]
match = "$result = [{ id: a:3, name: 'create-decimal' }]"

# 4) SELECT * FROM a ORDER BY id ASC — must produce numeric order:
#    Float(1.5) < Int(2) < Int(3), i.e. [a:1.5, a:2, a:3].
[[test.results]]
match = "$result = [{ id: a:1.5, name: 'create-float' }, { id: a:2, name: 'create-int' }, { id: a:3, name: 'create-decimal' }]"

# 5) SELECT * FROM a ORDER BY id DESC — reverse of the above.
[[test.results]]
match = "$result = [{ id: a:3, name: 'create-decimal' }, { id: a:2, name: 'create-int' }, { id: a:1.5, name: 'create-float' }]"
*/

CREATE a:2 SET name = 'create-int';
CREATE a:1.5 SET name = 'create-float';
CREATE a SET id = 3dec, name = 'create-decimal';

SELECT * FROM a ORDER BY id ASC;
SELECT * FROM a ORDER BY id DESC;
