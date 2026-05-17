/**
[test]
reason = "INSERT INTO t { id: 1.5, ... } previously silently truncated 1.5 → 1. The record id must preserve the float verbatim. Cross-variant equality means `t:1`, `t:1.0`, and `t:1.0dec` all collapse to the same canonical on-disk key, so subsequent inserts with numerically-equal IDs error as `already exists`."

[[test.results]]
match = "$result[0].name = 'half'"

[[test.results]]
match = "$result[0].name = 'whole'"

[[test.results]]
match = "$error = /already exists/"
error = true

[[test.results]]
match = "$error = /already exists/"
error = true

[[test.results]]
match = "array::len($result) = 2 AND $result[0].name = 'whole' AND $result[1].name = 'half'"

*/
-- The original bug: 1.5 must not be truncated to 1.
INSERT INTO t { id: 1.5, name: 'half' };

-- Integer id (canonical Int slot).
INSERT INTO t { id: 1, name: 'whole' };

-- These canonicalize to the same on-disk key as t:1 and must fail with
-- "already exists" rather than silently overwriting or creating duplicates.
INSERT INTO t { id: 1.0, name: 'whole-as-float' };
INSERT INTO t { id: 1.0dec, name: 'whole-as-decimal' };

-- Final state: two rows. Int variant (t:1) sorts before Float variant (t:1.5f).
SELECT * FROM t ORDER BY id;
