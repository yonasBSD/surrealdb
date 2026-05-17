/**
[test]
reason = "Round-trip the canonical `to_sql()` form of a float / decimal record-id key through the language-test framework's `value =` deserializer. Running `--results accept` against a query that returns records with non-integer numeric IDs writes lines such as `[{ id: a:1.5f, name: 'create-float' }]` — the `f` and `dec` suffixes come from `Number::Float` / `Number::Decimal` `ToSql` impls. Before this fix the next load of the same file failed with `Parse error: Unexpected token \\\".\\\" expected delimiter \\\"}\\\"` because `parse_value_record_id_inner` only consumed the leading integer of `1.5f` and left `.5f` lingering. The fix teaches the value parser to accept `<digits>[.<digits>](f|dec)` as a record-id key in flexible-record-id mode."

[[test.results]]
value = "[{ id: a:1.5f, name: 'create-float' }]"

[[test.results]]
value = "[{ id: a:0.1dec, name: 'create-decimal' }]"

[[test.results]]
value = "[{ count: 2 }]"

*/

-- Float record-id (1.5 stays as Float on disk — `fract != 0`, so the
-- encode-time canonicalizer doesn't collapse it to Int).
SELECT * FROM (CREATE a:1.5 SET name = 'create-float');

-- Decimal record-id (0.1 isn't bit-exactly representable as f64, so the
-- canonicalizer keeps it in the Decimal slot rather than promoting to Float).
SELECT * FROM (CREATE a SET id = 0.1dec, name = 'create-decimal');

-- Confirm both rows landed; the `value =` lines above are what exercise the
-- parser fix at config-load time.
SELECT count() AS count FROM a GROUP ALL;
