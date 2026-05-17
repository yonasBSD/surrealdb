/**
[test]
reason = "NaN and ±Infinity are not valid record-id keys; INSERT must error rather than silently accept them. NaN-as-id would break Eq/Hash invariants on the record key."

[[test.results]]
match = "$error = /property 'id' is: NaN/"
error = true

[[test.results]]
match = "$error = /property 'id' is: Infinity/"
error = true

[[test.results]]
match = "$error = /property 'id' is: -Infinity/"
error = true

*/
-- NaN, +Inf, -Inf must be rejected as record-id keys.
INSERT INTO t { id: NaN, name: 'should-fail' };
INSERT INTO t { id: Infinity, name: 'should-fail' };
INSERT INTO t { id: -Infinity, name: 'should-fail' };
