/**
[env]
imports = ["upgrade/define/relation_numeric_import.surql"]

[test]
upgrade = true
reason = "RELATION-typed table with numeric record IDs at both endpoints and the edge survives upgrade — exercises rev-1 → rev-2 RecordIdKey migration in non-id positions (in/out fields, graph traversal pointers) which other relation/reference upgrade tests miss because they use string identifiers"

[[test.results]]
match = '''
    string::contains($result.tables.follows, "DEFINE TABLE follows TYPE RELATION")
    && string::contains($result.tables.follows, "IN usr")
    && string::contains($result.tables.follows, "OUT usr")
'''

[[test.results]]
value = "[{ id: follows:101, in: usr:1, out: usr:2, since: d'2025-01-01T00:00:00Z' }, { id: follows:102, in: usr:2, out: usr:3, since: d'2025-02-01T00:00:00Z' }]"

[[test.results]]
value = "[{ followed: [usr:2], id: usr:1 }, { followed: [usr:3], id: usr:2 }, { followed: [], id: usr:3 }]"

*/
INFO FOR DB;
SELECT * FROM follows ORDER BY id;
SELECT id, ->follows->usr AS followed FROM usr ORDER BY id;
