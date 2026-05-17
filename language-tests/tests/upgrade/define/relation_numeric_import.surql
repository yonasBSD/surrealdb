/**
[test]

[[test.results]]
value = "NONE"

[[test.results]]
value = "NONE"

[[test.results]]
value = "[{ id: usr:1 }]"

[[test.results]]
value = "[{ id: usr:2 }]"

[[test.results]]
value = "[{ id: usr:3 }]"

[[test.results]]
value = "[{ id: follows:101, in: usr:1, out: usr:2, since: d'2025-01-01T00:00:00Z' }]"

[[test.results]]
value = "[{ id: follows:102, in: usr:2, out: usr:3, since: d'2025-02-01T00:00:00Z' }]"

*/
DEFINE TABLE usr SCHEMALESS;
DEFINE TABLE follows TYPE RELATION FROM usr TO usr SCHEMALESS;
CREATE usr:1;
CREATE usr:2;
CREATE usr:3;
RELATE usr:1 -> follows:101 -> usr:2 SET since = d'2025-01-01T00:00:00Z';
RELATE usr:2 -> follows:102 -> usr:3 SET since = d'2025-02-01T00:00:00Z';
