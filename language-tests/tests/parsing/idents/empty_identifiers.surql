/**
[env]
clean = true

[test]

[[test.results]]
value = "NONE"

[[test.results]]
value = "NONE"

[[test.results]]
value = "{ database: '', namespace: '' }"

[[test.results]]
value = "NONE"

[[test.results]]
value = "NONE"

[[test.results]]
value = '''{ accesses: {  }, databases: { "": 'DEFINE DATABASE ``' }, users: {  } }'''

[[test.results]]
value = '''{ accesses: {  }, analyzers: {  }, apis: {  }, buckets: {  }, configs: {  }, functions: {  }, models: {  }, modules: {  }, params: {  }, sequences: {  }, tables: { "": 'DEFINE TABLE `` TYPE NORMAL SCHEMAFULL PERMISSIONS NONE' }, users: {  } }'''

[[test.results]]
value = '''{ events: {  }, fields: { "``.``": 'DEFINE FIELD ``.`` ON `` TYPE number PERMISSIONS FULL' }, indexes: {  }, lives: {  }, tables: {  } }'''

[[test.results]]
value = "[{ ``: { ``: 1 }, id: ``:1 }]"

[[test.results]]
value = "[{ ``: { ``: 2 }, id: ``:2 }]"

[[test.results]]
value = "[{ ``: { ``: 3 }, id: ``:`` }]"

[[test.results]]
# Numeric record-ids encode under disc 10; String record-ids under disc 3.
# Storage byte order is therefore: String first, then Numbers.
value = "[{ ``: { ``: 3 }, id: ``:`` }, { ``: { ``: 1 }, id: ``:1 }, { ``: { ``: 2 }, id: ``:2 }]"

*/

DEFINE NAMESPACE ``;
DEFINE DATABASE ``;

USE NS `` DB ``;

DEFINE TABLE `` SCHEMAFULL;

DEFINE FIELD ``.`` ON `` TYPE number;

INFO FOR NAMESPACE;
INFO FOR DATABASE;
INFO FOR TB ``;

CREATE ``:1 SET `` = { "": 1 };
CREATE ``:2 SET `` = { "": 2 };
CREATE ``:`` SET `` = { "": 3 };

SELECT * FROM ``;
