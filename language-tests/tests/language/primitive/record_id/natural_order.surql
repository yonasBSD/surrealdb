/**
[test]
reason = "Tests `natural order` — the order that record-ids are naturally sorted in. Numerics use the unified disc-10 lex layout so byte order across mixed numeric variants matches `Number::cmp`. Numerics sort AFTER strings/uuids/arrays/objects because disc 10 > disc 3..6, aligning with the derived `Ord` on `RecordIdKey` where `Number` is the last enum variant. The two `±100000000000000000000` ids overflow `i64`, so they parse as STRING record-ids and live in the string range (disc 3)."

[[test.results]]
value = "'OK'"

[[test.results]]
value = "[{ id: test:`-100000000000000000000` }, { id: test:`100000000000000000000` }, { id: test:A }, { id: test:Z }, { id: test:a }, { id: test:z }, { id: test:u'00000000-0000-0000-0000-000000000000' }, { id: test:u'ffffffff-ffff-ffff-ffff-ffffffffffff' }, { id: test:[NONE] }, { id: test:[NULL] }, { id: test:[1, 2, 3] }, { id: test:['a'] }, { id: test:{ a: NONE } }, { id: test:{ a: NULL } }, { id: test:{ a: 1 } }, { id: test:{ a: 'a' } }, { id: test:{ z: NONE } }, { id: test:{ z: NULL } }, { id: test:{ z: 1 } }, { id: test:{ z: 'a' } }, { id: test:-1000000 }, { id: test:-1 }, { id: test:1 }, { id: test:1000000 }]"

*/

{
    create test:1;
    create test:1000000;
    create test:A;
    create test:Z;
    create test:a;
    create test:z;
    create test:-1;
    create test:-1000000;
    create test:-100000000000000000000;
    create test:100000000000000000000;
    create test:[1,2,3];
    create test:["a"];
    create test:[NULL];
    create test:[NONE];
    create test:{a: 1};
    create test:{a: "a"};
    create test:{a: NULL};
    create test:{a: NONE};
    create test:{z: 1};
    create test:{z: "a"};
    create test:{z: NULL};
    create test:{z: NONE};
    create test:u"00000000-0000-0000-0000-000000000000";
    create test:u"ffffffff-ffff-ffff-ffff-ffffffffffff";

    RETURN "OK";
};

SELECT * FROM test;
