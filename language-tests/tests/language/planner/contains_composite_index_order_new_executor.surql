/**
[env]
planner-strategy = ["all-ro"]

[test]
reason = "CONTAINS / INSIDE on the leading array-element column of a compound index must produce an IndexScan with a Compound prefix, so that index_covers_ordering can supply ORDER BY + LIMIT pushdown via a directional walk of the prefix-bounded range. Previously the analyser rejected composite indexes for containment predicates and fell back to TableScan."

[[test.results]]
value = "NONE"

[[test.results]]
value = "[{ age: 90, id: record:5 }, { age: 50, id: record:2 }]"

[[test.results]]
value = '''"SelectProject [ctx: Db] [projections: id, age] {rows: 2}\n    IndexScan [ctx: Db] [index: tag_age, access: ['omicron'], direction: Backward, limit: 2] {rows: 2}\n\nTotal rows: 2"'''

[[test.results]]
value = "[{ age: 10, id: record:6 }, { age: 20, id: record:1 }]"

[[test.results]]
value = '''"SelectProject [ctx: Db] [projections: id, age] {rows: 2}\n    IndexScan [ctx: Db] [index: tag_age, access: ['omicron'], direction: Forward, limit: 2] {rows: 2}\n\nTotal rows: 2"'''

[[test.results]]
value = "NONE"

[[test.results]]
value = "[{ age: 10, id: entry:3, score: 99 }, { age: 20, id: entry:2, score: 30 }, { age: 20, id: entry:1, score: 50 }]"

[[test.results]]
value = '''"SelectProject [ctx: Db] [projections: id, age, score] {rows: 3}\n    IndexScan [ctx: Db] [index: tag_age_score, access: ['omicron'], direction: Forward, limit: 3] {rows: 3}\n\nTotal rows: 3"'''

[[test.results]]
value = "[{ age: 30, id: entry:4, score: 70 }, { age: 20, id: entry:1, score: 50 }, { age: 20, id: entry:2, score: 30 }]"

[[test.results]]
value = '''"SelectProject [ctx: Db] [projections: id, age, score] {rows: 3}\n    IndexScan [ctx: Db] [index: tag_age_score, access: ['omicron'], direction: Backward, limit: 3] {rows: 3}\n\nTotal rows: 3"'''
*/

-- Setup: composite index whose leading column is an array-element flatten.
{
    DEFINE TABLE OVERWRITE record SCHEMALESS;
    DEFINE INDEX OVERWRITE tag_age ON record FIELDS tags.*, age;
    CREATE record:1 SET tags = ['alpha', 'omicron'], age = 20;
    CREATE record:2 SET tags = ['omicron', 'beta'], age = 50;
    CREATE record:3 SET tags = ['gamma'], age = 70;
    CREATE record:4 SET tags = ['omicron', 'delta'], age = 30;
    CREATE record:5 SET tags = ['omicron'], age = 90;
    CREATE record:6 SET tags = ['omicron', 'epsilon'], age = 10;
    RETURN NONE;
};

-- Case A: CONTAINS + ORDER BY trailing column DESC + LIMIT.
-- Expected top-2 omicron rows by age DESC: record:5 (90), record:2 (50).
SELECT id, age FROM record WHERE tags CONTAINS 'omicron' ORDER BY age DESC LIMIT 2;
EXPLAIN ANALYZE SELECT id, age FROM record WHERE tags CONTAINS 'omicron' ORDER BY age DESC LIMIT 2;

-- Case B: INSIDE on right-side idiom + ORDER BY ASC + LIMIT.
-- Expected bottom-2: record:6 (10), record:1 (20).
SELECT id, age FROM record WHERE 'omicron' INSIDE tags ORDER BY age ASC LIMIT 2;
EXPLAIN ANALYZE SELECT id, age FROM record WHERE 'omicron' INSIDE tags ORDER BY age ASC LIMIT 2;

-- Cases C / D: three-column composite index. Two trailing columns (`age`,
-- `score`) must both be covered by ORDER BY for the directional walk to
-- preserve ordering. This pins down `index_covers_ordering`'s
-- multi-trailing-column path for the containment-prefix shape.
{
    DEFINE TABLE OVERWRITE entry SCHEMALESS;
    DEFINE INDEX OVERWRITE tag_age_score ON entry FIELDS tags.*, age, score;
    CREATE entry:1 SET tags = ['omicron'], age = 20, score = 50;
    CREATE entry:2 SET tags = ['omicron'], age = 20, score = 30;
    CREATE entry:3 SET tags = ['omicron'], age = 10, score = 99;
    CREATE entry:4 SET tags = ['omicron'], age = 30, score = 70;
    CREATE entry:5 SET tags = ['other'],   age = 99, score = 99;
    RETURN NONE;
};

-- Case C: CONTAINS + ORDER BY two trailing columns ASC + LIMIT (Forward walk).
-- Expected order by (age ASC, score ASC): entry:3 (10, 99), entry:2 (20, 30),
-- entry:1 (20, 50).
SELECT id, age, score FROM entry
    WHERE tags CONTAINS 'omicron'
    ORDER BY age ASC, score ASC LIMIT 3;
EXPLAIN ANALYZE SELECT id, age, score FROM entry
    WHERE tags CONTAINS 'omicron'
    ORDER BY age ASC, score ASC LIMIT 3;

-- Case D: same index, both trailing columns DESC + LIMIT (Backward walk).
-- Expected order by (age DESC, score DESC): entry:4 (30, 70), entry:1 (20, 50),
-- entry:2 (20, 30).
SELECT id, age, score FROM entry
    WHERE tags CONTAINS 'omicron'
    ORDER BY age DESC, score DESC LIMIT 3;
EXPLAIN ANALYZE SELECT id, age, score FROM entry
    WHERE tags CONTAINS 'omicron'
    ORDER BY age DESC, score DESC LIMIT 3;
