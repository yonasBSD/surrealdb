/**
[test]

[[test.results]]
value = "[{ id: person:100, test: 'One' }]"

[[test.results]]
error = "Database record `person:100` already exists"

[[test.results]]
error = "Database record `person:100` already exists"

[[test.results]]
error = "Database record `person:100` already exists"

[[test.results]]
value = "[{ id: person:`100`, test: 'Two' }]"

[[test.results]]
error = "Database record `person:`100`` already exists"

[[test.results]]
# String id (disc 3) sorts before Number id (disc 10) in storage byte order.
value = "[{ id: person:`100`, test: 'Two' }, { id: person:100, test: 'One' }]"

*/

CREATE person:100 SET test = 'One';
CREATE person:00100;
CREATE r'person:100';
CREATE r"person:100";
CREATE person:⟨100⟩ SET test = 'Two';
CREATE person:`100`;
SELECT * FROM person;
