import csv, json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
rows = list(csv.DictReader((root/"output.csv").open(encoding="utf-8")))
assert len(rows) == 518
assert set(rows[0]) == {"case_id","deletion_status","steps_json"}
allowed = {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}
for row in rows:
    assert row["deletion_status"] in allowed
    steps = json.loads(row["steps_json"])
    assert [x["step_no"] for x in steps] == list(range(1, len(steps)+1))
    for x in steps:
        assert set(x) == {"step_no","phase","system_id","resource_id","operation","state","evidence_id"}
print("Structural validation passed:", len(rows), "rows")
