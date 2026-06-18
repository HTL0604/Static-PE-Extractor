import csv
from pathlib import Path

from app.output.exporter import export_csv


def test_export_csv_uses_union_keys(tmp_path: Path) -> None:
    out = tmp_path / "out.csv"
    export_csv([{"a": 1}, {"b": 2}], out)
    with out.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert "a" in rows[0]
    assert "b" in rows[0]

