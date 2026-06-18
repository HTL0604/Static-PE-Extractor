from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def export_json(records: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")


def export_csv(records: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    keys: set[str] = set()
    for rec in records:
        keys.update(rec.keys())
    ordered_keys = sorted(keys)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_keys)
        writer.writeheader()
        for rec in records:
            normalized = {
                k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
                for k, v in rec.items()
            }
            writer.writerow(normalized)

