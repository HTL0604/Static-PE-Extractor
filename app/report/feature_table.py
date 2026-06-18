from __future__ import annotations

from typing import Any


def build_feature_table_markdown(records: list[dict[str, Any]]) -> str:
    if not records:
        return "## Feature Table\n\nNo records."
    keys = sorted({k for r in records for k in r.keys()})
    lines = ["## Feature Table", "", "| Feature | Available |", "|---|---|"]
    for key in keys:
        available = sum(1 for r in records if key in r and r.get(key) not in (None, [], ""))
        lines.append(f"| `{key}` | {available}/{len(records)} |")
    return "\n".join(lines)

