from __future__ import annotations

from typing import Any


def build_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    analyzed = [r for r in records if not r.get("skipped")]
    return {
        "total": len(records),
        "analyzed": len(analyzed),
        "skipped": len(records) - len(analyzed),
        "exe_count": sum(1 for r in analyzed if r.get("pe_type") == "EXE"),
        "dll_count": sum(1 for r in analyzed if r.get("pe_type") == "DLL"),
        "possible_packed_count": sum(1 for r in analyzed if r.get("possible_packed")),
    }

