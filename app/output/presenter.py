from __future__ import annotations

from typing import Any


def format_terminal_summary(summary: dict[str, Any]) -> str:
    return (
        "Analysis Summary\n"
        f"- Total files scanned: {summary['total']}\n"
        f"- Successfully analyzed: {summary['analyzed']}\n"
        f"- Skipped: {summary['skipped']}\n"
        f"- EXE: {summary['exe_count']} | DLL: {summary['dll_count']}\n"
        f"- Possible packed: {summary['possible_packed_count']}"
    )

