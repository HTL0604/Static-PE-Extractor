from __future__ import annotations

from pathlib import Path


def scan_input_paths(input_path: Path, recursive: bool) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if not input_path.is_dir():
        return []
    pattern = "**/*" if recursive else "*"
    return [p for p in input_path.glob(pattern) if p.is_file()]

