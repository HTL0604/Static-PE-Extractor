from __future__ import annotations

import logging
from pathlib import Path

from app.core.parser import load_rules, parse_pe_file
from app.core.scanner import scan_input_paths
from app.models import ExtractionRecord

LOGGER = logging.getLogger(__name__)


def analyze_paths(
    input_path: Path,
    *,
    recursive: bool,
    max_file_size_mb: int,
    extract_strings: bool,
    rules_dir: Path,
) -> list[ExtractionRecord]:
    candidates = scan_input_paths(input_path, recursive)
    rules = load_rules(rules_dir)
    records: list[ExtractionRecord] = []
    max_bytes = max_file_size_mb * 1024 * 1024
    for file_path in candidates:
        record = parse_pe_file(
            file_path,
            max_file_size_bytes=max_bytes,
            extract_strings=extract_strings,
            rules=rules,
        )
        if record.get("skipped"):
            LOGGER.warning("Skipped %s: %s", file_path, record.get("skip_reason"))
        records.append(record)
    return records

