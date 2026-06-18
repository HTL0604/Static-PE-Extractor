from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

import pefile

from app.features import (
    extract_derived_features,
    extract_export_features,
    extract_file_features,
    extract_header_features,
    extract_import_features,
    extract_packer_features,
    extract_resource_features,
    extract_risk_features,
    extract_section_features,
    extract_signature_features,
    extract_string_features,
)
from app.models import ExtractionRecord

LOGGER = logging.getLogger(__name__)


def load_rules(rules_dir: Path) -> dict[str, Any]:
    def _read(name: str) -> dict[str, Any]:
        return json.loads((rules_dir / name).read_text(encoding="utf-8"))

    return {
        "suspicious_apis": set(_read("suspicious_apis.json").get("apis", [])),
        "packer_section_names": {
            n.lower() for n in _read("packer_section_names.json").get("names", [])
        },
        "thresholds": _read("thresholds.json"),
    }


def parse_pe_file(
    file_path: Path,
    *,
    max_file_size_bytes: int,
    extract_strings: bool,
    rules: dict[str, Any],
) -> ExtractionRecord:
    record: ExtractionRecord = {
        "record_id": uuid.uuid4().hex,
        "file_path": str(file_path),
        "file_name": file_path.name,
        "skipped": False,
        "skip_reason": None,
        "error": None,
    }

    if not file_path.exists() or not file_path.is_file():
        record["skipped"] = True
        record["skip_reason"] = "path_not_file"
        return record

    if file_path.stat().st_size > max_file_size_bytes:
        record["skipped"] = True
        record["skip_reason"] = "file_too_large"
        return record

    try:
        data = file_path.read_bytes()
        pe = pefile.PE(data=data, fast_load=False)
        pe.parse_data_directories()
    except Exception as exc:
        LOGGER.warning("Skip invalid PE %s: %s", file_path, exc)
        record["skipped"] = True
        record["skip_reason"] = f"invalid_pe:{exc}"
        return record

    try:
        record.update(extract_file_features(file_path, data))
        record.update(extract_header_features(pe))

        record["optional_magic"] = int(pe.OPTIONAL_HEADER.Magic)

        record.update(
            extract_section_features(
                pe,
                high_entropy_threshold=float(
                    rules["thresholds"].get("high_entropy_threshold", 7.2)
                ),
                suspicious_names=set(rules["packer_section_names"]),
            )
        )

        record.update(extract_import_features(pe, set(rules["suspicious_apis"])))
        record.update(extract_export_features(pe))
        record.update(extract_resource_features(pe))
        record.update(extract_signature_features(pe))

        if extract_strings:
            record.update(
                extract_string_features(
                    data,
                    int(rules["thresholds"].get("string_preview_limit", 10)),
                )
            )
        else:
            record.update(extract_string_features(b"", 0))

        record.update(
            extract_derived_features(
                record,
                int(rules["thresholds"].get("api_preview_limit", 20)),
                int(rules["thresholds"].get("string_preview_limit", 10)),
            )
        )

        record.update(
            extract_packer_features(
                record,
                int(rules["thresholds"].get("packer_score_medium", 2)),
                int(rules["thresholds"].get("packer_score_high", 4)),
            )
        )

        record.update(extract_risk_features(record))

    except Exception as exc:
        LOGGER.exception("Feature extraction failed for %s", file_path)
        record["error"] = f"extract_error:{exc}"

    finally:
        pe.close()

    return record
