from __future__ import annotations


def extract_packer_features(record: dict[str, object], medium_score: int, high_score: int) -> dict[str, object]:
    indicators: list[str] = []
    if record.get("high_entropy_sections"):
        indicators.append("high_entropy_sections")
    if record.get("suspicious_section_names"):
        indicators.append("suspicious_section_names")
    if int(record.get("imported_api_count", 0)) < 10:
        indicators.append("low_import_count")
    if bool(record.get("has_signature")) is False:
        indicators.append("unsigned_binary")
    score = len(indicators)
    if score >= high_score:
        suspicion = "high"
    elif score >= medium_score:
        suspicion = "medium"
    else:
        suspicion = "low"
    return {
        "possible_packed": suspicion in {"medium", "high"},
        "packer_indicators": indicators,
        "packer_name_guess": "UPX-like" if "suspicious_section_names" in indicators else "unknown",
        "packer_suspicion": suspicion,
    }

