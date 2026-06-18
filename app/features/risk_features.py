from __future__ import annotations


def extract_risk_features(record: dict[str, object]) -> dict[str, object]:
    score = 0
    reasons: list[str] = []

    if record.get("has_suspicious_imports"):
        score += 25
        reasons.append("suspicious_imports")

    if record.get("has_high_entropy_section"):
        score += 25
        reasons.append("high_entropy_section")

    if record.get("has_suspicious_section_name"):
        score += 15
        reasons.append("suspicious_section_name")

    if record.get("entry_point_in_suspicious_section"):
        score += 20
        reasons.append("entry_point_in_suspicious_section")

    if record.get("possible_packed"):
        score += 15
        reasons.append("possible_packed")

    if record.get("has_signature") is False:
        score += 10
        reasons.append("unsigned_binary")

    score = min(score, 100)

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_reasons": reasons,
    }
