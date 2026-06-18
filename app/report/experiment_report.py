from __future__ import annotations

from typing import Any


def build_experiment_markdown(records: list[dict[str, Any]]) -> str:
    analyzed = [r for r in records if not r.get("skipped")]
    max_entropy = max((float(r.get("max_section_entropy", 0.0)) for r in analyzed), default=0.0)
    avg_imports = (
        sum(int(r.get("imported_api_count", 0)) for r in analyzed) / len(analyzed)
        if analyzed
        else 0.0
    )
    return (
        "## Experimental Results\n\n"
        f"- Total analyzed files: **{len(analyzed)}**\n"
        f"- Average imported APIs per file: **{avg_imports:.2f}**\n"
        f"- Maximum observed section entropy: **{max_entropy:.3f}**\n"
    )


def build_commentary_markdown(records: list[dict[str, Any]]) -> str:
    analyzed = [r for r in records if not r.get("skipped")]
    if not analyzed:
        return "## Commentary\n\nNo valid PE files were analyzed, so no behavioral observation can be made."
    packed_ratio = sum(1 for r in analyzed if r.get("possible_packed")) / len(analyzed)
    suspicious_import_ratio = sum(1 for r in analyzed if r.get("has_suspicious_imports")) / len(
        analyzed
    )
    entropy_outliers = [
        r["file_name"]
        for r in analyzed
        if float(r.get("max_section_entropy", 0.0)) >= 7.5
    ][:10]
    lines = ["## Commentary", ""]
    lines.append(
        f"- {packed_ratio:.1%} samples are flagged as potentially packed based on combined indicators."
    )
    lines.append(
        f"- {suspicious_import_ratio:.1%} samples expose suspicious API imports that may imply process injection/download behavior."
    )
    if entropy_outliers:
        lines.append(
            f"- High-entropy outliers detected in: {', '.join(entropy_outliers)}."
        )
    else:
        lines.append("- No major high-entropy outliers were detected in this run.")
    return "\n".join(lines)

