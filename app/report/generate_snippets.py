from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.output.summary import build_summary
from app.report.experiment_report import build_commentary_markdown, build_experiment_markdown
from app.report.feature_table import build_feature_table_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate markdown snippets from result JSON")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    records = json.loads(Path(args.input).read_text(encoding="utf-8"))
    summary = build_summary(records)
    summary_md = (
        "## Summary\n\n"
        f"- Total: **{summary['total']}**\n"
        f"- Analyzed: **{summary['analyzed']}**\n"
        f"- Skipped: **{summary['skipped']}**\n"
        f"- EXE/DLL: **{summary['exe_count']} / {summary['dll_count']}**\n"
    )
    output = "\n\n".join(
        [
            build_feature_table_markdown(records),
            build_experiment_markdown(records),
            summary_md,
            build_commentary_markdown(records),
        ]
    )
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")
    print(f"Markdown snippets written to {args.output}")


if __name__ == "__main__":
    main()

