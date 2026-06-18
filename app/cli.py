from __future__ import annotations

import argparse
from pathlib import Path

from app.core import analyze_paths
from app.logging_config import configure_logging
from app.output.exporter import export_csv, export_json
from app.output.presenter import format_terminal_summary
from app.output.summary import build_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="pe_static_extractor_project")
    parser.add_argument("--input", required=True, help="Input file or folder path")
    parser.add_argument("--json", default="output/result.json", help="JSON output path")
    parser.add_argument("--csv", default="output/result.csv", help="CSV output path")
    parser.add_argument("--recursive", action="store_true", help="Scan folders recursively")
    parser.add_argument("--max-file-size-mb", type=int, default=100)
    parser.add_argument("--no-strings", action="store_true", help="Disable string extraction")
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO"
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    configure_logging(args.log_level)
    base = Path(__file__).resolve().parent
    records = analyze_paths(
        Path(args.input),
        recursive=args.recursive,
        max_file_size_mb=args.max_file_size_mb,
        extract_strings=not args.no_strings,
        rules_dir=base / "rules",
    )
    export_json(records, Path(args.json))
    export_csv(records, Path(args.csv))
    summary = build_summary(records)
    print(format_terminal_summary(summary))
    print(f"JSON: {args.json}")
    print(f"CSV: {args.csv}")


if __name__ == "__main__":
    main()

