# pe_static_extractor_project

Clean-architecture Python project for static PE feature extraction (`.exe`/`.dll`) without executing binaries.

## Security Warning

This project is for **static malware analysis** only. Never execute unknown samples. Run analysis in an isolated environment.

## Features

- CLI batch/file analysis.
- Flask web dashboard.
- JSON + CSV export.
- Markdown report snippets generator.
- Modular feature extractors (file/header/section/import/export/strings/resource/signature/derived/packer).

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run CLI

```bash
python -m app.cli --input samples --recursive
```

Options:

- `--input` required (file or folder)
- `--json` default `output/result.json`
- `--csv` default `output/result.csv`
- `--recursive` recursive folder scan
- `--max-file-size-mb` default `100`
- `--no-strings` disable string extraction
- `--log-level` `INFO|DEBUG|WARNING|ERROR`

## Run Web

```bash
python -m app.web.app
```

- Upload size limit: 50MB.
- Debug mode is disabled by default.
- Uploaded files are sanitized and cleaned up after analysis.
- Input path is validated to stay inside configured workspace root (`WORKSPACE_ROOT` env var).

## Run Streamlit Dashboard

```bash
streamlit run app/streamlit_app.py
```

If you are using the local virtual environment without activating it:

```bash
.\.venv\Scripts\python.exe -m streamlit run app/streamlit_app.py
```

The Streamlit dashboard provides a richer interactive UI with multi-file PE
upload, summary metrics, charts, record drill-down tabs, and JSON/CSV downloads.

## Generate Report Snippets

```bash
python -m app.report.generate_snippets --input output/result.json --output output/report_snippets.md
```

Generated sections:

- Feature table markdown
- Experimental results markdown
- Summary markdown
- Commentary markdown (data-driven)

## Example

```bash
python -m app.cli --input samples --recursive --json output/result.json --csv output/result.csv
python -m app.report.generate_snippets --input output/result.json --output output/report_snippets.md
```

## Limitations

- Signature check is presence heuristic (certificate table), not full trust validation.
- Packer detection is heuristic scoring and may produce false positives/negatives.
- String extraction uses regex-based scanning and previews only.

## Changelog (vs original)

- Added `--recursive`.
- Added max file size guard and `--no-strings`.
- Commentary report is fully data-driven.
- Replaced global web state with ID-based in-memory TTL store.
- `is_pe32_plus` now derives from Optional Header Magic (`0x20B`).
- Packer logic upgraded to scoring with `low/medium/high` suspicion while preserving `possible_packed`.
- CSV exporter now builds stable schema from union of keys.

