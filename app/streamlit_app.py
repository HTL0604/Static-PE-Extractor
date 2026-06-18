from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import streamlit as st

from app.core.orchestrator import analyze_paths
from app.output.exporter import export_csv, export_json
from app.output.summary import build_summary


RULES_DIR = Path(__file__).resolve().parent / "rules"


def _analyze_upload(uploaded_file: Any, max_file_size_mb: int, extract_strings: bool) -> dict[str, Any]:
    suffix = f"_{uploaded_file.name}" if uploaded_file.name else ""
    with tempfile.NamedTemporaryFile(prefix="pe_upload_", suffix=suffix, delete=False) as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = Path(tmp.name)
    try:
        records = analyze_paths(
            tmp_path,
            recursive=False,
            max_file_size_mb=max_file_size_mb,
            extract_strings=extract_strings,
            rules_dir=RULES_DIR,
        )
        record = records[0] if records else {
            "file_name": uploaded_file.name,
            "file_path": uploaded_file.name,
            "skipped": True,
            "skip_reason": "no_record_created",
            "error": None,
        }
        record["file_name"] = uploaded_file.name
        record["file_path"] = uploaded_file.name
        return record
    finally:
        tmp_path.unlink(missing_ok=True)


def _analyze_uploads(
    uploaded_files: list[Any],
    max_file_size_mb: int,
    extract_strings: bool,
) -> list[dict[str, Any]]:
    return [
        _analyze_upload(uploaded_file, max_file_size_mb, extract_strings)
        for uploaded_file in uploaded_files
    ]


def _compact_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "file_name": record.get("file_name"),
        "pe_type": record.get("pe_type", "-"),
        "architecture": record.get("architecture", "-"),
        "sections": record.get("section_count", 0),
        "imports": record.get("imported_api_count", 0),
        "max_entropy": record.get("max_section_entropy", 0),
        "risk": record.get("risk_level", "-"),
        "risk_score": record.get("risk_score", 0),
        "packed": record.get("possible_packed", False),
        "skipped": record.get("skipped", False),
        "skip_reason": record.get("skip_reason"),
    }


def _json_bytes(records: list[dict[str, Any]]) -> bytes:
    return json.dumps(records, indent=2, ensure_ascii=False).encode("utf-8")


def _csv_bytes(records: list[dict[str, Any]]) -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        export_csv(records, tmp_path)
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


def _persist_outputs(records: list[dict[str, Any]]) -> None:
    export_json(records, Path("output/result.json"))
    export_csv(records, Path("output/result.csv"))


def _render_summary(records: list[dict[str, Any]]) -> None:
    summary = build_summary(records)
    high_risk = sum(1 for r in records if r.get("risk_level") == "high")
    medium_risk = sum(1 for r in records if r.get("risk_level") == "medium")

    cols = st.columns(6)
    cols[0].metric("Total", summary["total"])
    cols[1].metric("Analyzed", summary["analyzed"])
    cols[2].metric("Skipped", summary["skipped"])
    cols[3].metric("EXE / DLL", f"{summary['exe_count']} / {summary['dll_count']}")
    cols[4].metric("Packed", summary["possible_packed_count"])
    cols[5].metric("Risk M/H", f"{medium_risk} / {high_risk}")


def _render_charts(records: list[dict[str, Any]]) -> None:
    analyzed = [r for r in records if not r.get("skipped")]
    if not analyzed:
        st.info("No valid PE files were analyzed.")
        return

    chart_rows = [
        {
            "file": r.get("file_name", ""),
            "imports": int(r.get("imported_api_count", 0) or 0),
            "max_entropy": float(r.get("max_section_entropy", 0) or 0),
            "risk_score": int(r.get("risk_score", 0) or 0),
        }
        for r in analyzed
    ]
    left, right = st.columns(2)
    left.subheader("Imported APIs")
    left.bar_chart(chart_rows, x="file", y="imports", height=260)
    right.subheader("Max Section Entropy")
    right.line_chart(chart_rows, x="file", y="max_entropy", height=260)

    st.subheader("Risk Score")
    st.bar_chart(chart_rows, x="file", y="risk_score", height=260)


def _render_detail(record: dict[str, Any]) -> None:
    st.subheader(record.get("file_name", "Selected record"))
    if record.get("skipped"):
        st.warning(f"Skipped: {record.get('skip_reason')}")
        st.json(record)
        return

    overview, sections, imports, strings, raw = st.tabs(
        ["Overview", "Sections", "Imports", "Strings", "Raw Record"]
    )
    with overview:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Type", record.get("pe_type", "-"))
        c2.metric("Architecture", record.get("architecture", "-"))
        c3.metric("Risk", f"{record.get('risk_level', '-')}".upper())
        c4.metric("Packed", "Yes" if record.get("possible_packed") else "No")
        st.write("**SHA-256**")
        st.code(str(record.get("sha256", "")), language="text")
        st.write("**Risk reasons**")
        st.write(record.get("risk_reasons", []))
        st.write("**Packer indicators**")
        st.write(record.get("packer_indicators", []))

    with sections:
        st.dataframe(record.get("section_details", []), use_container_width=True)

    with imports:
        st.write("**Suspicious imports**")
        st.write(record.get("suspicious_imports", []))
        st.write("**Imported DLLs**")
        st.write(record.get("imported_dll_names", []))
        st.write("**Imported APIs preview**")
        st.write(record.get("imports_preview", []))

    with strings:
        st.write("**URLs**")
        st.write(record.get("url_strings", []))
        st.write("**IPs**")
        st.write(record.get("ip_strings", []))
        st.write("**Registry strings**")
        st.write(record.get("registry_strings", []))
        st.write("**Suspicious strings**")
        st.write(record.get("suspicious_strings", []))

    with raw:
        st.json(record)


def _record_label(record: dict[str, Any], index: int) -> str:
    status = "skipped" if record.get("skipped") else str(record.get("risk_level", "low"))
    return f"{index + 1}. {record.get('file_name', 'unknown')} ({status})"


def main() -> None:
    st.set_page_config(
        page_title="PE Static Extractor",
        page_icon="PE",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.6rem; }
        div[data-testid="stMetric"] {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 14px 16px;
        }
        div[data-testid="stMetric"] label { color: #475569; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("PE Static Extractor")
    st.caption("Static PE feature extraction for EXE/DLL files. Files are parsed only, never executed.")

    with st.sidebar:
        st.header("Input")
        extract_strings = st.checkbox("Extract strings", value=True)
        max_file_size_mb = st.slider("Max file size (MB)", 1, 500, 100)
        save_outputs = st.checkbox("Save to output/result.json and output/result.csv", value=False)
        run = st.button("Analyze", type="primary", use_container_width=True)

    uploaded_files = st.file_uploader(
        "Upload PE files",
        type=["exe", "dll", "sys"],
        accept_multiple_files=True,
        help="Select one or more PE files to analyze.",
    )

    if "records" not in st.session_state:
        st.session_state.records = []

    if run:
        try:
            with st.spinner("Analyzing PE files..."):
                if not uploaded_files:
                    st.warning("Choose at least one PE file before analyzing.")
                    return
                records = _analyze_uploads(uploaded_files, max_file_size_mb, extract_strings)

                if save_outputs:
                    _persist_outputs(records)
                st.session_state.records = records
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")

    records: list[dict[str, Any]] = st.session_state.records
    if not records:
        st.info("Run an analysis from the sidebar to view results.")
        return

    _render_summary(records)

    st.divider()
    st.subheader("Selected File")
    if len(records) == 1:
        selected_index = 0
    else:
        labels = [_record_label(record, index) for index, record in enumerate(records)]
        selected_label = st.selectbox("Choose a file to inspect", labels, index=0)
        selected_index = labels.index(selected_label)
    _render_detail(records[selected_index])

    st.divider()
    st.subheader("Results")
    compact_rows = [_compact_record(r) for r in records]
    st.dataframe(compact_rows, use_container_width=True, hide_index=True)

    left, right = st.columns([1, 1])
    left.download_button(
        "Download JSON",
        data=_json_bytes(records),
        file_name="pe_static_results.json",
        mime="application/json",
        use_container_width=True,
    )
    right.download_button(
        "Download CSV",
        data=_csv_bytes(records),
        file_name="pe_static_results.csv",
        mime="text/csv",
        use_container_width=True,
    )

    st.divider()
    _render_charts(records)


if __name__ == "__main__":
    main()
