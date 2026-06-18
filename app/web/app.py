from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flask import Flask, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from app.core.orchestrator import analyze_paths
from app.output.summary import build_summary


@dataclass
class RecordStore:
    ttl_seconds: int = 1800
    data: dict[str, tuple[float, dict[str, Any]]] = field(default_factory=dict)

    def put(self, record: dict[str, Any]) -> None:
        self.data[record["record_id"]] = (time.time(), record)
        self.cleanup()

    def get(self, record_id: str) -> dict[str, Any] | None:
        self.cleanup()
        value = self.data.get(record_id)
        return value[1] if value else None

    def all_records(self) -> list[dict[str, Any]]:
        self.cleanup()
        return [v[1] for v in self.data.values()]

    def cleanup(self) -> None:
        now = time.time()
        self.data = {
            rid: item for rid, item in self.data.items() if now - item[0] <= self.ttl_seconds
        }


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
    app.config["WORKSPACE_ROOT"] = str(Path(os.getenv("WORKSPACE_ROOT", ".")).resolve())
    store = RecordStore()

    @app.get("/")
    @app.post("/")
    def index() -> str:
        message = ""
        if request.method == "POST":
            path_input = request.form.get("input_path", "").strip()
            upload = request.files.get("file")
            temp_path: Path | None = None
            try:
                if upload and upload.filename:
                    safe_name = secure_filename(upload.filename)
                    fd, tmp_name = tempfile.mkstemp(prefix="pe_upload_", suffix=f"_{safe_name}")
                    os.close(fd)
                    temp_path = Path(tmp_name)
                    upload.save(temp_path)
                    target = temp_path
                else:
                    target = Path(path_input).resolve()
                    workspace_root = Path(app.config["WORKSPACE_ROOT"])
                    if workspace_root not in [target] + list(target.parents):
                        raise ValueError("Input path must be inside configured workspace root")
                records = analyze_paths(
                    target,
                    recursive=bool(request.form.get("recursive")),
                    max_file_size_mb=100,
                    extract_strings=True,
                    rules_dir=Path(__file__).resolve().parents[1] / "rules",
                )
                for rec in records:
                    store.put(rec)
                message = f"Analyzed {len(records)} file(s)."
            except Exception as exc:
                message = f"Error: {exc}"
            finally:
                if temp_path and temp_path.exists():
                    temp_path.unlink(missing_ok=True)
        return render_template("index.html", message=message)

    @app.get("/report")
    def report() -> str:
        records = store.all_records()
        summary = build_summary(records)
        analyzed = [r for r in records if not r.get("skipped")]
        imports_chart = [{"file": r.get("file_name", ""), "count": r.get("imported_api_count", 0)} for r in analyzed]
        entropy_chart = [{"file": r.get("file_name", ""), "entropy": r.get("max_section_entropy", 0)} for r in analyzed]
        return render_template(
            "report.html",
            summary=summary,
            records=records,
            imports_chart=imports_chart,
            entropy_chart=entropy_chart,
        )

    @app.get("/detail/<record_id>")
    def detail(record_id: str) -> str:
        record = store.get(record_id)
        if not record:
            return redirect(url_for("report"))
        return render_template("detail.html", record=record)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=False)

