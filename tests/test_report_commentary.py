from app.report.experiment_report import build_commentary_markdown


def test_commentary_is_data_driven() -> None:
    records = [
        {"skipped": False, "possible_packed": True, "has_suspicious_imports": True, "max_section_entropy": 7.8, "file_name": "a.exe"},
        {"skipped": False, "possible_packed": False, "has_suspicious_imports": False, "max_section_entropy": 4.0, "file_name": "b.dll"},
    ]
    md = build_commentary_markdown(records)
    assert "50.0%" in md
    assert "a.exe" in md

