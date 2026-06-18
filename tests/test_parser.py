from pathlib import Path

from app.core.parser import parse_pe_file


def test_parser_skips_invalid_pe(tmp_path: Path) -> None:
    f = tmp_path / "not_pe.bin"
    f.write_bytes(b"hello")
    rec = parse_pe_file(
        f,
        max_file_size_bytes=1024 * 1024,
        extract_strings=False,
        rules={
            "thresholds": {},
            "suspicious_apis": set(),
            "packer_section_names": set(),
        },
    )
    assert rec["skipped"] is True
    assert "invalid_pe" in (rec["skip_reason"] or "")

