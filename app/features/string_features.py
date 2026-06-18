from __future__ import annotations

import re


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UNICODE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
REG_RE = re.compile(r"(?:HKEY_|SOFTWARE\\|CurrentVersion\\)", re.IGNORECASE)
PATH_RE = re.compile(r"[A-Za-z]:\\[^\s]+")
SUSPICIOUS_RE = re.compile(r"(?:powershell|cmd\.exe|rundll32|base64)", re.IGNORECASE)


def extract_string_features(data: bytes, preview_limit: int) -> dict[str, object]:
    ascii_strings = [m.group().decode(errors="ignore") for m in ASCII_RE.finditer(data)]
    unicode_strings = [
        m.group().decode("utf-16le", errors="ignore") for m in UNICODE_RE.finditer(data)
    ]
    merged = ascii_strings + unicode_strings
    return {
        "ascii_string_count": len(ascii_strings),
        "unicode_string_count": len(unicode_strings),
        "ascii_strings_preview": ascii_strings[:preview_limit],
        "unicode_strings_preview": unicode_strings[:preview_limit],
        "url_strings": [s for s in merged if URL_RE.search(s)][:preview_limit],
        "ip_strings": [s for s in merged if IP_RE.search(s)][:preview_limit],
        "registry_strings": [s for s in merged if REG_RE.search(s)][:preview_limit],
        "file_path_strings": [s for s in merged if PATH_RE.search(s)][:preview_limit],
        "suspicious_strings": [s for s in merged if SUSPICIOUS_RE.search(s)][:preview_limit],
    }

