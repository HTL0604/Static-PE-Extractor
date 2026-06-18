from __future__ import annotations


SUBSYSTEM_MAP = {2: "Windows GUI", 3: "Windows CUI", 9: "Windows CE GUI"}


def extract_derived_features(
    record: dict[str, object], api_preview_limit: int, string_preview_limit: int
) -> dict[str, object]:
    subsystem = int(record.get("subsystem", 0))
    is_dll = bool(record.get("is_dll", False))
    is_pe32_plus = int(record.get("optional_magic", 0)) == 0x20B
    imported_api_names = list(record.get("imported_api_names", []))
    export_names = list(record.get("export_names", []))
    suspicious_imports = list(record.get("suspicious_imports", []))
    suspicious_strings = list(record.get("suspicious_strings", []))
    ascii_preview = list(record.get("ascii_strings_preview", []))
    unicode_preview = list(record.get("unicode_strings_preview", []))
    return {
        "pe_type": "DLL" if is_dll else "EXE",
        "subsystem_name": SUBSYSTEM_MAP.get(subsystem, f"unknown_{subsystem}"),
        "is_pe32_plus": is_pe32_plus,
        "has_suspicious_imports": bool(suspicious_imports),
        "has_high_entropy_section": bool(record.get("high_entropy_sections", [])),
        "has_suspicious_section_name": bool(record.get("suspicious_section_names", [])),
        "imports_preview": imported_api_names[:api_preview_limit],
        "exports_preview": export_names[:api_preview_limit],
        "strings_preview": (ascii_preview + unicode_preview + suspicious_strings)[
            :string_preview_limit
        ],
    }

