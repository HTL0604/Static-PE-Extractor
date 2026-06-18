from __future__ import annotations


def extract_export_features(pe: object) -> dict[str, object]:
    export_names: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = (sym.name or b"").decode(errors="ignore")
            if name:
                export_names.append(name)
    return {
        "has_exports": bool(export_names),
        "export_count": len(export_names),
        "export_names": export_names,
    }

