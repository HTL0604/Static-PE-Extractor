from __future__ import annotations


def extract_import_features(pe: object, suspicious_apis: set[str]) -> dict[str, object]:
    dll_names: list[str] = []
    api_names: list[str] = []
    suspicious: list[str] = []

    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = (entry.dll or b"").decode(errors="ignore")
        dll_names.append(dll)
        for imp in entry.imports:
            api = (imp.name or b"").decode(errors="ignore")
            if api:
                api_names.append(api)
                if api in suspicious_apis:
                    suspicious.append(api)

    return {
        "imported_dll_count": len(dll_names),
        "imported_api_count": len(api_names),
        "imported_dll_names": sorted(set(dll_names)),
        "imported_api_names": sorted(set(api_names)),
        "suspicious_imports": sorted(set(suspicious)),
    }

