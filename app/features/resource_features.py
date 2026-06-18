from __future__ import annotations


RESOURCE_TYPE_MAP = {3: "ICON", 16: "VERSION", 24: "MANIFEST"}


def extract_resource_features(pe: object) -> dict[str, object]:
    types: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") and pe.DIRECTORY_ENTRY_RESOURCE:
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            rid = int(entry.struct.Id) if entry.struct else -1
            types.append(RESOURCE_TYPE_MAP.get(rid, f"TYPE_{rid}"))
    unique_types = sorted(set(types))
    return {
        "has_resources": bool(types),
        "resource_count": len(types),
        "resource_types": unique_types,
        "has_version_info": "VERSION" in unique_types,
        "has_manifest": "MANIFEST" in unique_types,
        "has_icons": "ICON" in unique_types,
    }

