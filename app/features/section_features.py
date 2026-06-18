from __future__ import annotations

import math


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0

    probs = [data.count(i) / len(data) for i in range(256) if data.count(i)]
    return -sum(p * math.log2(p) for p in probs)


def _get_entry_point(pe: object) -> int | None:
    try:
        return int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    except AttributeError:
        return None
    except Exception:
        return None


def extract_section_features(
    pe: object, high_entropy_threshold: float, suspicious_names: set[str]
) -> dict[str, object]:
    details: list[dict[str, object]] = []
    entropies: list[float] = []
    names: list[str] = []
    suspicious: list[str] = []
    high_entropy: list[str] = []

    # Entry Point Analysis
    entry_point = _get_entry_point(pe)
    entry_point_section = "unknown"
    entry_point_section_entropy = 0.0
    entry_point_in_suspicious_section = False

    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        data = section.get_data()
        entropy = _entropy(data)

        names.append(name)
        entropies.append(entropy)

        section_virtual_address = int(getattr(section, "VirtualAddress", 0))
        section_virtual_size = int(getattr(section, "Misc_VirtualSize", 0))
        section_raw_size = int(getattr(section, "SizeOfRawData", 0))
        section_characteristics = int(getattr(section, "Characteristics", 0))

        section_start = section_virtual_address
        section_end = section_start + max(section_virtual_size, section_raw_size)

        if entry_point is not None and section_start <= entry_point < section_end:
            entry_point_section = name
            entry_point_section_entropy = round(entropy, 4)
            entry_point_in_suspicious_section = name.lower() in suspicious_names

        details.append(
            {
                "name": name,
                "virtual_size": section_virtual_size,
                "raw_size": section_raw_size,
                "virtual_address": section_virtual_address,
                "entropy": round(entropy, 4),
                "characteristics": section_characteristics,
            }
        )

        if entropy >= high_entropy_threshold:
            high_entropy.append(name)

        if name.lower() in suspicious_names:
            suspicious.append(name)

    max_entropy = max(entropies) if entropies else 0.0
    avg_entropy = (sum(entropies) / len(entropies)) if entropies else 0.0

    return {
        "section_names": names,
        "section_count": len(names),
        "section_details": details,
        "max_section_entropy": round(max_entropy, 4),
        "avg_section_entropy": round(avg_entropy, 4),
        "high_entropy_sections": high_entropy,
        "suspicious_section_names": suspicious,
        "entry_point_section": entry_point_section,
        "entry_point_section_entropy": entry_point_section_entropy,
        "entry_point_in_suspicious_section": entry_point_in_suspicious_section,
    }
