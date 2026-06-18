from __future__ import annotations


def extract_signature_features(pe: object) -> dict[str, object]:
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    addr = int(sec_dir.VirtualAddress)
    size = int(sec_dir.Size)
    present = bool(addr and size)
    return {
        "has_signature": present,
        "certificate_table_present": present,
        "certificate_table_virtual_address": addr,
        "certificate_table_size": size,
        "signature_status": "present" if present else "not_present",
    }

