from __future__ import annotations

from datetime import UTC, datetime


MACHINE_MAP = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM"}


def extract_header_features(pe: object) -> dict[str, object]:
    file_header = pe.FILE_HEADER
    opt_header = pe.OPTIONAL_HEADER
    machine = int(file_header.Machine)
    return {
        "machine": hex(machine),
        "architecture": MACHINE_MAP.get(machine, "unknown"),
        "number_of_sections": int(file_header.NumberOfSections),
        "timestamp": int(file_header.TimeDateStamp),
        "compile_time_human": datetime.fromtimestamp(
            int(file_header.TimeDateStamp), tz=UTC
        ).isoformat(),
        "characteristics": int(file_header.Characteristics),
        "entry_point": int(opt_header.AddressOfEntryPoint),
        "image_base": int(opt_header.ImageBase),
        "subsystem": int(opt_header.Subsystem),
        "dll_characteristics": int(opt_header.DllCharacteristics),
        "is_dll": bool(file_header.Characteristics & 0x2000),
    }

