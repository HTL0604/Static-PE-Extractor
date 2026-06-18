from __future__ import annotations

from typing import Any, TypedDict


class ExtractionRecord(TypedDict, total=False):
    entry_point_section: str
    entry_point_section_entropy: float
    entry_point_in_suspicious_section: bool
    risk_score: int 
    risk_level: str
    risk_reasons: list[str]
    record_id: str
    error: str | None
    skipped: bool
    skip_reason: str | None
    file_name: str
    file_path: str
    file_size: int
    md5: str
    sha256: str
    machine: str
    architecture: str
    number_of_sections: int
    timestamp: int
    compile_time_human: str
    characteristics: int
    entry_point: int
    image_base: int
    subsystem: int
    dll_characteristics: int
    is_dll: bool
    section_names: list[str]
    section_count: int
    section_details: list[dict[str, Any]]
    max_section_entropy: float
    avg_section_entropy: float
    high_entropy_sections: list[str]
    suspicious_section_names: list[str]
    imported_dll_count: int
    imported_api_count: int
    imported_dll_names: list[str]
    imported_api_names: list[str]
    suspicious_imports: list[str]
    has_exports: bool
    export_count: int
    export_names: list[str]
    ascii_string_count: int
    unicode_string_count: int
    ascii_strings_preview: list[str]
    unicode_strings_preview: list[str]
    url_strings: list[str]
    ip_strings: list[str]
    registry_strings: list[str]
    file_path_strings: list[str]
    suspicious_strings: list[str]
    has_resources: bool
    resource_count: int
    resource_types: list[str]
    has_version_info: bool
    has_manifest: bool
    has_icons: bool
    has_signature: bool
    certificate_table_present: bool
    certificate_table_virtual_address: int
    certificate_table_size: int
    signature_status: str
    pe_type: str
    subsystem_name: str
    is_pe32_plus: bool
    has_suspicious_imports: bool
    has_high_entropy_section: bool
    has_suspicious_section_name: bool
    imports_preview: list[str]
    exports_preview: list[str]
    strings_preview: list[str]
    possible_packed: bool
    packer_indicators: list[str]
    packer_name_guess: str
    packer_suspicion: str

