from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class AppConfig:
    workspace_root: Path
    output_json: Path = Path("output/result.json")
    output_csv: Path = Path("output/result.csv")
    max_file_size_mb: int = 100
    extract_strings: bool = True

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024

