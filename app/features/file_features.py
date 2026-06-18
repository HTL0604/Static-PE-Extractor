from __future__ import annotations

import hashlib
from pathlib import Path


def extract_file_features(file_path: Path, data: bytes) -> dict[str, object]:
    return {
        "file_name": file_path.name,
        "file_path": str(file_path),
        "file_size": len(data),
        "md5": hashlib.md5(data).hexdigest(),  # nosec B324
        "sha256": hashlib.sha256(data).hexdigest(),
    }

