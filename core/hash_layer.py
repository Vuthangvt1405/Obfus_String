# -*- coding: utf-8 -*-
"""Sample hashing and PE identity layer for analyst reports."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def calculate_sample_identity(file_path: str) -> dict[str, Any]:
    """Return stable hashes and basic PE metadata for the analyzed sample."""
    path = Path(file_path)
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    size = 0

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)

    info: dict[str, Any] = {
        "file_name": path.name,
        "file_path": str(path),
        "size_bytes": size,
        "hashes": {
            "md5": h_md5.hexdigest(),
            "sha1": h_sha1.hexdigest(),
            "sha256": h_sha256.hexdigest(),
        },
    }

    try:
        import pefile  # type: ignore

        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        info["pe"] = {
            "imphash": pe.get_imphash(),
            "machine": hex(pe.FILE_HEADER.Machine),
            "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        }
    except Exception as exc:
        info["pe"] = {"error": f"PE metadata unavailable: {exc}"}

    return info
