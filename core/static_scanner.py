"""
Purpose:
Static byte-buffer scanner for file and PE-section string discovery.

How it works:
This module delegates ASCII and UTF-16LE extraction to StringExtractor so
static scans share the same filtering, deduplication, and regex tagging as
runtime memory scans while remaining independent of Speakeasy.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from core.extractor import StringExtractor


StringFinding = dict[str, object]
DEFAULT_STATIC_SCAN_MAX_BYTES = 16 * 1024 * 1024


def scan_into_extractor(
    extractor: StringExtractor,
    data: bytes,
    base_address: int = 0,
    source: str | None = "static_scan",
) -> list[StringFinding]:
    """
    Purpose:
    Add static byte-buffer findings to an existing StringExtractor instance.

    How it works:
    Captures the extractor result count, delegates scanning to
    StringExtractor.scan_buffer(), then relabels only newly appended findings
    with static provenance.

    Parameters:
    - extractor: StringExtractor that should receive the findings.
    - data: raw file or PE-section bytes to scan.
    - base_address: address or file offset added to result locations.
    - source: provenance label for new findings; None keeps scan_buffer's label.

    Returns:
    The list of newly appended finding dictionaries.
    """
    results = cast(list[StringFinding], extractor.get_results())
    start_index = len(results)
    extractor_scan_buffer = cast(
        Callable[[int, bytes], None],
        getattr(extractor, "scan_buffer"),
    )
    extractor_scan_buffer(base_address, data)
    new_results = results[start_index:]

    if source is not None:
        for result in new_results:
            result["source"] = source

    return new_results


def scan_file(
    file_path: str,
    extractor: StringExtractor,
    base_address: int = 0,
    source: str | None = "static_scan",
    max_bytes: int = DEFAULT_STATIC_SCAN_MAX_BYTES,
) -> list[StringFinding]:
    """
    Purpose:
    Scan a bounded prefix of a sample file into the emulator-owned extractor.

    How it works:
    Reads at most max_bytes from file_path, then delegates to
    scan_into_extractor() so static results share the same filtering,
    deduplication, and result cap as runtime extraction.

    Parameters:
    - file_path: path to the sample file being loaded.
    - extractor: StringExtractor owned by the active MalwareEmulator.
    - base_address: address or file offset added to result locations.
    - source: provenance label for new findings; None keeps scan_buffer's label.
    - max_bytes: finite raw-byte read cap for best-effort static observation.

    Returns:
    The list of newly appended finding dictionaries.
    """
    if max_bytes <= 0:
        return []

    with Path(file_path).open("rb") as sample_file:
        data = sample_file.read(max_bytes)

    return scan_into_extractor(
        extractor,
        data,
        base_address=base_address,
        source=source,
    )


def scan_buffer(
    data: bytes,
    base_address: int = 0,
    min_length: int = 4,
    source: str | None = "static_scan",
) -> list[StringFinding]:
    """
    Purpose:
    Extract printable static strings from raw file or PE-section bytes.

    How it works:
    Creates a fresh StringExtractor, then delegates to scan_into_extractor()
    so standalone static scans use the same path as emulator-owned scans.

    Parameters:
    - data: raw bytes from a file, PE image, or PE section.
    - base_address: address or file offset to add to result locations.
    - min_length: minimum string length accepted by StringExtractor.
    - source: provenance label to place on each result; None preserves the
      extractor's default scan provenance.

    Returns:
    A list of StringExtractor-compatible result dictionaries.
    """
    extractor = StringExtractor(min_length=min_length)
    _ = scan_into_extractor(
        extractor,
        data,
        base_address=base_address,
        source=source,
    )
    return cast(list[StringFinding], extractor.get_results())
