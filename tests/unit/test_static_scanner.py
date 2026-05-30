"""
Purpose:
Unit tests for the Speakeasy-independent static scanner wrapper.

How it works:
Tests feed plain byte buffers into core.static_scanner.scan_buffer() and
assert that StringExtractor-compatible results are returned for ASCII and
UTF-16LE strings with static-scan provenance.
"""

from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import cast

from core.extractor import StringExtractor


ScanBuffer = Callable[..., list[dict[str, object]]]
static_scanner = import_module("core.static_scanner")
scan_buffer = cast(ScanBuffer, getattr(static_scanner, "scan_buffer"))
scan_file = cast(ScanBuffer, getattr(static_scanner, "scan_file"))


class TestStaticScanBuffer:
    """scan_buffer() extracts static strings from raw byte buffers."""

    def test_extracts_ascii_from_plain_buffer(self) -> None:
        """ASCII strings in noisy file bytes are extracted with static provenance."""
        base_address = 0x400000
        data = b"\x90\x90" + b"malware.example.com" + b"\x00\xff"

        results = scan_buffer(data, base_address=base_address)

        match = next(
            result for result in results
            if result["content"] == "malware.example.com"
        )
        assert match["encoding"] == "ASCII"
        assert match["location"] == str(base_address + 2)
        assert match["source"] == "static_scan"

    def test_extracts_utf16le_from_plain_buffer(self) -> None:
        """UTF-16LE strings in noisy file bytes are extracted with static provenance."""
        base_address = 0x500000
        payload = "WideTest".encode("utf-16le")
        data = b"\xff\xff\xff" + payload + b"\xff"

        results = scan_buffer(data, base_address=base_address)

        match = next(
            result for result in results
            if result["content"] == "WideTest"
        )
        assert match["encoding"] == "UTF-16LE"
        assert match["location"] == str(base_address + 3)
        assert match["source"] == "static_scan"

    def test_accepts_custom_source_label(self) -> None:
        """Caller-provided source labels replace the default static provenance."""
        results = scan_buffer(b"\xffsection_name\xff", source="pe_section")

        assert results[0]["content"] == "section_name"
        assert results[0]["source"] == "pe_section"


class TestStaticScanFile:
    """scan_file() keeps raw file scanning bounded."""

    def test_reads_only_configured_static_scan_cap(self, tmp_path: Path) -> None:
        """A file larger than max_bytes only contributes strings inside the cap."""
        sample_path = tmp_path / "large-sample.bin"
        _ = sample_path.write_bytes(
            b"early.example" + b"\x00" + (b"A" * 64) + b"late.example" + b"\x00"
        )

        results = scan_file(str(sample_path), StringExtractor(), max_bytes=32)
        contents = {result["content"] for result in results}

        assert "early.example" in contents
        assert "late.example" not in contents
