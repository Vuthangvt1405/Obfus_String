# -*- coding: utf-8 -*-
"""Regression tests for maximum-recall guardrail caps."""

from __future__ import annotations

from core.emulator import (
    DEFAULT_MAX_RESULTS,
    MAX_DEFERRED_CHUNK_READS,
    MalwareEmulator,
)
from core.extractor import StringExtractor
from hooks.mem_hooks import DEFAULT_MAX_DIRTY_REGIONS, WriteTracker


class ChunkReadEngine:
    """Fake Speakeasy engine that records deferred memory chunk reads."""

    def __init__(self) -> None:
        """
        Purpose:
        Create a fake engine for deferred memory scan cap tests.

        How it works:
        Stores every mem_read() call and returns printable bytes so the
        emulator exercises its normal scan path.

        Parameters:
        None.

        Returns:
        None.
        """
        self.read_calls: list[tuple[int, int]] = []

    def mem_read(self, address: int, size: int) -> bytes:
        """
        Purpose:
        Simulate Speakeasy memory reads for dirty-region scans.

        How it works:
        Records the requested address and size, then returns a bounded byte
        string that StringExtractor can scan.

        Parameters:
        - address: virtual address requested by the emulator.
        - size: number of bytes requested by the emulator.

        Returns:
        A bytes object of the requested size.
        """
        self.read_calls.append((address, size))
        return b"B" * size


def test_maximum_recall_emulator_uses_default_result_cap(monkeypatch) -> None:
    """
    Purpose:
    Ensure maximum-recall mode still has a result-count guardrail.

    How it works:
    Installs fake Speakeasy constructors, creates MalwareEmulator with default
    arguments, and asserts the embedded extractor is capped.

    Parameters:
    - monkeypatch: pytest fixture used to replace Speakeasy call sites.

    Returns:
    None.
    """
    monkeypatch.setattr(
        "core.emulator.speakeasy.config.get_default_config_dict",
        lambda: {},
    )
    monkeypatch.setattr("core.emulator.speakeasy.Speakeasy", lambda config: object())

    emu = MalwareEmulator()

    assert emu.extractor.max_results == DEFAULT_MAX_RESULTS


def test_maximum_recall_result_cap_applies_to_report_and_memory_paths() -> None:
    """
    Purpose:
    Prove the result cap is shared by all high-recall ingestion paths.

    How it works:
    Feeds API/report-style strings, deferred scan bytes, and explicit
    candidates into one capped extractor, then confirms no new unique entries
    are retained past the cap.

    Parameters:
    None.

    Returns:
    None.
    """
    extractor = StringExtractor(max_results=2)

    extractor.process_api_string("report", "first.example")
    extractor.scan_buffer(0x1000, b"\xffsecond.example\xff")
    extractor.ingest_candidate("third.example", source="overwrite_history")

    assert [entry["content"] for entry in extractor.get_results()] == [
        "first.example",
        "second.example",
    ]


def test_write_tracker_dirty_region_history_is_capped() -> None:
    """
    Purpose:
    Ensure disconnected dirty regions cannot grow without bound.

    How it works:
    Creates more disconnected writes than the configured region cap and asserts
    only the newest capped window remains available for deferred scanning.

    Parameters:
    None.

    Returns:
    None.
    """
    tracker = WriteTracker(max_dirty_regions=3)

    for index in range(6):
        _ = tracker.add_write(0x1000 + (index * 0x100), 4)

    assert tracker.get_regions() == [
        (0x1300, 0x1304),
        (0x1400, 0x1404),
        (0x1500, 0x1504),
    ]
    assert DEFAULT_MAX_DIRTY_REGIONS >= 3


def test_deferred_chunk_loads_are_capped_across_many_regions() -> None:
    """
    Purpose:
    Ensure deferred dirty-memory scanning has a global chunk-load cap.

    How it works:
    Builds an emulator instance with many dirty regions, each large enough to
    require two chunks, and confirms mem_read() stops at the global cap.

    Parameters:
    None.

    Returns:
    None.
    """
    emu = MalwareEmulator.__new__(MalwareEmulator)
    emu.se = ChunkReadEngine()
    emu.extractor = StringExtractor(max_results=1)
    emu.tracker = WriteTracker(max_dirty_regions=MAX_DEFERRED_CHUNK_READS + 20)

    for index in range(MAX_DEFERRED_CHUNK_READS + 20):
        start = 0x100000 + (index * 0x10000)
        emu.tracker.add_write(start, 9000)

    emu._extract_tracked_memory()

    assert len(emu.se.read_calls) == MAX_DEFERRED_CHUNK_READS
    assert all(size <= 4096 for _, size in emu.se.read_calls)
