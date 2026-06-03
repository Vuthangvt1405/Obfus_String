# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
import importlib
import types
from collections import deque
from collections.abc import Callable
from typing import Protocol, cast

try:
    speakeasy_errors: types.ModuleType | None = importlib.import_module('speakeasy.errors')
except ImportError:
    speakeasy_errors = None

logger = logging.getLogger(__name__)


class MemoryReader(Protocol):
    def mem_read(self, address: int, size: int) -> bytes:
        ...


class SnapshotExtractor(Protocol):
    def scan_buffer(self, base_address: int, data: bytes) -> object:
        ...


class HookEngine(MemoryReader, Protocol):
    def add_mem_write_hook(
        self,
        callback: Callable[[object, object, int, int, object], None],
    ) -> object:
        ...


HOT_WRITE_THRESHOLD = 100
SNAPSHOT_INTERVAL = 25
MAX_SNAPSHOT_SIZE = 4096
DEFAULT_MAX_DIRTY_REGIONS = 4096
MAX_EXECUTE_AFTER_WRITE_SNAPSHOTS = 32
MAX_EXECUTE_REGION_CHECKS = 128

if speakeasy_errors is None:
    MemoryAccessError = Exception
else:
    _default_memory_error = cast(type[Exception], getattr(speakeasy_errors, 'SpeakeasyError', Exception))
    MemoryAccessError = cast(
        type[Exception],
        getattr(speakeasy_errors, 'MemoryAccessError', _default_memory_error),
    )

class WriteTracker:
    """
    Theo dõi các vùng bộ nhớ bị ghi (dirty ranges) để xử lý sau thay vì
    làm giảm hiệu năng khi gọi extractor trên từng byte.

    Mỗi vùng lưu [start, end, count] với count là số lần ghi đã gộp vào vùng.
    is_hot(threshold) kiểm tra xem vùng nào có tần suất ghi vượt ngưỡng.
    """
    def __init__(
        self,
        max_candidate_history: int = 32,
        max_dirty_regions: int = DEFAULT_MAX_DIRTY_REGIONS,
        max_execute_after_write_snapshots: int = MAX_EXECUTE_AFTER_WRITE_SNAPSHOTS,
    ) -> None:
        """
        Purpose:
        Create a dirty-region tracker with bounded dirty and candidate storage.

        How it works:
        Keeps dirty regions in the existing list format, evicts the oldest
        disconnected regions past max_dirty_regions, stores overwrite snapshots
        in a bounded deque, and separately stores first-execute snapshots in a
        bounded deque.

        Parameters:
        - max_candidate_history: maximum number of candidate snapshots to keep.
        - max_dirty_regions: maximum number of disconnected dirty regions to keep.
        - max_execute_after_write_snapshots: maximum first-execute snapshots to keep.

        Returns:
        None.
        """
        self.regions: list[list[int]] = []
        self.max_dirty_regions: int = max_dirty_regions
        self._candidates: deque[tuple[int, bytes]] = deque(maxlen=max_candidate_history)
        self.max_execute_after_write_snapshots: int = max(0, max_execute_after_write_snapshots)
        self._execute_after_write_candidates: deque[tuple[int, bytes]] = deque(
            maxlen=self.max_execute_after_write_snapshots,
        )
        self._execute_after_write_keys: deque[tuple[int, int]] = deque(
            maxlen=self.max_execute_after_write_snapshots,
        )

    def add_write(self, address: int, size: int) -> list[int]:
        """
        Purpose:
        Track one memory write and return the updated dirty region.

        How it works:
        Coalesces the write into one of the last 10 regions when ranges touch
        or overlap, incrementing that region's write count. Otherwise appends a
        new counted region and evicts the oldest disconnected region past the
        configured cap.

        Parameters:
        - address: starting virtual address of the write.
        - size: number of bytes written.

        Returns:
        The updated region list [start, end, count].
        """
        start = address
        end = address + size

        # Duyệt ngược để merge (coalesce) với các khoảng gần đây nhất.
        # Giới hạn tìm kiếm O(1) (tối đa 10 vùng) để giữ performance cực cao.
        for i in range(len(self.regions) - 1, max(-1, len(self.regions) - 11), -1):
            r_start, r_end, r_count = self.regions[i]
            # Kiểm tra giao nhau hoặc liền kề
            if start <= r_end and end >= r_start:
                self.regions[i][0] = min(r_start, start)
                self.regions[i][1] = max(r_end, end)
                self.regions[i][2] = r_count + 1
                return self.regions[i]

        # Nếu không merge được với các khoảng gần đây, thêm mới với count=1
        self.regions.append([start, end, 1])
        if len(self.regions) > self.max_dirty_regions:
            _ = self.regions.pop(0)
        return self.regions[-1]

    def add_candidate(self, address: int, data: bytes) -> tuple[int, bytes]:
        """
        Purpose:
        Store one overwrite-history candidate snapshot for later ingestion.

        How it works:
        Copies at most MAX_SNAPSHOT_SIZE bytes into the bounded candidate deque,
        preserving older overwritten candidates until the configured cap evicts
        them.

        Parameters:
        - address: starting virtual address where the candidate was observed.
        - data: bytes-like candidate snapshot to retain.

        Returns:
        The stored (address, data) tuple.
        """
        candidate = (address, bytes(data[:MAX_SNAPSHOT_SIZE]))
        self._candidates.append(candidate)
        return candidate

    def get_candidates(self) -> list[tuple[int, bytes]]:
        """
        Purpose:
        Return stored overwrite-history candidate snapshots.

        How it works:
        Converts the bounded internal deque to a list without changing dirty
        region state or the get_regions() compatibility contract.

        Parameters:
        None.

        Returns:
        A list of (address, data) tuples.
        """
        return list(self._candidates)

    def capture_execute_after_write(
        self,
        reader: MemoryReader,
        instruction_address: int,
    ) -> tuple[int, bytes] | None:
        """
        Purpose:
        Capture a bounded snapshot when execution enters a dirty written region.

        How it works:
        Checks only the most recent MAX_EXECUTE_REGION_CHECKS dirty regions,
        skips regions already captured, stops after the configured snapshot cap,
        and reads at most MAX_SNAPSHOT_SIZE bytes from the matching region.

        Parameters:
        - reader: emulator-like object exposing mem_read(address, size).
        - instruction_address: current instruction address from a code hook.

        Returns:
        The stored (address, data) tuple, or None when no bounded snapshot is taken.
        """
        if self.max_execute_after_write_snapshots <= 0:
            return None
        if len(self._execute_after_write_candidates) >= self.max_execute_after_write_snapshots:
            return None

        recent_regions = self.regions[-MAX_EXECUTE_REGION_CHECKS:]
        for start, end, _ in reversed(recent_regions):
            if not start <= instruction_address < end:
                continue
            region_key = (start, end)
            if region_key in self._execute_after_write_keys:
                return None
            read_size = min(end - start, MAX_SNAPSHOT_SIZE)
            if read_size <= 0:
                return None
            try:
                data = reader.mem_read(start, read_size)
            except MemoryAccessError as err:
                logger.debug(f"[Hook] Bỏ qua execute-after-write snapshot {hex(start)}: {err}")
                return None
            if not data:
                return None
            candidate = (start, bytes(data[:MAX_SNAPSHOT_SIZE]))
            self._execute_after_write_candidates.append(candidate)
            self._execute_after_write_keys.append(region_key)
            return candidate
        return None

    def get_execute_after_write_candidates(self) -> list[tuple[int, bytes]]:
        """
        Purpose:
        Return stored execute-after-write candidate snapshots.

        How it works:
        Converts the bounded internal deque to a list without modifying dirty
        region or overwrite-history state.

        Parameters:
        None.

        Returns:
        A list of (address, data) tuples.
        """
        return list(self._execute_after_write_candidates)

    def get_regions(self) -> list[tuple[int, int]]:
        """
        Returns:
            List of (start, end) tuples for backwards compatibility.
        """
        return [(r[0], r[1]) for r in self.regions]

    def is_hot(self, threshold: int = 100) -> bool:
        """
        Kiểm tra xem có vùng nhớ nào có tần suất ghi vượt ngưỡng hot hay không.

        Parameters:
            threshold: Số lần ghi tối thiểu để coi là hot (mặc định 100).

        Returns:
            True nếu có ít nhất một vùng có count >= threshold.
        """
        for _, _, count in self.regions:
            if count >= threshold:
                return True
        return False


def _snapshot_hot_region(se: MemoryReader, extractor: SnapshotExtractor, region: list[int]) -> None:
    """
    Purpose:
    Scan a bounded snapshot from a hot dirty memory region during hook execution.

    How it works:
    Reads at most MAX_SNAPSHOT_SIZE bytes from the region's current start
    address and passes successful reads to extractor.scan_buffer(). Unmapped
    hot regions are ignored so the memory hook stays non-fatal.

    Parameters:
    - se: Speakeasy-like engine exposing mem_read(address, size).
    - extractor: StringExtractor-like object exposing scan_buffer().
    - region: [start, end, count] dirty-region entry from WriteTracker.

    Returns:
    None.
    """
    start, end, _ = region
    read_size = min(end - start, MAX_SNAPSHOT_SIZE)
    if read_size <= 0:
        return

    try:
        mem_data = se.mem_read(start, read_size)
    except MemoryAccessError as err:
        logger.debug(f"[Hook] Bỏ qua hot-region snapshot {hex(start)}: {err}")
        return

    if mem_data:
        _ = extractor.scan_buffer(start, mem_data)


def setup_memory_hooks(se: HookEngine, extractor: SnapshotExtractor, tracker: WriteTracker | None = None) -> None:
    """
    Purpose:
    Register the Speakeasy memory-write hook for dirty-region tracking.

    How it works:
    Adds a lightweight write callback that records each dirty range. When a
    region is hot and its write count hits SNAPSHOT_INTERVAL, the hook reads a
    capped snapshot and scans it for transient plaintext.

    Parameters:
    - se: Speakeasy-like engine exposing add_mem_write_hook() and mem_read().
    - extractor: StringExtractor-like object used for snapshot scans.
    - tracker: optional WriteTracker instance for coalesced dirty regions.

    Returns:
    None.
    """

    def hook_mem_write(emu: object, access: object, address: int, size: int, value: object) -> None:
        """
        Purpose:
        Handle one memory-write notification from Speakeasy.

        How it works:
        Updates the dirty-region tracker. Repeated writes read at most
        MAX_SNAPSHOT_SIZE bytes from the target address into bounded candidate
        history, and hot regions still trigger the existing snapshot scan.

        Parameters:
        - emu: callback emulator object, used for mem_read() when present.
        - access: Speakeasy access metadata, unused.
        - address: starting virtual address written.
        - size: number of bytes written.
        - value: integer write value supplied by Speakeasy, unused.

        Returns:
        None.
        """
        _ = access
        _ = value
        if tracker:
            region = tracker.add_write(address, size)
            count = region[2]
            snapshot_engine = cast(MemoryReader, emu if emu is not None else se)
            if count > 1 and size > 0:
                try:
                    candidate_size = min(size, MAX_SNAPSHOT_SIZE)
                    candidate = snapshot_engine.mem_read(address, candidate_size)
                except MemoryAccessError as err:
                    logger.debug(f"[Hook] Bỏ qua overwrite candidate {hex(address)}: {err}")
                else:
                    if candidate:
                        _ = tracker.add_candidate(address, candidate)
            if count >= HOT_WRITE_THRESHOLD and count % SNAPSHOT_INTERVAL == 0:
                _snapshot_hot_region(snapshot_engine, extractor, region)

    try:
        _ = se.add_mem_write_hook(hook_mem_write)
        logger.info("[Hook] Đã cắm Memory Write hook qua Speakeasy API (Lightweight Tracking).")
    except Exception as e:
        logger.error(f"[Hook] Lỗi móc bộ nhớ: {e}")
