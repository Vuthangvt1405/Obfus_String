# pyright: reportMissingImports=false
import pytest  # type: ignore[import-not-found]
from types import SimpleNamespace
from unittest.mock import Mock

from core.emulator import MalwareEmulator
from core.extractor import StringExtractor
from hooks.mem_hooks import (
    HOT_WRITE_THRESHOLD,
    MAX_SNAPSHOT_SIZE,
    MemoryAccessError,
    WriteTracker,
    setup_memory_hooks,
)

class MockSpeakeasy:
    def __init__(self):
        self._memory = {}
        self.read_calls = []
        
    def mem_read(self, address, size):
        # Simulate memory mapping and reading
        # Let's say valid memory is at 0x1000 - 0x2000
        self.read_calls.append((address, size))
        result = bytearray()
        for i in range(size):
            addr = address + i
            if 0x1000 <= addr < 0x2000:
                result.append(self._memory.get(addr, 0))
            else:
                # Unmapped memory raises exception similar to real speakeasy
                raise MemoryAccessError(f"Unmapped memory read at {hex(addr)}")
        return bytes(result)
        
    def set_mock_mem(self, data_dict):
        """Helper to populate valid memory space"""
        self._memory.update(data_dict)

class HookedMockSpeakeasy(MockSpeakeasy):
    """
    Purpose:
    Simulate Speakeasy memory writes with registered write hooks.

    How it works:
    Stores callbacks from add_mem_write_hook(). mem_write() commits bytes into
    the mock memory first, then invokes each callback with Speakeasy's write
    hook signature so hook-time mem_read sees post-write bytes.

    Parameters:
    None.

    Returns:
    A mock Speakeasy object with hookable memory writes.
    """
    def __init__(self):
        super().__init__()
        self._hooks = []

    def add_mem_write_hook(self, callback):
        self._hooks.append(callback)

    def mem_write(self, address, data):
        for i, b in enumerate(data):
            self._memory[address + i] = b

        value = int.from_bytes(data, byteorder='little') if data else 0
        for hook in self._hooks:
            hook(self, None, address, len(data), value)

class PreWriteHookedMockSpeakeasy(HookedMockSpeakeasy):
    """
    Purpose:
    Simulate Speakeasy write hooks that fire before bytes are overwritten.

    How it works:
    Stores callbacks through HookedMockSpeakeasy, invokes them before committing
    mem_write() bytes, then writes the new bytes into the backing memory map.

    Parameters:
    None.

    Returns:
    A mock Speakeasy object whose hooks can observe pre-overwrite memory.
    """
    def mem_write(self, address, data):
        value = int.from_bytes(data, byteorder='little') if data else 0
        for hook in self._hooks:
            hook(self, None, address, len(data), value)

        for i, b in enumerate(data):
            self._memory[address + i] = b

class SnapshotFailingSpeakeasy(HookedMockSpeakeasy):
    """
    Purpose:
    Force hook-time snapshot reads to raise MemoryAccessError.

    How it works:
    Reuses HookedMockSpeakeasy for write-hook execution but overrides
    mem_read() so snapshot attempts always see an unmapped-memory error.

    Parameters:
    None.

    Returns:
    A mock Speakeasy object whose mem_read() is unreadable.
    """
    def mem_read(self, address, size):
        raise MemoryAccessError(
            f"Unmapped memory read at {hex(address)}"
        )

def test_run_timeout_extracts_once_and_tracks_status():
    """
    Purpose:
    Verify constrained timeout stops still drain deferred extraction.

    How it works:
    Replaces Speakeasy with a fake run_module that raises TimeoutError and
    replaces both extraction phases with mocks so call counts are precise.

    Parameters:
    None.

    Returns:
    None; assertions validate status and one-shot extraction calls.
    """
    emu = MalwareEmulator()
    emu.module = object()
    emu.se = SimpleNamespace(
        run_module=Mock(side_effect=TimeoutError("Timeout reached"))
    )
    emu._extract_from_report = Mock()
    emu._extract_tracked_memory = Mock()

    emu.run()

    assert emu.execution_status == "timeout"
    emu.se.run_module.assert_called_once_with(emu.module)
    emu._extract_from_report.assert_called_once_with()
    emu._extract_tracked_memory.assert_called_once_with()


def test_run_max_instructions_extracts_once_and_tracks_status():
    """
    Purpose:
    Verify max-instruction constrained stops still drain deferred extraction.

    How it works:
    Uses a fake exception class named like Speakeasy/Unicorn instruction-limit
    failures and replaces both extraction phases with mocks for exact counts.

    Parameters:
    None.

    Returns:
    None; assertions validate max-instruction status and extraction calls.
    """
    class MaxInstructionsError(Exception):
        pass

    emu = MalwareEmulator()
    emu.module = object()
    emu.se = SimpleNamespace(
        run_module=Mock(side_effect=MaxInstructionsError("max instructions reached"))
    )
    emu._extract_from_report = Mock()
    emu._extract_tracked_memory = Mock()

    emu.run()

    assert emu.execution_status == "max_instructions"
    emu.se.run_module.assert_called_once_with(emu.module)
    emu._extract_from_report.assert_called_once_with()
    emu._extract_tracked_memory.assert_called_once_with()


def test_run_reraises_unrelated_exception_after_extracting_once():
    """
    Purpose:
    Verify fatal non-resource exceptions are not swallowed as safe stops.

    How it works:
    Makes run_module raise TypeError, then asserts run() re-raises while the
    finally path still executes both extraction phases exactly once.

    Parameters:
    None.

    Returns:
    None; assertions validate propagation and one-shot extraction calls.
    """
    emu = MalwareEmulator()
    emu.module = object()
    emu.se = SimpleNamespace(
        run_module=Mock(side_effect=TypeError("fatal emulator bug"))
    )
    emu._extract_from_report = Mock()
    emu._extract_tracked_memory = Mock()

    with pytest.raises(TypeError):
        emu.run()

    assert emu.execution_status == "error"
    emu.se.run_module.assert_called_once_with(emu.module)
    emu._extract_from_report.assert_called_once_with()
    emu._extract_tracked_memory.assert_called_once_with()


def test_post_run_memory_scans_valid():
    """
    Test scanning valid memory regions deferred after run finishes.
    Emulate having a tracked dirty memory region and scanning it for strings.
    """
    emu = MalwareEmulator()
    emu.se = MockSpeakeasy()
    
    # Write some mock string into valid region
    test_string = b"http://malicious.url/payload.exe"
    mock_data = {}
    for i, b in enumerate(test_string):
        mock_data[0x1100 + i] = b
    mock_data[0x1100 + len(test_string)] = 0 # null terminator
    
    emu.se.set_mock_mem(mock_data)
    
    # Simulate track
    emu.tracker.add_write(0x1100, len(test_string))
    
    # Trigger deferred extract (without full emulation run)
    emu._extract_tracked_memory()
    
    # Verify string was captured
    results = emu.get_extracted_strings()
    found = any(r['content'] == "http://malicious.url/payload.exe" for r in results)
    assert found, "Deferred scan failed to capture valid string in memory"

def test_post_run_memory_scans_unreadable_bounds():
    """
    Test scanning when malware writes to boundaries that partially
    fall off mapped memory to ensure it doesn't crash the scanning phase.
    """
    emu = MalwareEmulator()
    emu.se = MockSpeakeasy()
    
    # Valid valid string near the edge of memory space (0x1FF0)
    test_string = b"NearEdge!\x00"
    mock_data = {}
    for i, b in enumerate(test_string):
        mock_data[0x1FF0 + i] = b
    emu.se.set_mock_mem(mock_data)
    
    # Malware tracked write claiming far larger boundaries (into unmapped 0x2050)
    emu.tracker.add_write(0x1FF0, 0x60)
    
    # Trigger deferred extract
    # This should not raise an unhandled exception despite the memory boundary violation
    try:
        emu._extract_tracked_memory()
    except Exception as e:
        pytest.fail(f"_extract_tracked_memory raised an unexpected exception: {e}")
        
    # The scan should still process up to the failure or gracefully continue 
    # depending on implementation setup (we capped it to chunks). 
    # NOTE: our MockSpeakeasy throws immediately on read if *any* byte is unmapped in the chunk.
    # In Speakeasy reality, it fails the whole chunk read. But the exception must be caught.
    # We want to ensure no crash.
    assert True

def test_hot_region_snapshot_captures_transient_overwritten_plaintext():
    """
    Purpose:
    Verify hook-time hot-region snapshots catch plaintext that is overwritten
    before deferred post-run memory scanning can read it.

    How it works:
    Drives HOT_WRITE_THRESHOLD writes into one coalesced dirty region. The hot
    threshold write commits a URL, which the hook should snapshot immediately.
    The test then overwrites that memory with zeros and confirms the string was
    still captured even though final memory no longer contains it.

    Parameters:
    None.

    Returns:
    None; assertions validate snapshot capture.
    """
    se = HookedMockSpeakeasy()
    extractor = StringExtractor()
    tracker = WriteTracker()
    setup_memory_hooks(se, extractor, tracker=tracker)

    base_addr = 0x1200
    transient = b"http://transient.example/payload\x00"

    for _ in range(HOT_WRITE_THRESHOLD - 1):
        se.mem_write(base_addr, b"X")

    se.mem_write(base_addr, transient)
    se.mem_write(base_addr, b"\x00" * len(transient))

    final_bytes = se.mem_read(base_addr, len(transient))
    assert transient.rstrip(b"\x00") not in final_bytes

    results = extractor.get_results()
    found = any(
        r['content'] == "http://transient.example/payload"
        for r in results
    )
    assert found, "Hot-region snapshot missed overwritten transient plaintext"
    assert se.read_calls[-2][1] <= MAX_SNAPSHOT_SIZE

def test_hot_region_snapshot_ignores_memory_access_error():
    """
    Purpose:
    Ensure snapshot reads that hit unmapped memory do not abort hook execution.

    How it works:
    Uses a mock Speakeasy object whose mem_read() always raises
    MemoryAccessError, then performs enough writes to trigger a hot-region
    snapshot. The hook should catch the memory access failure and continue.

    Parameters:
    None.

    Returns:
    None; the absence of an exception is the expected behavior.
    """
    se = SnapshotFailingSpeakeasy()
    extractor = StringExtractor()
    tracker = WriteTracker()
    setup_memory_hooks(se, extractor, tracker=tracker)

    for _ in range(HOT_WRITE_THRESHOLD):
        se.mem_write(0x1300, b"Z")

    assert tracker.is_hot()


def test_pre_overwrite_candidate_survives_later_overwrite_with_history_source():
    """
    Purpose:
    Verify a plaintext buffer is retained when a later write overwrites it.

    How it works:
    Uses a pre-write hook fake so the second write can read the existing
    plaintext before zeros replace it. Deferred extraction should then process
    the bounded candidate history and emit overwrite_history provenance.

    Parameters:
    None.

    Returns:
    None; assertions validate candidate capture and deferred extraction.
    """
    se = PreWriteHookedMockSpeakeasy()
    extractor = StringExtractor()
    tracker = WriteTracker()
    setup_memory_hooks(se, extractor, tracker=tracker)

    emu = MalwareEmulator()
    emu.se = se
    emu.extractor = extractor
    emu.tracker = tracker

    base_addr = 0x1400
    plaintext = b"http://stack_before_overwrite.example/path\x00"

    se.mem_write(base_addr, plaintext)
    se.mem_write(base_addr, b"\x00" * len(plaintext))

    final_bytes = se.mem_read(base_addr, len(plaintext))
    assert plaintext.rstrip(b"\x00") not in final_bytes
    assert tracker.get_candidates(), "Hook did not retain a pre-overwrite candidate"

    emu._extract_tracked_memory()

    match = next(
        (
            result for result in extractor.get_results()
            if result['content'] == "http://stack_before_overwrite.example/path"
        ),
        None,
    )
    assert match is not None, "Deferred extraction missed overwrite candidate"
    assert match['source'] == "overwrite_history"


def test_pre_overwrite_candidate_capture_caps_read_size_without_scanning_hook():
    """
    Purpose:
    Ensure overwrite candidate capture stays bounded inside the memory hook.

    How it works:
    Writes a buffer larger than MAX_SNAPSHOT_SIZE, overwrites the same range,
    and confirms the hook read/candidate payload are capped while no synchronous
    scan_buffer() call occurs below the hot-region threshold.

    Parameters:
    None.

    Returns:
    None; assertions validate bounded capture behavior.
    """
    se = PreWriteHookedMockSpeakeasy()
    extractor = StringExtractor()
    extractor.scan_buffer = Mock(wraps=extractor.scan_buffer)
    tracker = WriteTracker()
    setup_memory_hooks(se, extractor, tracker=tracker)

    base_addr = 0x1000
    plaintext = b"A" * (MAX_SNAPSHOT_SIZE + 128)

    se.mem_write(base_addr, plaintext)
    se.mem_write(base_addr, b"B" * len(plaintext))

    [(candidate_addr, candidate_data)] = tracker.get_candidates()
    assert candidate_addr == base_addr
    assert len(candidate_data) == MAX_SNAPSHOT_SIZE
    assert se.read_calls[-1] == (base_addr, MAX_SNAPSHOT_SIZE)
    extractor.scan_buffer.assert_not_called()
