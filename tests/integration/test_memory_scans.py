import pytest
import speakeasy
import sys
import os

from core.emulator import MalwareEmulator
from core.extractor import StringExtractor
from hooks.mem_hooks import WriteTracker, setup_memory_hooks

class MockSpeakeasy:
    def __init__(self):
        self._memory = {}
        
    def mem_read(self, address, size):
        # Simulate memory mapping and reading
        # Let's say valid memory is at 0x1000 - 0x2000
        result = bytearray()
        for i in range(size):
            addr = address + i
            if 0x1000 <= addr < 0x2000:
                result.append(self._memory.get(addr, 0))
            else:
                # Unmapped memory raises exception similar to real speakeasy
                raise speakeasy.errors.MemoryAccessError(f"Unmapped memory read at {hex(addr)}")
        return bytes(result)
        
    def set_mock_mem(self, data_dict):
        """Helper to populate valid memory space"""
        self._memory.update(data_dict)

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
