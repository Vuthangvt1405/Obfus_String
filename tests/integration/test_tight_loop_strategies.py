# -*- coding: utf-8 -*-
# pyright: reportMissingImports=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnannotatedClassAttribute=false, reportUnusedParameter=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportAttributeAccessIssue=false, reportUnknownLambdaType=false, reportUntypedFunctionDecorator=false, reportAny=false
import json
import sys
import types

import pytest

from utils.reporter import ReportGenerator


class MaxInstructionsError(Exception):
    """
    Purpose:
    Represent a fake emulator instruction-limit stop.

    How it works:
    The class name and message contain the instruction-limit wording that
    MalwareEmulator.run() classifies as a safe max-instructions stop.

    Parameters:
    - message: Exception text passed by the test case.

    Returns:
    An exception instance for fake Speakeasy.run_module().
    """


class FakeConstrainedSpeakeasy:
    """
    Purpose:
    Simulate a Speakeasy engine that writes plaintext and then hits a limit.

    How it works:
    run_module() drops the payload into fake memory, records the dirty range
    through the production WriteTracker, then raises the configured stop error.

    Parameters:
    - tracker: WriteTracker instance owned by the MalwareEmulator under test.
    - payload: Bytes to expose through mem_read() before the stop.
    - base_address: Fake virtual address where payload bytes are written.
    - stop_error: Exception raised after the payload has been dropped.

    Returns:
    A fake Speakeasy-like object for MalwareEmulator.run().
    """

    def __init__(self, tracker, payload, base_address, stop_error):
        self.tracker = tracker
        self.payload = payload
        self.base_address = base_address
        self.stop_error = stop_error
        self.memory = {}
        self.read_calls = []
        self.did_drop_payload = False

    def run_module(self, module):
        """
        Purpose:
        Emulate a sample reaching a constrained tight-loop stop.

        How it works:
        Writes payload bytes into fake memory, marks the dirty range, then
        raises the configured timeout or max-instructions exception.

        Parameters:
        - module: Loaded module object passed by MalwareEmulator.run().

        Returns:
        Nothing; always raises stop_error after recording the payload.
        """
        for offset, byte in enumerate(self.payload):
            self.memory[self.base_address + offset] = byte
        self.tracker.add_write(self.base_address, len(self.payload))
        self.did_drop_payload = True
        raise self.stop_error

    def mem_read(self, address, size):
        """
        Purpose:
        Provide bytes from the fake virtual memory map.

        How it works:
        Reads the requested range byte-by-byte from the in-memory dict and
        raises OSError when the test asks for unmapped memory.

        Parameters:
        - address: Starting fake virtual address to read.
        - size: Number of bytes requested.

        Returns:
        The requested bytes object.
        """
        self.read_calls.append((address, size))
        result = bytearray()
        for offset in range(size):
            current_address = address + offset
            if current_address not in self.memory:
                raise OSError(f"unmapped memory at {hex(current_address)}")
            result.append(self.memory[current_address])
        return bytes(result)

    def get_json_report(self):
        """
        Purpose:
        Return a minimal Speakeasy JSON report.

        How it works:
        Supplies empty report sections so extraction success must come from
        deferred memory scanning rather than built-in report strings.

        Parameters:
        None.

        Returns:
        JSON string shaped like the Speakeasy report fields used by the code.
        """
        return json.dumps({"entry_points": [], "strings": {"in_memory": {}}})


def _install_fake_speakeasy(monkeypatch):
    """
    Purpose:
    Make core.emulator importable without the real Speakeasy package.

    How it works:
    Installs fake speakeasy and speakeasy.errors modules that expose the
    attributes imported by core.emulator and hooks.mem_hooks.

    Parameters:
    - monkeypatch: Pytest fixture used to replace sys.modules entries.

    Returns:
    None.
    """
    fake_speakeasy = types.ModuleType("speakeasy")
    fake_errors = types.ModuleType("speakeasy.errors")

    class SpeakeasyError(Exception):
        pass

    class NotSupportedError(SpeakeasyError):
        pass

    class MemoryAccessError(SpeakeasyError):
        pass

    fake_errors.SpeakeasyError = SpeakeasyError
    fake_errors.NotSupportedError = NotSupportedError
    fake_errors.MemoryAccessError = MemoryAccessError
    fake_speakeasy.errors = fake_errors
    fake_speakeasy.config = types.SimpleNamespace(
        get_default_config_dict=lambda: {}
    )
    fake_speakeasy.Speakeasy = lambda config=None: object()

    monkeypatch.setitem(sys.modules, "speakeasy", fake_speakeasy)
    monkeypatch.setitem(sys.modules, "speakeasy.errors", fake_errors)


def _load_runtime(monkeypatch):
    """
    Purpose:
    Load production emulator classes behind fake Speakeasy dependencies.

    How it works:
    Ensures fake Speakeasy modules exist, imports MalwareEmulator and helper
    classes, and returns them to the test helper.

    Parameters:
    - monkeypatch: Pytest fixture used to install fake modules if needed.

    Returns:
    Tuple of MalwareEmulator, StringExtractor, and WriteTracker classes.
    """
    _install_fake_speakeasy(monkeypatch)

    from core.emulator import MalwareEmulator
    from core.extractor import StringExtractor
    from hooks.mem_hooks import WriteTracker

    return MalwareEmulator, StringExtractor, WriteTracker


def _build_constrained_emulator(monkeypatch, stop_error, payload):
    """
    Purpose:
    Build a MalwareEmulator instance wired to the fake constrained engine.

    How it works:
    Bypasses MalwareEmulator.__init__ to avoid constructing real Speakeasy,
    then assigns the production extractor/tracker and fake se object directly.

    Parameters:
    - monkeypatch: Pytest fixture used to install fake Speakeasy modules.
    - stop_error: Exception raised by fake run_module().
    - payload: Bytes written before the fake stop is raised.

    Returns:
    Configured MalwareEmulator instance ready for run().
    """
    MalwareEmulator, StringExtractor, WriteTracker = _load_runtime(monkeypatch)
    emulator = MalwareEmulator.__new__(MalwareEmulator)
    emulator.module = object()
    emulator.extractor = StringExtractor()
    emulator.tracker = WriteTracker()
    emulator.execution_status = None
    emulator.se = FakeConstrainedSpeakeasy(
        tracker=emulator.tracker,
        payload=payload,
        base_address=0x1500,
        stop_error=stop_error,
    )
    return emulator


@pytest.mark.integration
@pytest.mark.tight_loop
@pytest.mark.parametrize(
    ("stop_error", "expected_status"),
    [
        (TimeoutError("timeout reached while sample stayed in tight loop"), "timeout"),
        (MaxInstructionsError("maximum instructions reached in tight loop"), "max_instructions"),
    ],
)
def test_get_extracted_strings_captures_payload_before_constrained_stop(
    monkeypatch,
    stop_error,
    expected_status,
):
    """
    Purpose:
    Verify extraction still works after timeout and max-instruction stops.

    How it works:
    Runs MalwareEmulator.run() against a fake Speakeasy object that drops a
    URL into tracked memory before raising a safe constrained-stop exception.

    Parameters:
    - monkeypatch: Pytest fixture used to avoid real Speakeasy imports.
    - stop_error: Parametrized fake stop exception raised by run_module().
    - expected_status: execution_status expected after MalwareEmulator.run().

    Returns:
    None; assertions validate status and extracted string content.
    """
    payload = b"http://tight-loop.example/dropper.exe\x00"
    emulator = _build_constrained_emulator(monkeypatch, stop_error, payload)

    emulator.run()

    results = emulator.get_extracted_strings()
    contents = [entry["content"] for entry in results]

    assert emulator.execution_status == expected_status
    assert emulator.se.did_drop_payload is True
    assert emulator.se.read_calls == [(0x1500, len(payload))]
    assert "http://tight-loop.example/dropper.exe" in contents


@pytest.mark.integration
@pytest.mark.tight_loop
def test_report_metadata_includes_constrained_stop_reason(monkeypatch, tmp_path):
    """
    Purpose:
    Verify constrained-run status metadata is written into the JSON report.

    How it works:
    Uses the fake timeout path, saves get_extracted_strings() results through
    ReportGenerator with main.py-compatible stop_reason metadata, and reads the
    generated JSON back from tmp_path.

    Parameters:
    - monkeypatch: Pytest fixture used to avoid real Speakeasy imports.
    - tmp_path: Pytest fixture for an isolated report output path.

    Returns:
    None; assertions validate execution_constraints and string preservation.
    """
    payload = b"http://metadata.example/after-timeout\x00"
    emulator = _build_constrained_emulator(
        monkeypatch,
        TimeoutError("timeout reached after payload drop"),
        payload,
    )
    emulator.run()

    report_path = tmp_path / "tight-loop-report.json"
    ReportGenerator(str(report_path)).save(
        emulator.get_extracted_strings(),
        metadata={"stop_reason": emulator.execution_status},
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["execution_constraints"] == {"stop_reason": "timeout"}
    assert report["total_strings"] == 1
    assert report["strings"][0]["content"] == "http://metadata.example/after-timeout"
