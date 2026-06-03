# pyright: reportMissingImports=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportAttributeAccessIssue=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportAny=false, reportUntypedFunctionDecorator=false, reportUnusedParameter=false, reportUnknownLambdaType=false, reportUnknownVariableType=false, reportUnannotatedClassAttribute=false, reportUnusedCallResult=false
"""
Purpose:
Integration tests for load_sample() before runtime emulation.

How it works:
The tests use a fake Speakeasy module loader so they can exercise
load_sample() without real PE files while verifying raw file bytes are not
emitted as string results before runtime emulation observes them.
"""

from __future__ import annotations

import importlib
import json
import sys
import types

import pytest


class FakeModule:
    """
    Purpose:
    Provide the minimal loaded-module interface MalwareEmulator.load_sample()
    logs after Speakeasy accepts a sample.

    How it works:
    Exposes a base address, an entry-point getter, and an empty section list.

    Parameters:
    None.

    Returns:
    A fake loaded module object.
    """

    base = 0x400000
    sections: list[object] = []

    def get_ep(self) -> int:
        """
        Purpose:
        Return the fake module entry point used by load_sample() logging.

        How it works:
        Returns a constant RVA-like integer.

        Parameters:
        None.

        Returns:
        The fake entry point integer.
        """
        return 0x401000


class FakeSpeakeasyEngine:
    """
    Purpose:
    Simulate the Speakeasy methods touched by load_sample() and run().

    How it works:
    Records loaded paths, returns FakeModule from load_module(), provides an
    empty JSON report, and records run_module() calls without doing emulation.

    Parameters:
    None.

    Returns:
    A fake Speakeasy engine instance.
    """

    def __init__(self) -> None:
        self.module = FakeModule()
        self.loaded_paths: list[str] = []
        self.ran_modules: list[object] = []

    def load_module(self, file_path: str) -> FakeModule:
        """
        Purpose:
        Record the sample path and return a fake loaded module.

        How it works:
        Appends file_path to loaded_paths, then returns the reusable module.

        Parameters:
        - file_path: Sample path passed through MalwareEmulator.load_sample().

        Returns:
        The fake loaded module.
        """
        self.loaded_paths.append(file_path)
        return self.module

    def run_module(self, module: object) -> None:
        """
        Purpose:
        Record runtime execution without invoking a real emulator.

        How it works:
        Appends the module argument to ran_modules and returns normally.

        Parameters:
        - module: Module object passed by MalwareEmulator.run().

        Returns:
        None.
        """
        self.ran_modules.append(module)

    def get_json_report(self) -> str:
        """
        Purpose:
        Provide the minimal report shape consumed by _extract_from_report().

        How it works:
        Serializes empty entry_points and in_memory buckets so strings cannot
        appear unless load_sample() scans raw bytes before emulation.

        Parameters:
        None.

        Returns:
        JSON string with empty Speakeasy report sections.
        """
        return json.dumps({"entry_points": [], "strings": {"in_memory": {}}})


def _install_fake_speakeasy(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Purpose:
    Make core.emulator importable without the real Speakeasy package.

    How it works:
    Installs fake speakeasy and speakeasy.errors modules with the attributes
    imported by core.emulator, then removes any cached core.emulator module so
    the next import binds to the fake dependencies.

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

    fake_errors.SpeakeasyError = SpeakeasyError
    fake_errors.NotSupportedError = NotSupportedError
    fake_speakeasy.errors = fake_errors
    fake_speakeasy.config = types.SimpleNamespace(get_default_config_dict=lambda: {})
    fake_speakeasy.Speakeasy = lambda config=None: object()

    monkeypatch.setitem(sys.modules, "speakeasy", fake_speakeasy)
    monkeypatch.setitem(sys.modules, "speakeasy.errors", fake_errors)
    monkeypatch.delitem(sys.modules, "core.emulator", raising=False)


def _build_emulator(monkeypatch: pytest.MonkeyPatch):
    """
    Purpose:
    Create a MalwareEmulator instance backed by fake Speakeasy dependencies.

    How it works:
    Installs fake Speakeasy modules, imports production classes, constructs the
    emulator normally, then swaps in FakeSpeakeasyEngine for sample loading and
    runtime execution.

    Parameters:
    - monkeypatch: Pytest fixture used to isolate module dependencies.

    Returns:
    Tuple of (emulator, fake engine, core.emulator module).
    """
    _install_fake_speakeasy(monkeypatch)
    emulator_module = importlib.import_module("core.emulator")
    emulator = emulator_module.MalwareEmulator()
    engine = FakeSpeakeasyEngine()
    emulator.se = engine
    return emulator, engine, emulator_module


@pytest.mark.integration
def test_load_sample_does_not_emit_raw_ascii_before_emulation(monkeypatch, tmp_path) -> None:
    """
    Purpose:
    Verify load_sample() does not emit raw ASCII strings before emulation.

    How it works:
    Writes a deterministic raw ASCII byte buffer, loads it through a fake
    Speakeasy engine, and asserts no pre-runtime result contains the raw string
    because raw file bytes should not be emitted before emulation.

    Parameters:
    - monkeypatch: Pytest fixture used to install fake Speakeasy modules.
    - tmp_path: Pytest fixture for the temporary sample file.

    Returns:
    None.
    """
    emulator, engine, _ = _build_emulator(monkeypatch)
    sample_path = tmp_path / "raw-ascii-sample.bin"
    raw_ascii = "http://static.example/payload.exe"
    sample_path.write_bytes(b"\x90\x90" + raw_ascii.encode("ascii") + b"\x00\xff")

    loaded_module = emulator.load_sample(str(sample_path))

    results = emulator.get_extracted_strings()
    contents = {result["content"] for result in results}
    assert loaded_module is engine.module
    assert engine.loaded_paths == [str(sample_path)]
    assert raw_ascii not in contents


@pytest.mark.integration
def test_load_sample_does_not_emit_raw_utf16le_before_emulation(monkeypatch, tmp_path) -> None:
    """
    Purpose:
    Verify load_sample() does not emit raw UTF-16LE strings before emulation.

    How it works:
    Writes a sample whose only meaningful string is UTF-16LE raw file bytes,
    loads it through a fake Speakeasy engine, and asserts no pre-runtime result
    contains that wide string.

    Parameters:
    - monkeypatch: Pytest fixture used to install fake Speakeasy modules.
    - tmp_path: Pytest fixture for the temporary sample file.

    Returns:
    None.
    """
    emulator, engine, _ = _build_emulator(monkeypatch)
    sample_path = tmp_path / "raw-wide-sample.bin"
    raw_wide = "http://wide.example/payload"
    sample_path.write_bytes(b"\xff\x00\xff" + raw_wide.encode("utf-16le") + b"\x00")

    loaded_module = emulator.load_sample(str(sample_path))

    results = emulator.get_extracted_strings()
    contents = {result["content"] for result in results}
    assert loaded_module is engine.module
    assert engine.loaded_paths == [str(sample_path)]
    assert raw_wide not in contents
