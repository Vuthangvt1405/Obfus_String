# pyright: reportMissingImports=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportAttributeAccessIssue=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportAny=false, reportUntypedFunctionDecorator=false, reportUnusedParameter=false, reportUnknownLambdaType=false, reportUnknownVariableType=false, reportUnannotatedClassAttribute=false, reportUnusedCallResult=false
"""
Purpose:
Integration tests for the default static scanning path in MalwareEmulator.

How it works:
The tests use a fake Speakeasy module loader so they can exercise
load_sample() without real PE files while still verifying strings flow into
the production StringExtractor before runtime emulation.
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
        Serializes empty entry_points and in_memory buckets so any extracted
        static strings must have come from load_sample(), not the report.

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
def test_load_sample_runs_static_scan_by_default(monkeypatch, tmp_path) -> None:
    """
    Purpose:
    Verify load_sample() automatically scans raw sample bytes for strings.

    How it works:
    Writes a deterministic byte buffer to tmp_path, loads it through a fake
    Speakeasy engine, and asserts the static string reaches StringExtractor
    before any runtime emulation report is involved.

    Parameters:
    - monkeypatch: Pytest fixture used to install fake Speakeasy modules.
    - tmp_path: Pytest fixture for the temporary sample file.

    Returns:
    None.
    """
    emulator, engine, _ = _build_emulator(monkeypatch)
    sample_path = tmp_path / "static-sample.bin"
    sample_path.write_bytes(b"\x90\x90http://static.example/payload.exe\x00\xff")

    loaded_module = emulator.load_sample(str(sample_path))

    results = emulator.get_extracted_strings()
    static_result = next(
        result for result in results
        if result["content"] == "http://static.example/payload.exe"
    )
    assert loaded_module is engine.module
    assert engine.loaded_paths == [str(sample_path)]
    assert static_result["source"] == "static_scan"
    assert static_result["encoding"] == "ASCII"


@pytest.mark.integration
def test_static_scan_failure_does_not_abort_load_sample(monkeypatch, tmp_path) -> None:
    """
    Purpose:
    Verify static scanning errors are non-fatal to normal sample loading.

    How it works:
    Replaces the emulator's scan_file dependency with a callable that raises,
    then asserts load_sample() still delegates to Speakeasy and returns the
    loaded module.

    Parameters:
    - monkeypatch: Pytest fixture used to patch dependencies.
    - tmp_path: Pytest fixture for the temporary sample file.

    Returns:
    None.
    """
    emulator, engine, emulator_module = _build_emulator(monkeypatch)
    sample_path = tmp_path / "scan-error-sample.bin"
    sample_path.write_bytes(b"http://scan-error.example/")
    calls: list[str] = []

    def failing_scan_file(file_path: str, extractor: object) -> list[dict[str, object]]:
        """
        Purpose:
        Simulate an unexpected static scanner failure for load_sample().

        How it works:
        Records the path it was asked to scan, then raises RuntimeError.

        Parameters:
        - file_path: Sample path passed to the scanner.
        - extractor: StringExtractor instance owned by the emulator.

        Returns:
        Never returns; raises RuntimeError.
        """
        calls.append(file_path)
        raise RuntimeError("static scanner failed")

    monkeypatch.setattr(emulator_module, "scan_file", failing_scan_file, raising=False)

    loaded_module = emulator.load_sample(str(sample_path))

    assert calls == [str(sample_path)]
    assert loaded_module is engine.module
    assert engine.loaded_paths == [str(sample_path)]
