# -*- coding: utf-8 -*-
"""Unit tests for bounded register-pointer string scanning."""

import importlib
from collections.abc import Callable, Mapping, Set
from contextlib import AbstractContextManager
from typing import Protocol, cast, override

from core.extractor import StringExtractor


class _CapLog(Protocol):
    text: str

    def at_level(self, level: str, logger: str) -> AbstractContextManager[None]: ...

register_hooks = importlib.import_module("hooks.register_hooks")
DEFAULT_REGISTER_READ_SIZE = cast(
    int,
    getattr(register_hooks, "DEFAULT_REGISTER_READ_SIZE"),
)
setup_register_hooks = cast(
    Callable[..., None],
    getattr(register_hooks, "setup_register_hooks"),
)
scan_register_candidates = cast(
    Callable[..., list[str]],
    getattr(register_hooks, "scan_register_candidates"),
)


class FakeRegisterEngine:
    """Minimal emulator stub with register discovery and bounded memory reads."""

    def __init__(
        self,
        registers: Mapping[str, object] | None = None,
        memory: Mapping[int, bytes] | None = None,
        unreadable: Set[int] | None = None,
    ) -> None:
        """
        Purpose:
        Build a fake emulator with architecture-neutral register names.

        How it works:
        Stores a register mapping, byte buffers keyed by address, unreadable
        addresses, and a log of mem_read() calls for bound assertions.

        Parameters:
        - registers: mapping of register names to candidate pointer values.
        - memory: mapping of addresses to bytes returned by mem_read().
        - unreadable: set of addresses that should raise OSError.

        Returns:
        void
        """
        self._registers: dict[str, object] = dict(registers or {})
        self._memory: dict[int, bytes] = dict(memory or {})
        self._unreadable: set[int] = set(unreadable or set())
        self.read_calls: list[tuple[int, int]] = []

    def get_registers(self) -> dict[str, object]:
        """
        Purpose:
        Expose fake register values without assuming x86/x64 naming.

        How it works:
        Returns the mapping provided at construction time.

        Parameters:
        None.

        Returns:
        dict-like mapping of register name to integer value.
        """
        return self._registers

    def mem_read(self, address: int, size: int) -> bytes:
        """
        Purpose:
        Simulate Speakeasy mem_read() for pointer-dereference tests.

        How it works:
        Records each read, raises for configured unreadable addresses, and
        otherwise returns the configured bytes truncated to the requested size.

        Parameters:
        - address: virtual address to read.
        - size: maximum number of bytes requested.

        Returns:
        bytes read from the fake memory map.
        """
        self.read_calls.append((address, size))
        if address in self._unreadable:
            raise OSError(f"unmapped address {hex(address)}")
        if address not in self._memory:
            raise OSError(f"unmapped address {hex(address)}")
        return self._memory[address][:size]


def _results(extractor: StringExtractor) -> list[dict[str, object]]:
    """
    Purpose:
    Give register-hook tests a typed view of StringExtractor results.

    How it works:
    Casts the untyped project result list to the JSON-like dict shape these
    tests assert against, without changing production extractor behavior.

    Parameters:
    - extractor: StringExtractor instance under test.

    Returns:
    A list of result dictionaries.
    """
    return cast(list[dict[str, object]], extractor.get_results())


def test_scan_register_candidates_reads_pointer_and_ingests_register_source() -> None:
    """
    Purpose:
    Verify a register pointer to a null-terminated ASCII string is captured.

    How it works:
    Uses a fake register named r0 pointing at b"decoded.example\x00" and
    asserts the helper records it through StringExtractor candidate ingestion.

    Parameters:
    None.

    Returns:
    void
    """
    emu = FakeRegisterEngine(
        registers={"r0": 0x1000},
        memory={0x1000: b"decoded.example\x00ignored"},
    )
    extractor = StringExtractor()

    findings = scan_register_candidates(emu, extractor)

    assert findings == ["decoded.example"]
    assert emu.read_calls == [(0x1000, DEFAULT_REGISTER_READ_SIZE)]
    results = _results(extractor)
    assert len(results) == 1
    assert results[0]["content"] == "decoded.example"
    assert results[0]["encoding"] == "CANDIDATE"
    assert results[0]["source"] == "register_scan"
    assert results[0]["location"] == "r0:0x1000"


def test_scan_register_candidates_ignores_unmapped_pointer_without_crashing() -> None:
    """
    Purpose:
    Ensure invalid register pointers are skipped safely.

    How it works:
    Points one fake register at an unreadable address and another at zero;
    the helper should catch the memory error and avoid a zero-address read.

    Parameters:
    None.

    Returns:
    void
    """
    emu = FakeRegisterEngine(
        registers={"r0": 0xDEAD, "r1": 0},
        unreadable={0xDEAD},
    )
    extractor = StringExtractor()

    findings = scan_register_candidates(emu, extractor)

    assert findings == []
    assert extractor.get_results() == []
    assert emu.read_calls == [(0xDEAD, DEFAULT_REGISTER_READ_SIZE)]


def test_scan_register_candidates_caps_mem_read_count() -> None:
    """
    Purpose:
    Verify register scanning cannot read an unbounded number of pointers.

    How it works:
    Provides six valid register pointers but sets max_reads=3, then asserts
    only the first three mem_read() calls and candidate results occur.

    Parameters:
    None.

    Returns:
    void
    """
    registers = {f"reg{i}": 0x2000 + (i * 0x100) for i in range(6)}
    memory = {
        address: f"value{i}.example\x00".encode("ascii")
        for i, address in enumerate(registers.values())
    }
    emu = FakeRegisterEngine(registers=registers, memory=memory)
    extractor = StringExtractor()

    findings = scan_register_candidates(emu, extractor, max_reads=3)

    assert findings == ["value0.example", "value1.example", "value2.example"]
    assert len(emu.read_calls) == 3
    assert [content["content"] for content in _results(extractor)] == findings


def test_scan_register_candidates_accepts_explicit_arch_neutral_values() -> None:
    """
    Purpose:
    Ensure callers can pass register values without x86/x64 assumptions.

    How it works:
    Gives explicit ARM-style register names to a memory-only fake emulator;
    the helper should use those values instead of requiring named CPU APIs.

    Parameters:
    None.

    Returns:
    void
    """
    emu = FakeRegisterEngine(memory={0x3000: b"armvalue.example\x00"})
    extractor = StringExtractor()

    findings = scan_register_candidates(
        emu,
        extractor,
        register_values=[("x0", 0x3000), ("sp", "not-a-pointer")],
    )

    assert findings == ["armvalue.example"]
    assert emu.read_calls == [(0x3000, DEFAULT_REGISTER_READ_SIZE)]
    assert _results(extractor)[0]["location"] == "x0:0x3000"


class FakeCodeHookEngine(FakeRegisterEngine):
    """Fake engine that stores the registered code hook callback."""

    def __init__(
        self,
        registers: Mapping[str, object] | None = None,
        memory: Mapping[int, bytes] | None = None,
    ) -> None:
        """
        Purpose:
        Build a fake register engine that supports add_code_hook().

        How it works:
        It extends FakeRegisterEngine and stores callbacks registered by
        setup_register_hooks() so tests can simulate repeated instruction hooks.

        Parameters:
        - registers: mapping of register names to candidate pointer values.
        - memory: mapping of addresses to bytes returned by mem_read().

        Returns:
        void
        """
        super().__init__(registers=registers, memory=memory)
        self.code_hooks: list[Callable[[object, int, int], None]] = []

    def add_code_hook(self, callback: Callable[[object, int, int], None]) -> object:
        """
        Purpose:
        Capture a code hook callback for test-driven invocation.

        How it works:
        Appends the callback to code_hooks and returns it as a harmless handle.

        Parameters:
        - callback: code hook callable registered by production setup.

        Returns:
        The callback handle.
        """
        self.code_hooks.append(callback)
        return callback


class BrokenRegisterEngine(FakeRegisterEngine):
    """Fake engine whose register accessor raises."""

    @override
    def get_registers(self) -> dict[str, object]:
        """
        Purpose:
        Simulate an emulator register snapshot failure.

        How it works:
        Raises RuntimeError whenever register values are requested.

        Parameters:
        None.

        Returns:
        Never returns; raises RuntimeError.
        """
        raise RuntimeError("register snapshot unavailable")


def test_setup_register_hooks_caps_total_code_hook_scans() -> None:
    """
    Purpose:
    Verify code-hook register scanning has a finite per-run budget.

    How it works:
    Registers the production code hook with max_hook_scans=2, invokes it five
    times, and asserts only two memory reads occur despite repeated callbacks.

    Parameters:
    None.

    Returns:
    void
    """
    emu = FakeCodeHookEngine(
        registers={"r0": 0x4000},
        memory={0x4000: b"budget.example\x00"},
    )
    extractor = StringExtractor()

    setup_register_hooks(emu, extractor, max_hook_scans=2)
    hook = emu.code_hooks[0]
    for index in range(5):
        hook(emu, 0x1000 + index, 1)

    assert emu.read_calls == [
        (0x4000, DEFAULT_REGISTER_READ_SIZE),
        (0x4000, DEFAULT_REGISTER_READ_SIZE),
    ]


def test_iter_register_values_logs_accessor_failure(caplog: _CapLog) -> None:
    """
    Purpose:
    Verify register snapshot failures are visible to debugging.

    How it works:
    Uses an engine whose get_registers() raises, then asserts the scan remains
    non-fatal while emitting a debug log that names the failed accessor.

    Parameters:
    - caplog: pytest log capture fixture.

    Returns:
    void
    """
    emu = BrokenRegisterEngine()
    extractor = StringExtractor()

    with caplog.at_level("DEBUG", logger="hooks.register_hooks"):
        findings = scan_register_candidates(emu, extractor)

    assert findings == []
    assert "get_registers" in caplog.text
    assert "register snapshot unavailable" in caplog.text
