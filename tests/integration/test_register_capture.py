# -*- coding: utf-8 -*-
"""Integration tests for automatic register-string capture lifecycle wiring."""

from typing import cast

from core.emulator import MalwareEmulator


class RegisterLifecycleEngine:
    """
    Purpose:
    Simulate the Speakeasy surface used by MalwareEmulator lifecycle tests.

    How it works:
    Stores fake register values, readable memory, hook-registration calls, and
    run_module() invocations so tests can assert automatic register capture.

    Parameters:
    None.

    Returns:
    A fake Speakeasy-like engine instance.
    """

    def __init__(self) -> None:
        self._registers: dict[str, int] = {"eax": 0x4100, "ebx": 0xDEAD}
        self._memory: dict[int, bytes] = {0x4100: b"register-final.example\x00"}
        self.run_calls: list[object] = []
        self.mem_read_calls: list[tuple[int, int]] = []
        self.mem_write_hooks: list[object] = []
        self.api_hooks: list[tuple[str, str]] = []
        self.code_hooks: list[object] = []

    def run_module(self, module: object) -> None:
        """
        Purpose:
        Record that MalwareEmulator invoked the fake module execution.

        How it works:
        Appends the module object to run_calls and returns without raising.

        Parameters:
        - module: loaded module object passed by MalwareEmulator.run().

        Returns:
        void
        """
        self.run_calls.append(module)

    def get_json_report(self) -> str:
        """
        Purpose:
        Provide an empty Speakeasy JSON report for final extraction.

        How it works:
        Returns the minimal JSON object shape consumed by _extract_from_report().

        Parameters:
        None.

        Returns:
        A JSON string with no report-derived strings.
        """
        return "{}"

    def add_mem_write_hook(self, callback: object) -> None:
        """
        Purpose:
        Accept memory-hook registration during MalwareEmulator.register_hooks().

        How it works:
        Stores the callback without invoking it.

        Parameters:
        - callback: memory write hook callback.

        Returns:
        void
        """
        self.mem_write_hooks.append(callback)

    def add_api_hook(self, callback: object, module: str, api_name: str) -> None:
        """
        Purpose:
        Accept API-hook registration during MalwareEmulator.register_hooks().

        How it works:
        Stores the module and API names for registration assertions.

        Parameters:
        - callback: API hook callback.
        - module: DLL module name.
        - api_name: API export name.

        Returns:
        void
        """
        _ = callback
        self.api_hooks.append((module, api_name))

    def add_code_hook(self, callback: object) -> None:
        """
        Purpose:
        Accept optional register code-hook registration.

        How it works:
        Stores the callback so the test can assert the safe hook was installed.

        Parameters:
        - callback: code hook callback.

        Returns:
        void
        """
        self.code_hooks.append(callback)

    def get_registers(self) -> dict[str, int]:
        """
        Purpose:
        Expose fake register pointers for register scanning.

        How it works:
        Returns one readable pointer and one unreadable pointer.

        Parameters:
        None.

        Returns:
        Mapping of register names to integer values.
        """
        return dict(self._registers)

    def mem_read(self, address: int, size: int) -> bytes:
        """
        Purpose:
        Simulate bounded Speakeasy memory reads for register pointers.

        How it works:
        Records each read and returns configured memory truncated to size;
        missing addresses raise OSError to test safe fallback.

        Parameters:
        - address: virtual address to read.
        - size: maximum number of bytes requested.

        Returns:
        Bytes read from fake memory.
        """
        self.mem_read_calls.append((address, size))
        if address not in self._memory:
            raise OSError(f"unmapped address {hex(address)}")
        return self._memory[address][:size]


class NoCodeHookEngine(RegisterLifecycleEngine):
    """
    Purpose:
    Simulate a Speakeasy engine without optional code-hook support.

    How it works:
    Inherits the register/memory behavior but intentionally omits
    add_code_hook() so setup must fall back cleanly.

    Parameters:
    None.

    Returns:
    A fake engine instance without add_code_hook().
    """

    def __getattribute__(self, name: str) -> object:  # pyright: ignore[reportImplicitOverride]
        """
        Purpose:
        Hide add_code_hook to model engines without optional hook support.

        How it works:
        Raises AttributeError only for add_code_hook and delegates all other
        attribute access to RegisterLifecycleEngine.

        Parameters:
        - name: attribute name being accessed.

        Returns:
        The requested attribute value for all supported attributes.
        """
        if name == "add_code_hook":
            raise AttributeError(name)
        return cast(object, super().__getattribute__(name))


def _build_emulator(engine: RegisterLifecycleEngine) -> MalwareEmulator:
    """
    Purpose:
    Create a MalwareEmulator using a fake Speakeasy engine.

    How it works:
    Constructs MalwareEmulator normally, replaces its engine with the fake, and
    marks a module as loaded so run() executes the lifecycle.

    Parameters:
    - engine: fake Speakeasy-like engine to install on the emulator.

    Returns:
    Configured MalwareEmulator instance.
    """
    emu = MalwareEmulator()
    setattr(emu, "se", engine)
    emu.module = object()
    return emu


def test_register_capture_runs_automatically_after_emulation() -> None:
    """
    Purpose:
    Verify register scanning runs automatically at the end of emulation.

    How it works:
    Runs MalwareEmulator with a fake engine whose eax points to a string and
    asserts the exact row keeps register_scan/eax provenance without relying on
    CLI debug flags or manual scanning.

    Parameters:
    None.

    Returns:
    void
    """
    engine = RegisterLifecycleEngine()
    emu = _build_emulator(engine)

    emu.run()

    module = cast(object, emu.module)
    assert engine.run_calls == [module]
    results = cast(list[dict[str, object]], emu.get_extracted_strings())
    results_by_content = {cast(str, result["content"]): result for result in results}
    register_row = results_by_content["register-final.example"]
    assert register_row["source"] == "register_scan"
    assert register_row["source_detail"] == "eax"


def test_register_hooks_install_safe_code_hook_when_supported() -> None:
    """
    Purpose:
    Verify optional during-run register tracking is registered when supported.

    How it works:
    Calls MalwareEmulator.register_hooks() on a fake engine exposing
    add_code_hook() and asserts memory, API, and register hook setup all occur.

    Parameters:
    None.

    Returns:
    void
    """
    engine = RegisterLifecycleEngine()
    emu = _build_emulator(engine)

    emu.register_hooks()

    assert len(engine.mem_write_hooks) == 1
    assert engine.api_hooks
    assert len(engine.code_hooks) == 1


def test_register_hook_setup_falls_back_when_code_hooks_missing() -> None:
    """
    Purpose:
    Ensure engines without code-hook support still register existing hooks.

    How it works:
    Uses a fake engine where add_code_hook is not callable, then asserts
    register_hooks() completes without raising and run() still emits the exact
    register_scan/eax row through its after-run finalization path.

    Parameters:
    None.

    Returns:
    void
    """
    engine = NoCodeHookEngine()
    emu = _build_emulator(engine)

    emu.register_hooks()
    emu.run()

    assert len(engine.mem_write_hooks) == 1
    results = cast(list[dict[str, object]], emu.get_extracted_strings())
    results_by_content = {cast(str, result["content"]): result for result in results}
    register_row = results_by_content["register-final.example"]
    assert register_row["source"] == "register_scan"
    assert register_row["source_detail"] == "eax"
