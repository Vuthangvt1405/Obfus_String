# -*- coding: utf-8 -*-
# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUntypedFunctionDecorator=false
"""Integration coverage for high-recall function-decoded string outputs."""

import json
from collections.abc import Callable
from typing import ClassVar, cast

import pytest

from core.emulator import MalwareEmulator
from core.extractor import StringExtractor
from hooks.mem_hooks import WriteTracker


ApiCallback = Callable[[object, str, object, list[object]], None]
MemWriteCallback = Callable[[object, object, int, int, object], None]
CodeCallback = Callable[[object, int, int], None]


class FunctionDecodedEngine:
    """
    Purpose:
    Simulate a Speakeasy-like engine that exposes decoded function outputs.

    How it works:
    Stores bytes in a virtual memory map, records production hooks installed by
    MalwareEmulator.register_hooks(), and run_module() simulates a decoder
    function writing plaintext, passing it to an API, and returning a pointer in
    a register.

    Parameters:
    - memory_output: Plaintext bytes written by the simulated decode function.
    - api_output: Plaintext string exposed through a hooked API argument.
    - register_output: Plaintext bytes pointed to by a register after decoding.
    - bad_pointers: Optional unreadable addresses used to prove safe skipping.

    Returns:
    A fake engine instance for MalwareEmulator integration tests.
    """

    MEMORY_ADDRESS: ClassVar[int] = 0x2000
    API_ADDRESS: ClassVar[int] = 0x3000
    REGISTER_ADDRESS: ClassVar[int] = 0x4000
    BAD_POINTER: ClassVar[int] = 0xDEAD

    def __init__(
        self,
        memory_output: bytes,
        api_output: str,
        register_output: bytes,
        bad_pointers: set[int] | None = None,
    ) -> None:
        self.memory_output: bytes = memory_output
        self.api_output: str = api_output
        self.register_output: bytes = register_output
        self.bad_pointers: set[int] = bad_pointers or {self.BAD_POINTER}
        self._memory: dict[int, int] = {}
        self._registers: dict[str, int] = {
            "eax": 0,
            "ecx": self.BAD_POINTER,
        }
        self.mem_write_hooks: list[MemWriteCallback] = []
        self.api_hooks: dict[tuple[str, str], ApiCallback] = {}
        self.code_hooks: list[CodeCallback] = []
        self.run_calls: list[object] = []
        self.mem_read_calls: list[tuple[int, int]] = []
        self.read_mem_string_calls: list[tuple[int, int]] = []

        self._write_bytes(self.API_ADDRESS, api_output.encode("ascii") + b"\x00")
        self._write_bytes(self.REGISTER_ADDRESS, register_output)

    def add_mem_write_hook(self, callback: MemWriteCallback) -> None:
        """
        Purpose:
        Record a production memory-write hook.

        How it works:
        Appends the callback so mem_write() can invoke it with the same shape
        Speakeasy uses during emulation.

        Parameters:
        - callback: Memory-write hook installed by setup_memory_hooks().

        Returns:
        void
        """
        self.mem_write_hooks.append(callback)

    def add_api_hook(
        self,
        callback: ApiCallback,
        module: str,
        api_name: str,
    ) -> None:
        """
        Purpose:
        Record a production API hook by module and API name.

        How it works:
        Stores the callback under its (module, api_name) pair so run_module()
        can fire the same hook a decoded function would reach at runtime.

        Parameters:
        - callback: API callback installed by setup_api_hooks().
        - module: DLL module name.
        - api_name: Exported API name.

        Returns:
        void
        """
        self.api_hooks[(module, api_name)] = callback

    def add_code_hook(self, callback: CodeCallback) -> None:
        """
        Purpose:
        Record a production code hook for register scanning.

        How it works:
        Appends the callback so run_module() can trigger during-run register
        scanning after the simulated decoder has populated eax.

        Parameters:
        - callback: Code hook installed by setup_register_hooks().

        Returns:
        void
        """
        self.code_hooks.append(callback)

    def run_module(self, module: object) -> None:
        """
        Purpose:
        Simulate a function-decoder execution path.

        How it works:
        Records the module, writes decoded memory output in two adjacent chunks,
        points eax at another decoded output, fires code hooks for register
        capture, then invokes lstrcpyA with a decoded API argument and one bad
        pointer to prove bad pointers do not crash extraction.

        Parameters:
        - module: Loaded module object passed by MalwareEmulator.run().

        Returns:
        void
        """
        self.run_calls.append(module)
        split_at = max(1, len(self.memory_output) // 2)
        self.mem_write(self.MEMORY_ADDRESS, self.memory_output[:split_at])
        self.mem_write(self.MEMORY_ADDRESS + split_at, self.memory_output[split_at:])

        self._registers["eax"] = self.REGISTER_ADDRESS
        for callback in self.code_hooks:
            callback(self, 0x401000, 5)

        lstrcpy = self.api_hooks.get(("kernel32", "lstrcpyA"))
        if lstrcpy is not None:
            lstrcpy(self, "lstrcpyA", None, [0x5000, self.API_ADDRESS])
            lstrcpy(self, "lstrcpyA", None, [0x5000, self.BAD_POINTER])

    def mem_write(self, address: int, data: bytes) -> None:
        """
        Purpose:
        Write bytes into virtual memory and notify registered write hooks.

        How it works:
        Commits the bytes first so hook-time reads see post-write data, then
        invokes each memory hook with a Speakeasy-compatible callback shape.

        Parameters:
        - address: Destination virtual address.
        - data: Bytes being written.

        Returns:
        void
        """
        self._write_bytes(address, data)
        value = int.from_bytes(data, byteorder="little") if data else 0
        for callback in self.mem_write_hooks:
            callback(self, None, address, len(data), value)

    def mem_read(self, address: int, size: int) -> bytes:
        """
        Purpose:
        Provide bounded bytes for memory and register extraction paths.

        How it works:
        Raises for configured bad pointers, otherwise returns requested bytes
        from the virtual memory map with zero fill for mapped-but-short strings.

        Parameters:
        - address: Starting virtual address to read.
        - size: Number of bytes requested.

        Returns:
        Bytes read from fake virtual memory.
        """
        self.mem_read_calls.append((address, size))
        if address in self.bad_pointers:
            raise OSError(f"unmapped address {hex(address)}")
        return bytes(self._memory.get(address + offset, 0) for offset in range(size))

    def read_mem_string(self, ptr: int, width: int = 1) -> str:
        """
        Purpose:
        Decode a null-terminated API argument string from virtual memory.

        How it works:
        Reads byte-by-byte for ANSI and word-by-word for UTF-16LE until a null
        terminator is found. Bad pointers raise so API hooks can skip them.

        Parameters:
        - ptr: Starting virtual address of the string.
        - width: Character width, 1 for ANSI or 2 for UTF-16LE.

        Returns:
        The decoded string.
        """
        self.read_mem_string_calls.append((ptr, width))
        if ptr in self.bad_pointers or ptr <= 0:
            raise OSError(f"unmapped address {hex(ptr)}")
        if width == 1:
            data = bytearray()
            offset = 0
            while self._memory.get(ptr + offset, 0) != 0:
                data.append(self._memory.get(ptr + offset, 0))
                offset += 1
            return data.decode("ascii")

        data = bytearray()
        offset = 0
        while not (
            self._memory.get(ptr + offset, 0) == 0
            and self._memory.get(ptr + offset + 1, 0) == 0
        ):
            data.extend([
                self._memory.get(ptr + offset, 0),
                self._memory.get(ptr + offset + 1, 0),
            ])
            offset += 2
        return data.decode("utf-16-le")

    def get_registers(self) -> dict[str, int]:
        """
        Purpose:
        Expose register pointers for scan_register_candidates().

        How it works:
        Returns a copy of the fake register mapping so scanner mutations cannot
        affect engine state.

        Parameters:
        None.

        Returns:
        Mapping of register names to candidate pointer values.
        """
        return dict(self._registers)

    def get_json_report(self) -> str:
        """
        Purpose:
        Provide an empty Speakeasy report for final report extraction.

        How it works:
        Returns the minimal report shape consumed by MalwareEmulator so this
        integration test proves capture through hooks and registers instead.

        Parameters:
        None.

        Returns:
        JSON string with no report-derived strings.
        """
        return json.dumps({"entry_points": [], "strings": {"in_memory": {}}})

    def _write_bytes(self, address: int, data: bytes) -> None:
        """
        Purpose:
        Store bytes in the fake virtual memory map.

        How it works:
        Writes each byte at address + offset so mem_read() and read_mem_string()
        can serve both range reads and C-string reads.

        Parameters:
        - address: Starting virtual address.
        - data: Bytes to store.

        Returns:
        void
        """
        for offset, byte in enumerate(data):
            self._memory[address + offset] = byte


def _build_emulator(engine: FunctionDecodedEngine) -> MalwareEmulator:
    """
    Purpose:
    Create a MalwareEmulator around a fake decoded-output engine.

    How it works:
    Bypasses MalwareEmulator.__init__ to avoid constructing real Speakeasy and
    installs the production extractor/tracker pair used by runtime extraction.

    Parameters:
    - engine: Fake Speakeasy-like engine to install.

    Returns:
    Configured MalwareEmulator instance ready for register_hooks() and run().
    """
    emulator = MalwareEmulator.__new__(MalwareEmulator)
    emulator.module = object()
    emulator.extractor = StringExtractor()
    emulator.tracker = WriteTracker()
    emulator.execution_status = None
    emulator.se = engine
    return emulator


def _results_by_content(emulator: MalwareEmulator) -> dict[str, dict[str, object]]:
    """
    Purpose:
    Index extracted string rows by content for integration assertions.

    How it works:
    Casts MalwareEmulator output to the JSON-like result shape and builds a
    dictionary keyed by each unique string content.

    Parameters:
    - emulator: MalwareEmulator whose extracted strings should be indexed.

    Returns:
    Mapping from string content to extracted result entry.
    """
    results = cast(list[dict[str, object]], emulator.get_extracted_strings())
    return {cast(str, result["content"]): result for result in results}


@pytest.mark.integration
def test_decoded_outputs_capture_memory_api_and_register_paths() -> None:
    """
    Purpose:
    Verify one function-decoder path reaches memory, API, and register outputs.

    How it works:
    Runs MalwareEmulator with a fake engine that writes a decoded memory buffer,
    invokes lstrcpyA with another decoded string, and leaves a third decoded
    pointer in eax. Assertions check production provenance for all three paths.

    Parameters:
    None.

    Returns:
    void
    """
    engine = FunctionDecodedEngine(
        memory_output=b"memory-decoded.example/path\x00",
        api_output="api-decoded.example",
        register_output=b"register-decoded.example\x00",
    )
    emulator = _build_emulator(engine)

    emulator.register_hooks()
    emulator.run()

    results = _results_by_content(emulator)
    module = cast(object, emulator.module)
    assert engine.run_calls == [module]
    assert results["memory-decoded.example/path"]["source"] == "deferred_scan"
    assert results["api-decoded.example"]["source"] == "api_hook"
    assert results["api-decoded.example"]["source_detail"] == "lstrcpyA"
    assert results["register-decoded.example"]["source"] == "register_scan"
    assert results["register-decoded.example"]["source_detail"] == "eax"


@pytest.mark.integration
def test_decoded_outputs_deduplicate_and_skip_bad_pointers_without_crashing() -> None:
    """
    Purpose:
    Verify the same decoded output can traverse all paths without duplicates.

    How it works:
    Sends one shared decoded string through memory, lstrcpyA, and eax while the
    fake engine also exposes invalid API/register pointers. The final row should
    be the single high-confidence API provenance entry and no exception should
    escape the run.

    Parameters:
    None.

    Returns:
    void
    """
    shared_output = "shared-decoded.example"
    engine = FunctionDecodedEngine(
        memory_output=f"{shared_output}\x00".encode("ascii"),
        api_output=shared_output,
        register_output=f"{shared_output}\x00".encode("ascii"),
    )
    emulator = _build_emulator(engine)

    emulator.register_hooks()
    emulator.run()

    results = _results_by_content(emulator)
    matching_rows = [
        result
        for result in cast(list[dict[str, object]], emulator.get_extracted_strings())
        if result["content"] == shared_output
    ]

    assert len(matching_rows) == 1
    assert results[shared_output]["source"] == "api_hook"
    assert results[shared_output]["source_detail"] == "lstrcpyA"
    assert (FunctionDecodedEngine.BAD_POINTER, 1) in engine.read_mem_string_calls
    assert any(call[0] == FunctionDecodedEngine.BAD_POINTER for call in engine.mem_read_calls)
