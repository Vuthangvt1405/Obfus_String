# -*- coding: utf-8 -*-
# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUntypedFunctionDecorator=false, reportImplicitOverride=false
"""Integration coverage for high-recall function-decoded string outputs."""

import json
from collections.abc import Callable
from typing import ClassVar, cast

import pytest

from core.emulator import MalwareEmulator
from core.extractor import StringExtractor
from hooks.mem_hooks import MAX_EXECUTE_AFTER_WRITE_SNAPSHOTS, WriteTracker
from hooks.register_hooks import DEFAULT_MAX_CODE_HOOK_SCANS


ApiCallback = Callable[[object, str, object, list[object]], None]
MemWriteCallback = Callable[[object, object, int, int, object], None]
CodeCallback = Callable[[object, int, int], None]


class FunctionDecodedEngine:
    """
    Purpose:
    Simulate a Speakeasy-like engine that exposes decoded function outputs.

    How it works:
    Stores pending decoded outputs outside virtual memory, records production
    hooks installed by MalwareEmulator.register_hooks(), and run_module()
    simulates a decoder function writing plaintext, passing it to an API, and
    returning a pointer in a register.

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
        """
        Purpose:
        Initialise a fake runtime decoder engine with plaintext not yet mapped.

        How it works:
        Stores decoded outputs as pending values, leaves virtual memory empty,
        and prepares hook/register bookkeeping that run_module() will populate.

        Parameters:
        - memory_output: Plaintext bytes written during simulated execution.
        - api_output: Plaintext API argument written during simulated execution.
        - register_output: Plaintext bytes pointed to during simulated execution.
        - bad_pointers: Optional unreadable addresses used to prove safe skips.

        Returns:
        void
        """
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

    def has_mapped_runtime_plaintext(self) -> bool:
        """
        Purpose:
        Report whether the fake decoder has mapped any plaintext bytes yet.

        How it works:
        Checks the virtual memory map that run_module() populates during the
        simulated self-decode path.

        Parameters:
        None.

        Returns:
        True when any runtime plaintext bytes are mapped, otherwise False.
        """
        return bool(self._memory)

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
        maps another decoded output before pointing eax at it, fires code hooks
        for register capture, then maps and passes a decoded API argument plus
        one bad pointer to prove bad pointers do not crash extraction.

        Parameters:
        - module: Loaded module object passed by MalwareEmulator.run().

        Returns:
        void
        """
        self.run_calls.append(module)
        split_at = max(1, len(self.memory_output) // 2)
        self.mem_write(self.MEMORY_ADDRESS, self.memory_output[:split_at])
        self.mem_write(self.MEMORY_ADDRESS + split_at, self.memory_output[split_at:])

        self._write_bytes(self.REGISTER_ADDRESS, self.register_output)
        self._registers["eax"] = self.REGISTER_ADDRESS
        for callback in self.code_hooks:
            callback(self, 0x401000, 5)

        self._write_bytes(self.API_ADDRESS, self.api_output.encode("ascii") + b"\x00")
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


class ExecuteAfterWriteEngine(FunctionDecodedEngine):
    """
    Purpose:
    Simulate a self-decode window where plaintext exists only before overwrite.

    How it works:
    Reuses the fake decoded-output engine hook surface, but run_module() writes
    plaintext into an executable buffer, fires code hooks inside that buffer,
    then overwrites the buffer so final memory no longer contains plaintext.

    Parameters:
    - plaintext: Short plaintext bytes exposed only during execute-after-write.
    - overwritten: Replacement bytes left in memory after the transient window.

    Returns:
    A fake engine instance for execute-after-write integration tests.
    """

    EXECUTE_ADDRESS: ClassVar[int] = 0x7000

    def __init__(self, plaintext: bytes, overwritten: bytes) -> None:
        """
        Purpose:
        Initialise transient plaintext and final overwrite bytes.

        How it works:
        Passes inert values to the base fake engine and stores the plaintext and
        overwrite payloads used by run_module().

        Parameters:
        - plaintext: Bytes written before simulated execution.
        - overwritten: Bytes written after simulated execution.

        Returns:
        void
        """
        super().__init__(memory_output=b"", api_output="", register_output=b"")
        self.plaintext: bytes = plaintext
        self.overwritten: bytes = overwritten

    def run_module(self, module: object) -> None:
        """
        Purpose:
        Simulate decode -> execute written region -> overwrite behavior.

        How it works:
        Records the module, writes plaintext into the execute buffer, invokes
        registered code hooks with an address inside that buffer, then overwrites
        the same bytes with non-plaintext data.

        Parameters:
        - module: Loaded module object passed by MalwareEmulator.run().

        Returns:
        void
        """
        self.run_calls.append(module)
        self.mem_write(self.EXECUTE_ADDRESS, self.plaintext)
        for callback in self.code_hooks:
            callback(self, self.EXECUTE_ADDRESS + 2, 5)
        self.mem_write(self.EXECUTE_ADDRESS, self.overwritten)

    def final_memory_contains(self, needle: bytes) -> bool:
        """
        Purpose:
        Report whether final fake memory still contains a byte sequence.

        How it works:
        Reads the final buffer range from the fake memory map and checks for the
        requested bytes after run_module() has completed.

        Parameters:
        - needle: Byte sequence to search for in final memory.

        Returns:
        True when the final buffer contains needle, otherwise False.
        """
        data = bytes(
            self._memory.get(self.EXECUTE_ADDRESS + offset, 0)
            for offset in range(max(len(self.plaintext), len(self.overwritten)))
        )
        return needle in data


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
    setattr(emulator, "se", engine)
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

    plaintext_outputs = {
        "memory-decoded.example/path",
        "api-decoded.example",
        "register-decoded.example",
    }

    assert not engine.has_mapped_runtime_plaintext()
    emulator.register_hooks()
    assert plaintext_outputs.isdisjoint(_results_by_content(emulator))
    emulator.run()

    results = _results_by_content(emulator)
    module = cast(object, emulator.module)
    assert engine.run_calls == [module]
    assert plaintext_outputs.issubset(results)
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


@pytest.mark.integration
def test_dotnet_replace_remove_style_plaintext_is_runtime_boundary_only() -> None:
    """
    Purpose:
    Verify article-style .NET Replace/Remove obfuscation is covered as runtime output only.

    How it works:
    Builds a source-like string with inserted method-name junk plus homoglyph/special
    characters, simulates runtime Remove/Replace producing plaintext, and exposes only
    that plaintext through the fake lstrcpyA API boundary.

    Parameters:
    None.

    Returns:
    void
    """
    remove_junk = "String.Remove(3, 17)"
    source_like = f"pay{remove_junk}l\u043eoad.ex\u00a7ample/path"
    after_remove = source_like[:3] + source_like[3 + len(remove_junk) :]
    runtime_plaintext = after_remove.replace("\u043e", "").replace("\u00a7", "")
    assert runtime_plaintext == "payload.example/path"

    engine = FunctionDecodedEngine(
        memory_output=b"",
        api_output=runtime_plaintext,
        register_output=b"",
    )
    emulator = _build_emulator(engine)

    emulator.register_hooks()
    pre_run_results = _results_by_content(emulator)
    assert source_like not in pre_run_results
    assert after_remove not in pre_run_results
    assert runtime_plaintext not in pre_run_results

    emulator.run()

    results = _results_by_content(emulator)
    assert source_like not in results
    assert after_remove not in results
    assert runtime_plaintext in results
    assert results[runtime_plaintext]["source"] == "api_hook"
    assert results[runtime_plaintext]["source_detail"] == "lstrcpyA"


@pytest.mark.integration
def test_execute_after_write_capture_survives_plaintext_overwrite() -> None:
    """
    Purpose:
    Verify plaintext is captured when execution enters a written buffer.

    How it works:
    Runs a fake engine that writes plaintext, fires code hooks inside that
    region, overwrites the buffer, and asserts the final memory no longer holds
    plaintext while extraction still reports execute_after_write provenance.

    Parameters:
    None.

    Returns:
    void
    """
    plaintext = b"execute-window.example/path\x00"
    engine = ExecuteAfterWriteEngine(
        plaintext=plaintext,
        overwritten=b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxx\x00",
    )
    emulator = _build_emulator(engine)

    emulator.register_hooks()
    emulator.run()

    results = _results_by_content(emulator)
    assert not engine.final_memory_contains(b"execute-window.example/path")
    assert "execute-window.example/path" in results
    assert results["execute-window.example/path"]["source"] == "execute_after_write"


@pytest.mark.integration
def test_execute_after_write_capture_is_bounded() -> None:
    """
    Purpose:
    Verify execute-after-write snapshots do not grow with unbounded regions.

    How it works:
    Creates more transient execute buffers than the snapshot cap, runs the same
    bounded code-hook path, and asserts retained snapshots and code-hook register
    scan work stay capped.

    Parameters:
    None.

    Returns:
    void
    """
    engine = ExecuteAfterWriteEngine(
        plaintext=b"execute-bounds.example\x00",
        overwritten=b"yyyyyyyyyyyyyyyyyyyyyy\x00",
    )

    def run_many_regions(module: object) -> None:
        """
        Purpose:
        Simulate many execute-after-write regions beyond the snapshot cap.

        How it works:
        Writes unique plaintext into disconnected buffers, fires code hooks in
        each buffer, then overwrites the buffer so final memory cannot recover it.

        Parameters:
        - module: Loaded module object passed by MalwareEmulator.run().

        Returns:
        void
        """
        engine.run_calls.append(module)
        for index in range(DEFAULT_MAX_CODE_HOOK_SCANS + 20):
            address = engine.EXECUTE_ADDRESS + index * 0x100
            payload = f"execute-bound-{index:02d}.example\x00".encode("ascii")
            engine.mem_write(address, payload)
            for callback in engine.code_hooks:
                callback(engine, address, 5)
            engine.mem_write(address, b"z" * len(payload))

    engine.run_module = run_many_regions
    emulator = _build_emulator(engine)

    emulator.register_hooks()
    emulator.run()

    execute_snapshots = emulator.tracker.get_execute_after_write_candidates()
    bad_pointer_reads = [
        call for call in engine.mem_read_calls if call[0] == FunctionDecodedEngine.BAD_POINTER
    ]
    assert len(execute_snapshots) == MAX_EXECUTE_AFTER_WRITE_SNAPSHOTS
    assert len(bad_pointer_reads) == DEFAULT_MAX_CODE_HOOK_SCANS + 1
