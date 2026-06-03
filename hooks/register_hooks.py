# -*- coding: utf-8 -*-
import logging
import string
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, TypeAlias, cast

logger = logging.getLogger(__name__)

DEFAULT_REGISTER_READ_SIZE = 256
DEFAULT_MAX_REGISTER_READS = 8
DEFAULT_MAX_CODE_HOOK_SCANS = 64

RegisterValue: TypeAlias = tuple[str, object]


class _MemoryReader(Protocol):
    def mem_read(self, address: int, size: int) -> bytes: ...


class _CodeHookRegistrar(Protocol):
    def add_code_hook(self, callback: Callable[[object, int, int], None]) -> object: ...


class _ExecuteAfterWriteTracker(Protocol):
    def capture_execute_after_write(
        self,
        reader: _MemoryReader,
        instruction_address: int,
    ) -> tuple[int, bytes] | None: ...


class _CandidateIngestor(Protocol):
    min_length: int

    def ingest_candidate(
        self,
        content: str,
        source: str,
        location: str | None = None,
        source_detail: str | None = None,
    ) -> None: ...


RegisterValuesInput: TypeAlias = Mapping[object, object] | Sequence[tuple[object, object]] | None


def _iter_register_values(
    emu: object,
    register_values: RegisterValuesInput = None,
) -> list[RegisterValue]:
    """
    Purpose:
    Normalize register candidates into an architecture-neutral list.

    How it works:
    Prefers explicit caller-provided register_values. Otherwise it asks the
    emulator for get_registers() or Speakeasy get_all_registers() and normalizes
    mappings or iterable (name, value) pairs without CPU register-name coupling.

    Parameters:
    - emu: emulator-like object that may expose a register snapshot accessor.
    - register_values: optional mapping or iterable of (name, value) pairs.

    Returns:
    A list of (register_name, value) tuples.
    """
    values: object = register_values
    if values is None:
        for accessor_name in ("get_registers", "get_all_registers"):
            accessor = getattr(emu, accessor_name, None)
            if not callable(accessor):
                continue
            try:
                get_values = cast(Callable[[], object], accessor)
                values = get_values()
                break
            except Exception as err:
                logger.debug(
                    "[RegisterScan] Không đọc được snapshot qua %s: %s",
                    accessor_name,
                    err,
                )
                continue
    if values is None:
        return []
    if isinstance(values, Mapping):
        register_mapping = cast(Mapping[object, object], values)
        return [(str(name), value) for name, value in register_mapping.items()]
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return []

    normalized: list[RegisterValue] = []
    register_sequence = cast(Sequence[object], values)
    for item in register_sequence:
        if not isinstance(item, tuple):
            return []
        try:
            name, value = cast(tuple[object, object], item)
        except ValueError:
            return []
        normalized.append((str(name), value))
    return normalized


def _coerce_pointer_value(value: object) -> int | None:
    """
    Purpose:
    Convert register values into integer pointer candidates.

    How it works:
    Accepts integer values directly and parses hexadecimal strings returned by
    Speakeasy's get_all_registers() report-style API. Invalid or non-positive
    values are rejected before any memory read is attempted.

    Parameters:
    - value: raw register value from an emulator register snapshot.

    Returns:
    A positive integer pointer candidate, or None when the value is unusable.
    """
    pointer: int
    if isinstance(value, int):
        pointer = value
    elif isinstance(value, str):
        try:
            pointer = int(value, 0)
        except ValueError:
            return None
    else:
        return None

    if pointer <= 0:
        return None
    return pointer


def _decode_ascii_c_string(data: bytes, min_length: int) -> str | None:
    """
    Purpose:
    Extract one printable ASCII C-string from a bounded register-pointer read.

    How it works:
    Walks bytes from the start of the read until a null terminator. It rejects
    non-printable bytes and returns only strings that meet the extractor's
    minimum length.

    Parameters:
    - data: bounded bytes returned from mem_read().
    - min_length: minimum decoded string length to accept.

    Returns:
    The decoded ASCII string, or None if the bytes are not a valid candidate.
    """
    if not data:
        return None

    valid_chars = set(string.printable.encode("ascii"))
    ascii_bytes = bytearray()
    for byte in data:
        if byte == 0:
            break
        if byte not in valid_chars:
            return None
        ascii_bytes.append(byte)

    if len(ascii_bytes) < min_length:
        return None
    return ascii_bytes.decode("ascii")


def _safe_read_candidate(emu: _MemoryReader, address: object, read_size: int) -> bytes | None:
    """
    Purpose:
    Safely dereference one register value as a possible string pointer.

    How it works:
    Accepts only positive integer addresses and wraps mem_read() so unmapped or
    otherwise invalid memory never crashes the caller.

    Parameters:
    - emu: emulator-like object exposing mem_read(address, size).
    - address: register value to treat as a candidate pointer.
    - read_size: maximum bytes to read from the candidate pointer.

    Returns:
    The bytes read from memory, or None when the value is not readable.
    """
    if not isinstance(address, int) or address <= 0:
        return None
    try:
        return emu.mem_read(address, read_size)
    except Exception as err:
        logger.debug(f"[RegisterScan] Bỏ qua register pointer {hex(address)}: {err}")
        return None


def scan_register_candidates(
    emu: _MemoryReader,
    extractor: _CandidateIngestor,
    register_values: RegisterValuesInput = None,
    max_reads: int = DEFAULT_MAX_REGISTER_READS,
    read_size: int = DEFAULT_REGISTER_READ_SIZE,
) -> list[str]:
    """
    Purpose:
    Scan register values as bounded candidate pointers to recovered strings.

    How it works:
    Normalizes explicit or emulator-provided register values, dereferences only
    positive integer candidates through mem_read(), caps total successful read
    attempts with max_reads, decodes printable ASCII C-strings, and appends each
    finding via extractor.ingest_candidate(source='register_scan').

    Parameters:
    - emu: emulator-like object exposing mem_read() and optional register snapshots.
    - extractor: StringExtractor-like object exposing ingest_candidate().
    - register_values: optional mapping or iterable of (register_name, value).
    - max_reads: maximum candidate pointer reads to attempt.
    - read_size: maximum bytes per candidate pointer read.

    Returns:
    A list of decoded strings found during the register scan.
    """
    if max_reads <= 0 or read_size <= 0:
        return []

    findings: list[str] = []
    reads_attempted = 0
    min_length = getattr(extractor, "min_length", 4)

    for register_name, value in _iter_register_values(emu, register_values):
        pointer = _coerce_pointer_value(value)
        if pointer is None:
            continue
        if reads_attempted >= max_reads:
            break

        reads_attempted += 1
        data = _safe_read_candidate(emu, pointer, read_size)
        candidate = _decode_ascii_c_string(data or b"", min_length)
        if candidate is None:
            continue

        extractor.ingest_candidate(
            candidate,
            source="register_scan",
            location=f"{register_name}:{hex(pointer)}",
            source_detail=register_name,
        )
        findings.append(candidate)

    return findings


def setup_register_hooks(
    se: object,
    extractor: _CandidateIngestor,
    max_hook_scans: int = DEFAULT_MAX_CODE_HOOK_SCANS,
    execute_after_write_tracker: _ExecuteAfterWriteTracker | None = None,
) -> None:
    """
    Purpose:
    Register bounded register-pointer scanning with Speakeasy when available.

    How it works:
    If the engine exposes add_code_hook(), installs a callback with a finite
    per-run scan budget. Each allowed callback first asks the optional dirty
    tracker to snapshot execute-after-write windows, then invokes
    scan_register_candidates() with the callback emulator object. Later hot-loop
    callbacks return immediately and post-run scanning remains available.

    Parameters:
    - se: Speakeasy-like engine that may expose add_code_hook().
    - extractor: StringExtractor-like object receiving register-scan findings.
    - max_hook_scans: maximum code-hook callbacks that may trigger register scans.
    - execute_after_write_tracker: optional dirty tracker for first-execute snapshots.

    Returns:
    void
    """
    add_code_hook = getattr(se, "add_code_hook", None)
    if not callable(add_code_hook):
        logger.info("[RegisterScan] Code hook API unavailable; using post-run scan only.")
        return

    hook_scans_remaining = max(0, max_hook_scans)

    def hook_code(emu: object, address: int, size: int) -> None:
        """
        Purpose:
        Capture register-held string pointers during emulation.

        How it works:
        Consumes one finite hook-scan budget slot, captures a bounded
        execute-after-write snapshot when the current instruction enters a dirty
        region, then runs the existing bounded register scanner against the
        callback emulator when provided, otherwise the registered engine.

        Parameters:
        - emu: callback emulator object supplied by Speakeasy.
        - address: current instruction address.
        - size: current instruction size, unused.

        Returns:
        void
        """
        nonlocal hook_scans_remaining
        _ = size
        if hook_scans_remaining <= 0:
            return
        hook_scans_remaining -= 1
        scan_engine = emu if emu is not None else se
        if execute_after_write_tracker is not None:
            _ = execute_after_write_tracker.capture_execute_after_write(
                cast(_MemoryReader, scan_engine),
                address,
            )
        _ = scan_register_candidates(cast(_MemoryReader, scan_engine), extractor)

    try:
        registrar = cast(_CodeHookRegistrar, se)
        _ = registrar.add_code_hook(hook_code)
        logger.info("[RegisterScan] Đã cắm register code hook có giới hạn.")
    except Exception as err:
        logger.warning(f"[RegisterScan] Không thể cài register code hook: {err}")
