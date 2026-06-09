# -*- coding: utf-8 -*-
import logging

from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeAlias, cast

logger = logging.getLogger(__name__)


class _StringReader(Protocol):
    def read_mem_string(self, ptr: int, width: int = 1) -> str: ...


ArgSpec: TypeAlias = tuple[int, int]
ApiHookSpec: TypeAlias = tuple[str, str, list[ArgSpec]]
ApiCallback: TypeAlias = Callable[[_StringReader, str, object, Sequence[object]], object]


class _HookRegistrar(Protocol):
    def add_api_hook(self, callback: ApiCallback, module: str, api_name: str) -> object: ...


class _StringExtractorLike(Protocol):
    def process_api_string(
        self,
        api_name: str,
        str_val: str,
        source_detail: str | None = None,
    ) -> None: ...


class _BehaviorTracerLike(Protocol):
    def record_api_call(
        self,
        api_name: str,
        args: Sequence[Any] | None = None,
        *,
        source: str = "api_hook",
        time: float | None = None,
    ) -> None: ...


def _safe_read_ansi(emu: _StringReader, ptr: object) -> str | None:
    """
    Purpose:
    Safely read a null-terminated ANSI (width=1) string from emulated memory.

    How it works:
    Validates the pointer is a positive integer, then delegates to
    emu.read_mem_string. Returns None on any failure so that callers
    never crash the emulator.

    Parameters:
    - emu: Speakeasy emulator instance with read_mem_string().
    - ptr: Integer memory address to read from.

    Returns:
    The decoded string, or None if the pointer is invalid or unreadable.
    """
    if not isinstance(ptr, int) or ptr <= 0:
        return None
    try:
        return emu.read_mem_string(ptr, width=1)
    except Exception:
        return None


def _safe_read_wide(emu: _StringReader, ptr: object) -> str | None:
    """
    Purpose:
    Safely read a null-terminated wide (UTF-16LE, width=2) string from
    emulated memory.

    How it works:
    Same guard-then-read strategy as _safe_read_ansi but with width=2.

    Parameters:
    - emu: Speakeasy emulator instance with read_mem_string().
    - ptr: Integer memory address to read from.

    Returns:
    The decoded string, or None if the pointer is invalid or unreadable.
    """
    if not isinstance(ptr, int) or ptr <= 0:
        return None
    try:
        return emu.read_mem_string(ptr, width=2)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Allowlist of string-bearing Windows APIs to hook.
#
# Each entry: (module, api_name, argument_specs)
# argument_specs is a list of (arg_index, width) pairs where width is
# 1 for ANSI, 2 for Wide.  Only these argument slots are read.
# ---------------------------------------------------------------------------
_STRING_API_HOOKS: list[ApiHookSpec] = [
    # WinINet — network APIs that receive decrypted C2 domains / URLs
    ("wininet", "InternetConnectA",  [(1, 1)]),   # lpszServerName
    ("wininet", "InternetConnectW",  [(1, 2)]),
    ("wininet", "InternetOpenA",     [(0, 1)]),   # lpszAgent (user-agent)
    ("wininet", "InternetOpenW",     [(0, 2)]),
    ("wininet", "HttpOpenRequestA",  [(1, 1), (2, 1)]),  # lpszVerb, lpszObjectName
    ("wininet", "HttpOpenRequestW",  [(1, 2), (2, 2)]),
    # URLMon — single-call download helper
    ("urlmon",  "URLDownloadToFileA", [(1, 1), (2, 1)]),  # szURL, szFileName
    ("urlmon",  "URLDownloadToFileW", [(1, 2), (2, 2)]),
    # WinHTTP — URL/session APIs expose direct string pointers. Speakeasy
    # models WinHTTP as wide-only names, but A/W aliases keep import hooks
    # symmetric with the rest of the analyst string surface.
    ("winhttp", "WinHttpOpen",          [(0, 2), (2, 2), (3, 2)]),  # user-agent, proxy, bypass
    ("winhttp", "WinHttpOpenA",         [(0, 1), (2, 1), (3, 1)]),
    ("winhttp", "WinHttpOpenW",         [(0, 2), (2, 2), (3, 2)]),
    ("winhttp", "WinHttpConnect",       [(1, 2)]),                  # server name
    ("winhttp", "WinHttpConnectA",      [(1, 1)]),
    ("winhttp", "WinHttpConnectW",      [(1, 2)]),
    ("winhttp", "WinHttpOpenRequest",   [(1, 2), (2, 2), (3, 2), (4, 2)]),  # verb, path, version, referrer
    ("winhttp", "WinHttpOpenRequestA",  [(1, 1), (2, 1), (3, 1), (4, 1)]),
    ("winhttp", "WinHttpOpenRequestW",  [(1, 2), (2, 2), (3, 2), (4, 2)]),
    ("winhttp", "WinHttpGetProxyForUrl", [(1, 2)]),                 # URL
    ("winhttp", "WinHttpGetProxyForUrlA", [(1, 1)]),
    ("winhttp", "WinHttpGetProxyForUrlW", [(1, 2)]),

    # kernel32 — process creation
    ("kernel32", "CreateProcessA",   [(0, 1), (1, 1)]),   # lpApplicationName, lpCommandLine
    ("kernel32", "CreateProcessW",   [(0, 2), (1, 2)]),
    # shell32 — command / process execution
    ("shell32", "ShellExecuteA",     [(2, 1)]),           # lpFile
    ("shell32", "ShellExecuteW",     [(2, 2)]),
    # advapi32 — registry access
    ("advapi32", "RegOpenKeyExA",    [(1, 1)]),           # lpSubKey
    ("advapi32", "RegOpenKeyExW",    [(1, 2)]),
    ("advapi32", "RegCreateKeyExA",  [(1, 1)]),
    ("advapi32", "RegCreateKeyExW",  [(1, 2)]),
    ("advapi32", "RegSetValueExA",   [(1, 1), (4, 1)]),   # value name, data best-effort
    ("advapi32", "RegSetValueExW",   [(1, 2), (4, 2)]),
    # kernel32 — filesystem access
    ("kernel32", "CreateFileA",      [(0, 1)]),           # lpFileName
    ("kernel32", "CreateFileW",      [(0, 2)]),
    ("kernel32", "DeleteFileA",      [(0, 1)]),
    ("kernel32", "DeleteFileW",      [(0, 2)]),
    ("kernel32", "MoveFileA",        [(0, 1), (1, 1)]),
    ("kernel32", "MoveFileW",        [(0, 2), (1, 2)]),
    ("kernel32", "CopyFileA",        [(0, 1), (1, 1)]),
    ("kernel32", "CopyFileW",        [(0, 2), (1, 2)]),
]


def _get_or_create_iob_table(emu) -> int:
    """
    Purpose: 
    Provides a stable pointer to an emulated _iob chunk for msvcrt standard streams.

    How it works:
    Checks if `emu._iob_table_addr` is set. If not, queries emulator for pointer size,
    allocates exactly `3 * 0x100` bytes (covering stdin/stdout/stderr), fills with
    zeroes, caches the pointer on the emulator object, and returns it.
    If `mem_alloc` or `get_ptr_size` are unavailable, supplies fallback defaults and fixed address zero-fill.

    Parameters:
    - emu: The Speakeasy emulator instance or FakeEmu test mock.

    Returns:
    The integer base address for the allocated C-runtime table.
    """
    if hasattr(emu, '_iob_table_addr'):
        return emu._iob_table_addr

    size = 3 * 0x100
    try:
        addr = emu.mem_alloc(size, base=None)
    except Exception:
        addr = 0x69000000

    try:
        emu.mem_write(addr, b'\x00' * size)
    except Exception:
        pass

    emu._iob_table_addr = addr
    return addr


def setup_api_hooks(
    se: _HookRegistrar,
    extractor: _StringExtractorLike,
    behavior_tracer: _BehaviorTracerLike | None = None,
) -> None:
    """
    Purpose:
    Install API hooks that capture string arguments passed to common
    Windows APIs used by malware for string copy, memory allocation,
    network communication, process execution, registry access, and filesystem use.

    How it works:
    1. Registers existing lstrcpyA/W and VirtualAlloc hooks.
    2. Iterates the _STRING_API_HOOKS allowlist and installs a generic
       callback for each entry that reads the specified argument slots
       via _safe_read_ansi / _safe_read_wide.
    3. Every hook failure is logged as a non-fatal warning — the emulator
       continues running regardless.

    Parameters:
    - se:        Speakeasy emulator object exposing add_api_hook().
    - extractor: StringExtractor instance — captured strings are forwarded
                 to extractor.process_api_string().

    Returns:
    None.
    """

    def _record_behavior(api_name: str, argv: Sequence[object], extra_args: Sequence[object] | None = None) -> None:
        if behavior_tracer is None:
            return
        args = list(argv)
        if extra_args:
            args.extend(extra_args)
        try:
            behavior_tracer.record_api_call(api_name, args, source="api_hook")
        except Exception:
            logger.debug(f"[Hook] Behavior trace skipped for {api_name}")

    def _capture_string_arg(
        emu: _StringReader,
        api_name: str,
        argv: Sequence[object],
        arg_index: int,
        reader: Callable[[_StringReader, object], str | None],
        *,
        source_detail: str | None = None,
    ) -> str | None:
        if arg_index >= len(argv):
            return None
        val = reader(emu, argv[arg_index])
        if val is not None:
            extractor.process_api_string(api_name, val, source_detail=source_detail or api_name)
        return val

    def my_lstrcpyA(emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> None:
        _capture_string_arg(emu, 'lstrcpyA', argv, 1, _safe_read_ansi)

    def my_lstrcpyW(emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> None:
        _capture_string_arg(emu, 'lstrcpyW', argv, 1, _safe_read_wide)

    def my_VirtualAlloc(_emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> None:
        _record_behavior('VirtualAlloc', argv)
        if len(argv) >= 4:
            dwSize = cast(int, argv[1])
            flProtect = cast(int, argv[3])
            logger.debug(f"[Hook] VirtualAlloc(Size={hex(dwSize)}, Protect={hex(flProtect)})")

    def my___iob_func(emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> int:
        return _get_or_create_iob_table(emu)

    def _safe_mem_write(ptr: object, data: bytes) -> None:
        if isinstance(ptr, int) and ptr > 0 and hasattr(se, 'mem_write'):
            try:
                se.mem_write(ptr, data)
            except Exception:
                pass

    def _write_int(ptr: object, value: int, size: int = 4) -> None:
        _safe_mem_write(ptr, int(value).to_bytes(size, 'little', signed=False))

    def my_getenv(emu, api_name, func, argv):
        """Satisfy only the lab-gate environment variable; delegate others."""
        val = _safe_read_ansi(emu, argv[0]) if len(argv) >= 1 else None
        if val and val != 'LAB_MALWARE_ALLOWED':
            extractor.process_api_string(api_name, val, source_detail=api_name)
        if val is not None and val != 'LAB_MALWARE_ALLOWED':
            return func(argv) if callable(func) else 0
        # If Speakeasy cannot decode getenv's argument (common with some CRT
        # thunks), prefer exploration and satisfy the gate.
        addr = emu.mem_alloc(2, base=None) if hasattr(emu, 'mem_alloc') else 0x69000100
        if hasattr(emu, 'mem_write'):
            emu.mem_write(addr, b'1\x00')
        return addr

    def my_WinHttpSendRequest(emu: _StringReader, api_name: str, func: object, argv: Sequence[object]) -> int:
        behavior_args = []
        if len(argv) >= 5:
            is_wide = api_name.endswith('W') or api_name == 'WinHttpSendRequest'
            reader = _safe_read_wide if is_wide else _safe_read_ansi
            headers = _capture_string_arg(emu, api_name, argv, 1, reader)
            if headers is not None:
                behavior_args.append(headers)

            # Capture optional body
            body_ptr = argv[3]
            body_len = argv[4]
            if isinstance(body_ptr, int) and body_ptr > 0 and isinstance(body_len, int) and body_len > 0:
                try:
                    raw_body = emu.read_mem_string(body_ptr, width=1) # best effort ansi representation
                    if raw_body:
                        # limit to specified length
                        body_val = raw_body[:body_len] if len(raw_body) > body_len else raw_body
                        extractor.process_api_string(api_name, body_val, source_detail=f"{api_name}_body")
                        behavior_args.append(body_val)
                except Exception:
                    pass
        _record_behavior(api_name, argv, behavior_args)
        return func(argv) if callable(func) else 1

    def my___acrt_iob_func(emu, api_name, func, argv):
        base = _get_or_create_iob_table(emu)
        if len(argv) >= 1 and isinstance(argv[0], int) and argv[0] in (0, 1, 2):
            return base + (argv[0] * 0x100)
        return base

    def my_fflush(emu, api_name, func, argv):
        return 0

    def my_fclose(emu, api_name, func, argv):
        return 0

    def my_puts(emu, api_name, func, argv):
        _capture_string_arg(emu, api_name, argv, 0, _safe_read_ansi)
        return 1

    def my_putchar(emu, api_name, func, argv):
        return int(argv[0]) & 0xFF if len(argv) >= 1 and isinstance(argv[0], int) else 0

    def my_printf(emu, api_name, func, argv):
        _capture_string_arg(emu, api_name, argv, 0, _safe_read_ansi)
        return 1

    def my_fprintf(emu, api_name, func, argv):
        _capture_string_arg(emu, api_name, argv, 1, _safe_read_ansi)
        return 1

    def my_fwrite(emu, api_name, func, argv):
        if len(argv) >= 4:
            ptr, size, count = argv[:3]
            if isinstance(ptr, int) and ptr > 0 and isinstance(size, int) and size > 0 and isinstance(count, int) and count > 0:
                read_len = min(size * count, 4096)
                try:
                    raw = emu.read_mem_string(ptr, width=1)
                    val = raw[:read_len] if len(raw) > read_len else raw
                    if val:
                        extractor.process_api_string(api_name, val, source_detail=api_name)
                except Exception:
                    pass
            return int(argv[2]) if isinstance(argv[2], int) else 0
        return 0
        
    def my_setvbuf(emu, api_name, func, argv):
        return 0


    def my_atexit(emu, api_name, func, argv):
        return 0


    def my_time64(emu, api_name, func, argv):
        return 0



    def my_IsDebuggerPresent(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        return 0


    def my_CheckRemoteDebuggerPresent(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        if len(argv) >= 2:
            _write_int(argv[1], 0)
        return 1

    def my_Sleep(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        return None

    def my_GetTickCount(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        tick = getattr(emu, '_analysis_tick', 100000)
        tick += 100
        setattr(emu, '_analysis_tick', tick)
        return tick & 0xffffffff

    def my_QueryPerformanceCounter(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        counter = getattr(emu, '_analysis_qpc', 1000000)
        counter += 1000
        setattr(emu, '_analysis_qpc', counter)
        if len(argv) >= 1:
            _write_int(argv[0], counter, size=8)
        return 1

    def my_NtQueryInformationProcess(emu, api_name, func, argv):
        # Common anti-debug classes:
        #   7  ProcessDebugPort          -> 0 / no debug port
        #   0x1e ProcessDebugObjectHandle -> 0 / no object
        #   0x1f ProcessDebugFlags       -> 1 / not debugged
        _record_behavior(api_name, argv)
        if len(argv) >= 3:
            info_class = argv[1]
            out_ptr = argv[2]
            if isinstance(info_class, int):
                val = 1 if info_class == 0x1f else 0
                size = 8 if info_class in (7, 0x1e) else 4
                _write_int(out_ptr, val, size=size)
        if len(argv) >= 5:
            _write_int(argv[4], 0)
        return 0

    def my_FindWindow(emu, api_name, func, argv):
        # Hide debugger/sandbox tool windows by returning NULL.
        _record_behavior(api_name, argv)
        return 0

    def my_OutputDebugStringA(emu, api_name, func, argv):
        _capture_string_arg(emu, api_name, argv, 0, _safe_read_ansi)
        return None

    def my_OutputDebugStringW(emu, api_name, func, argv):
        _capture_string_arg(emu, api_name, argv, 0, _safe_read_wide)
        return None

    def my_ExitProcess(emu, api_name, func, argv):
        # Non-fatal under emulation so final extractors can still drain state.
        return None

    def my_FindNextFile(emu, api_name, func, argv):
        # Speakeasy may model failed BOOL APIs as 0xffffffff for some paths,
        # which can accidentally keep file-enumeration loops alive. Return the
        # Win32 BOOL failure value (0) so ransomware directory walks terminate
        # and later payload stages become observable.
        _record_behavior(api_name, argv)
        return 0

    def my_strtol(emu, api_name, func, argv):
        # msvcrt.strtol(nptr, endptr, base) is used by std::stoi in MinGW.
        # Speakeasy may not implement it; a small hook lets execution continue
        # into payload threads.
        text = _safe_read_ansi(emu, argv[0]) if len(argv) >= 1 else None
        if text:
            extractor.process_api_string(api_name, text, source_detail=api_name)
        base = argv[2] if len(argv) >= 3 and isinstance(argv[2], int) else 10
        try:
            value = int((text or "0").strip().split("\x00", 1)[0], base or 10)
        except Exception:
            value = 0
        if len(argv) >= 2:
            # Best-effort endptr = nptr + len(parsed text).
            nptr = argv[0]
            endptr = argv[1]
            if isinstance(nptr, int) and isinstance(endptr, int) and endptr > 0:
                _write_int(endptr, nptr + len(text or ""), size=8)
        return value

    def my_memchr(emu, api_name, func, argv):
        # MinGW/C++ runtime uses memchr while normalizing module paths before
        # user payload code runs. Speakeasy may not implement it; emulate the
        # small C-library behavior so analysis can continue past CRT startup.
        if len(argv) < 3:
            return 0
        buf, ch, count = argv[:3]
        if not (isinstance(buf, int) and buf > 0 and isinstance(ch, int) and isinstance(count, int) and count > 0):
            return 0
        try:
            data = emu.mem_read(buf, min(count, 0x10000))
        except Exception:
            return 0
        needle = ch & 0xFF
        idx = data.find(bytes([needle]))
        return buf + idx if idx >= 0 else 0

    def my_socket_behavior(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        return func(argv) if callable(func) else 1

    def my_inet_pton(emu, api_name, func, argv):
        ip = _safe_read_ansi(emu, argv[1]) if len(argv) >= 2 else None
        if ip:
            extractor.process_api_string(api_name, ip, source_detail=api_name)
        _record_behavior(api_name, argv, [ip] if ip else None)
        return func(argv) if callable(func) else 1

    def _make_hook(hook_api_name: str, arg_specs: Sequence[ArgSpec]) -> ApiCallback:
        """
        Purpose:
        Factory that returns a Speakeasy-compatible callback for a given
        API and its string-argument specification.

        How it works:
        The returned closure iterates arg_specs, reads the pointer at each
        argument index with the appropriate width helper, and forwards
        non-None results to extractor.process_api_string().

        Parameters:
        - hook_api_name: Name of the Windows API (used as location label).
        - arg_specs:     List of (arg_index, width) tuples.

        Returns:
        A callback function matching the Speakeasy hook signature
        (emu, api_name, func, argv).
        """
        def _hook(emu: _StringReader, _api_name: str, func: object, argv: Sequence[object]) -> object:
            behavior_args = []
            for arg_idx, width in arg_specs:
                if arg_idx >= len(argv):
                    continue
                reader: Callable[[_StringReader, object], str | None] = _safe_read_ansi if width == 1 else _safe_read_wide
                val = reader(emu, argv[arg_idx])
                if val is not None:
                    extractor.process_api_string(hook_api_name, val,
                                                 source_detail=hook_api_name)
                    behavior_args.append(val)
            _record_behavior(hook_api_name, argv, behavior_args)
            if hook_api_name in ("RegOpenKeyExA", "RegOpenKeyExW"):
                joined = " ".join(behavior_args).lower()
                if "vmware" in joined or "virtualbox" in joined or "vbox" in joined:
                    # ERROR_FILE_NOT_FOUND. Hide common VM artifacts so samples
                    # do not terminate before analyst-observable payload paths.
                    return 2
                if "currentversion\\run" in joined:
                    if len(argv) >= 5:
                        _write_int(argv[4], 0x7000, size=8)
                    return 0
            return func(argv) if callable(func) else None
        return _hook

    # ------------------------------------------------------------------
    # Install all hooks — each wrapped in its own try/except
    # ------------------------------------------------------------------

    installed: list[str] = []

    # Legacy hooks
    legacy_hooks = [
        (my_lstrcpyA, 'kernel32', 'lstrcpyA', {}),
        (my_lstrcpyW, 'kernel32', 'lstrcpyW', {}),
        (my_VirtualAlloc, 'kernel32', 'VirtualAlloc', {}),
        (my___iob_func, 'msvcrt', '__iob_func', {}),
        (my___acrt_iob_func, 'msvcrt', '__acrt_iob_func', {}),
        (my_fflush, 'msvcrt', 'fflush', {}),
        (my_fclose, 'msvcrt', 'fclose', {}),
        (my_puts, 'msvcrt', 'puts', {}),
        (my_putchar, 'msvcrt', 'putchar', {}),
        (my_printf, 'msvcrt', 'printf', {}),
        (my_fprintf, 'msvcrt', 'fprintf', {}),
        (my_fwrite, 'msvcrt', 'fwrite', {}),
        (my_setvbuf, 'msvcrt', 'setvbuf', {}),
        (my_atexit, 'msvcrt', 'atexit', {}),
        (my_time64, 'msvcrt', '_time64', {}),
        (my_IsDebuggerPresent, 'kernel32', 'IsDebuggerPresent', {}),
        (my_CheckRemoteDebuggerPresent, 'kernel32', 'CheckRemoteDebuggerPresent', {}),
        (my_Sleep, 'kernel32', 'Sleep', {}),
        (my_OutputDebugStringA, 'kernel32', 'OutputDebugStringA', {}),
        (my_OutputDebugStringW, 'kernel32', 'OutputDebugStringW', {}),
        (my_ExitProcess, 'kernel32', 'ExitProcess', {}),
        (my_getenv, 'msvcrt', 'getenv', {}),
        (my_WinHttpSendRequest, 'winhttp', 'WinHttpSendRequest', {}),
        (my_WinHttpSendRequest, 'winhttp', 'WinHttpSendRequestA', {}),
        (my_WinHttpSendRequest, 'winhttp', 'WinHttpSendRequestW', {}),
    ]

    def _simple_behavior_hook(api_name_for_trace: str):
        def _hook(_emu, api_name, func, argv):
            _record_behavior(api_name_for_trace or api_name, argv)
            return func(argv) if callable(func) else None
        return _hook

    if behavior_tracer is not None:
        legacy_hooks.extend([
            (my_GetTickCount, 'kernel32', 'GetTickCount', {}),
            (my_QueryPerformanceCounter, 'kernel32', 'QueryPerformanceCounter', {}),
            (my_NtQueryInformationProcess, 'ntdll', 'NtQueryInformationProcess', {}),
            (my_FindWindow, 'user32', 'FindWindowA', {}),
            (my_FindWindow, 'user32', 'FindWindowW', {}),
            (my_FindWindow, 'user32', 'FindWindowExA', {}),
            (my_FindWindow, 'user32', 'FindWindowExW', {}),
            (my_FindNextFile, 'kernel32', 'FindNextFileA', {}),
            (my_FindNextFile, 'kernel32', 'FindNextFileW', {}),
            (my_strtol, 'msvcrt', 'strtol', {}),
            (my_memchr, 'msvcrt', 'memchr', {}),
            (my_socket_behavior, 'ws2_32', 'WSAStartup', {}),
            (my_socket_behavior, 'ws2_32', 'socket', {}),
            (my_socket_behavior, 'ws2_32', 'connect', {}),
            (my_socket_behavior, 'ws2_32', 'closesocket', {}),
            (my_socket_behavior, 'ws2_32', 'WSACleanup', {}),
            (my_inet_pton, 'ws2_32', 'inet_pton', {}),
        ])

    behavior_only_hooks = [
        ('kernel32', 'WriteFile'),
        ('kernel32', 'OpenProcess'),
        ('kernel32', 'TerminateProcess'),
        ('kernel32', 'VirtualAllocEx'),
        ('kernel32', 'WriteProcessMemory'),
        ('kernel32', 'CreateRemoteThread'),
        ('kernel32', 'QueueUserAPC'),
        ('kernel32', 'SetThreadContext'),
        ('kernel32', 'ResumeThread'),
        ('kernel32', 'CreateToolhelp32Snapshot'),
        ('kernel32', 'Process32First'),
        ('kernel32', 'Process32Next'),
        ('ntdll', 'NtCreateThreadEx'),
    ]
    if behavior_tracer is not None:
        for mod, name in behavior_only_hooks:
            legacy_hooks.append((_simple_behavior_hook(name), mod, name, {}))
    for cb, mod, name, kwargs in legacy_hooks:
        try:
            _ = se.add_api_hook(cb, mod, name, **kwargs)
            installed.append(name)
        except Exception as exc:
            logger.warning(f"[Hook] Không thể cài đặt hook {name}: {exc}")


    # Allowlist hooks
    for mod, api_name, arg_specs in _STRING_API_HOOKS:
        try:
            _ = se.add_api_hook(_make_hook(api_name, arg_specs), mod, api_name)
            installed.append(api_name)
        except Exception as exc:
            logger.warning(f"[Hook] Không thể cài đặt hook {api_name}: {exc}")

    if installed:
        logger.info(f"[Hook] Đã cài đặt {len(installed)} API hooks: {', '.join(installed)}.")
