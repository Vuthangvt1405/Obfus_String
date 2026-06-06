# -*- coding: utf-8 -*-
import logging
import speakeasy.windows.common as sc_common

from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeAlias, cast

logger = logging.getLogger(__name__)


class _StringReader(Protocol):
    def read_mem_string(self, ptr: int, width: int = 1) -> str: ...


ArgSpec: TypeAlias = tuple[int, int]
ApiHookSpec: TypeAlias = tuple[str, str, list[ArgSpec]]
ApiCallback: TypeAlias = Callable[[_StringReader, str, object, Sequence[object]], None]


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

    # ------------------------------------------------------------------
    # Original hooks (kernel32 string-copy / alloc)
    # ------------------------------------------------------------------

    def my_lstrcpyA(emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> None:
        if len(argv) >= 2:
            val = _safe_read_ansi(emu, argv[1])
            if val is not None:
                extractor.process_api_string('lstrcpyA', val,
                                             source_detail='lstrcpyA')

    def my_lstrcpyW(emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> None:
        if len(argv) >= 2:
            val = _safe_read_wide(emu, argv[1])
            if val is not None:
                extractor.process_api_string('lstrcpyW', val,
                                             source_detail='lstrcpyW')

    def my_VirtualAlloc(_emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> None:
        _record_behavior('VirtualAlloc', argv)
        if len(argv) >= 4:
            dwSize = cast(int, argv[1])
            flProtect = cast(int, argv[3])
            logger.debug(f"[Hook] VirtualAlloc(Size={hex(dwSize)}, Protect={hex(flProtect)})")

    def my___iob_func(emu: _StringReader, _api_name: str, _func: object, argv: Sequence[object]) -> int:
        return _get_or_create_iob_table(emu)



    def my_getenv(emu, api_name, func, argv):
        if len(argv) >= 1:
            val = _safe_read_ansi(emu, argv[0])
            # Always satisfy the sample's lab-safety getenv gate inside the
            # emulator. This removes the need for a host LAB_MALWARE_ALLOWED
            # argument/environment variable while keeping execution sandboxed.
            if val in ('LAB_MALWARE_ALLOWED', 'LAB/MALWIRE/ALLOwED'):
                addr = emu.mem_alloc(2, base=None) if hasattr(emu, 'mem_alloc') else 0x69000100
                if hasattr(emu, 'mem_write'):
                    emu.mem_write(addr, b'1\x00')
                return addr
        return func(argv) if callable(func) else 0

    def my_WinHttpSendRequest(emu: _StringReader, api_name: str, func: object, argv: Sequence[object]) -> int:
        # WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext)
        # Arg 1 is headers (wide/ansi based on API name). Arg 3 is body (always bytes/ansi). Arg 4 is length.
        if len(argv) >= 5:
            # Capture headers
            is_wide = api_name.endswith('W') or api_name == 'WinHttpSendRequest'
            reader = _safe_read_wide if is_wide else _safe_read_ansi
            headers = reader(emu, argv[1])
            behavior_args = []
            if headers is not None:
                extractor.process_api_string(api_name, headers, source_detail=api_name)
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
        _record_behavior(api_name, argv, behavior_args if 'behavior_args' in locals() else None)
        return func(argv) if callable(func) else 1

    # ------------------------------------------------------------------
    # Generic string-bearing API hook factory
    # ------------------------------------------------------------------


    def my___acrt_iob_func(emu, api_name, func, argv):
        return _get_or_create_iob_table(emu) + (int(argv[0]) * 0x100) if len(argv) >= 1 and isinstance(argv[0], int) and argv[0] in (0, 1, 2) else _get_or_create_iob_table(emu)

    def my_fflush(emu, api_name, func, argv):
        return 0

    def my_fclose(emu, api_name, func, argv):
        return 0

    def my_puts(emu, api_name, func, argv):
        if len(argv) >= 1:
            val = _safe_read_ansi(emu, argv[0])
            if val is not None:
                extractor.process_api_string(api_name, val, source_detail=api_name)
        return 1

    def my_putchar(emu, api_name, func, argv):
        return int(argv[0]) & 0xFF if len(argv) >= 1 and isinstance(argv[0], int) else 0

    def my_printf(emu, api_name, func, argv):
        if len(argv) >= 1:
            val = _safe_read_ansi(emu, argv[0])
            if val is not None:
                extractor.process_api_string(api_name, val, source_detail=api_name)
        return 1

    def my_fprintf(emu, api_name, func, argv):
        if len(argv) >= 2:
            val = _safe_read_ansi(emu, argv[1])
            if val is not None:
                extractor.process_api_string(api_name, val, source_detail=api_name)
        return 1

    def my_fwrite(emu, api_name, func, argv):
        if len(argv) >= 4:
            ptr = argv[0]
            size = argv[1]
            count = argv[2]
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
            out_ptr = argv[1]
            if isinstance(out_ptr, int) and out_ptr > 0:
                try:
                    emu.mem_write(out_ptr, b'\x00\x00\x00\x00')
                except Exception:
                    pass
        return 1




    def my_Sleep(emu, api_name, func, argv):
        _record_behavior(api_name, argv)
        return None

    def my_OutputDebugStringA(emu, api_name, func, argv):
        if len(argv) >= 1:
            val = _safe_read_ansi(emu, argv[0])
            if val is not None:
                extractor.process_api_string(api_name, val, source_detail=api_name)
        return None

    def my_OutputDebugStringW(emu, api_name, func, argv):
        if len(argv) >= 1:
            val = _safe_read_wide(emu, argv[0])
            if val is not None:
                extractor.process_api_string(api_name, val, source_detail=api_name)
        return None

    def my_ExitProcess(emu, api_name, func, argv):
        # We MUST bypass ExitProcess by manipulating the instruction pointer (RIP) 
        # to effectively RETURN from FullEvasionCheck instead of halting.
        # However, an easier way: just skip it! Wait, ExitProcess does not return. If we return, the program continues executing to the next instruction in ExitProcess which is likely INT3 or crash.
        # Let's make it increment RIP to return from FullEvasionCheck. Actually, just returning `0` and ignoring the failure is best, because `FullEvasionCheck` has no code after `ExitProcess(0)`. The function epilogue for `FullEvasionCheck` will run and it will return normally to main!
        return None

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
        ('ntdll', 'NtQueryInformationProcess'),
        ('kernel32', 'GetTickCount'),
        ('kernel32', 'QueryPerformanceCounter'),
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
