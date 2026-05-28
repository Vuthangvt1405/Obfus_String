# -*- coding: utf-8 -*-
import logging

logger = logging.getLogger(__name__)


def _safe_read_ansi(emu, ptr):
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


def _safe_read_wide(emu, ptr):
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
_STRING_API_HOOKS = [
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
]


def setup_api_hooks(se, extractor):
    """
    Purpose:
    Install API hooks that capture string arguments passed to common
    Windows APIs used by malware for string copy, memory allocation,
    and network communication.

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

    # ------------------------------------------------------------------
    # Original hooks (kernel32 string-copy / alloc)
    # ------------------------------------------------------------------

    def my_lstrcpyA(emu, api_name, func, argv):
        if len(argv) >= 2:
            val = _safe_read_ansi(emu, argv[1])
            if val is not None:
                extractor.process_api_string('lstrcpyA', val)

    def my_lstrcpyW(emu, api_name, func, argv):
        if len(argv) >= 2:
            val = _safe_read_wide(emu, argv[1])
            if val is not None:
                extractor.process_api_string('lstrcpyW', val)

    def my_VirtualAlloc(emu, api_name, func, argv):
        if len(argv) >= 4:
            dwSize = argv[1]
            flProtect = argv[3]
            logger.debug(f"[Hook] VirtualAlloc(Size={hex(dwSize)}, Protect={hex(flProtect)})")

    # ------------------------------------------------------------------
    # Generic string-bearing API hook factory
    # ------------------------------------------------------------------

    def _make_hook(hook_api_name, arg_specs):
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
        def _hook(emu, api_name, func, argv):
            for arg_idx, width in arg_specs:
                if arg_idx >= len(argv):
                    continue
                reader = _safe_read_ansi if width == 1 else _safe_read_wide
                val = reader(emu, argv[arg_idx])
                if val is not None:
                    extractor.process_api_string(hook_api_name, val)
        return _hook

    # ------------------------------------------------------------------
    # Install all hooks — each wrapped in its own try/except
    # ------------------------------------------------------------------

    installed = []

    # Legacy hooks
    for cb, mod, name in [
        (my_lstrcpyA, 'kernel32', 'lstrcpyA'),
        (my_lstrcpyW, 'kernel32', 'lstrcpyW'),
        (my_VirtualAlloc, 'kernel32', 'VirtualAlloc'),
    ]:
        try:
            se.add_api_hook(cb, mod, name)
            installed.append(name)
        except Exception as exc:
            logger.warning(f"[Hook] Không thể cài đặt hook {name}: {exc}")

    # Allowlist hooks
    for mod, api_name, arg_specs in _STRING_API_HOOKS:
        try:
            se.add_api_hook(_make_hook(api_name, arg_specs), mod, api_name)
            installed.append(api_name)
        except Exception as exc:
            logger.warning(f"[Hook] Không thể cài đặt hook {api_name}: {exc}")

    if installed:
        logger.info(f"[Hook] Đã cài đặt {len(installed)} API hooks: {', '.join(installed)}.")
