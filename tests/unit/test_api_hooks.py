# -*- coding: utf-8 -*-
"""
Unit tests for hooks/api_hooks.py — verifies safe pointer reading,
allowlist-driven hook installation, argument capture routing to
StringExtractor.process_api_string(), and non-fatal failure on bad pointers.
"""

import pytest
from unittest.mock import MagicMock, call

from core.extractor import StringExtractor
from hooks.api_hooks import (
    _safe_read_ansi,
    _safe_read_wide,
    _STRING_API_HOOKS,
    setup_api_hooks,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeEmu:
    """Minimal emulator stub that returns canned strings by address."""

    def __init__(self, mem_table=None):
        self._mem = mem_table or {}
        self._allocations = {}
        self._written = {}

    def read_mem_string(self, ptr, width=1):
        key = (ptr, width)
        if key in self._mem:
            return self._mem[key]
        raise Exception(f"unmapped address {hex(ptr)} width={width}")
        
    def mem_alloc(self, size, base=None):
        addr = 0x69000000
        self._allocations[addr] = size
        return addr
        
    def mem_write(self, addr, data):
        self._written[addr] = data
        
    def get_ptr_size(self):
        return 4


# ---------------------------------------------------------------------------
# _safe_read_ansi / _safe_read_wide
# ---------------------------------------------------------------------------


class TestSafeReadAnsi:

    def test_returns_string_on_valid_pointer(self) -> None:
        emu = FakeEmu({(0x1000, 1): "hello"})
        assert _safe_read_ansi(emu, 0x1000) == "hello"

    def test_returns_none_on_null_pointer(self) -> None:
        emu = FakeEmu()
        assert _safe_read_ansi(emu, 0) is None

    def test_returns_none_on_negative_pointer(self) -> None:
        emu = FakeEmu()
        assert _safe_read_ansi(emu, -1) is None

    def test_returns_none_on_non_int_pointer(self) -> None:
        emu = FakeEmu()
        assert _safe_read_ansi(emu, "bad") is None

    def test_returns_none_on_unmapped_address(self) -> None:
        emu = FakeEmu()
        assert _safe_read_ansi(emu, 0xDEAD) is None


class TestSafeReadWide:

    def test_returns_string_on_valid_pointer(self) -> None:
        emu = FakeEmu({(0x2000, 2): "wide_str"})
        assert _safe_read_wide(emu, 0x2000) == "wide_str"

    def test_returns_none_on_null_pointer(self) -> None:
        emu = FakeEmu()
        assert _safe_read_wide(emu, 0) is None

    def test_returns_none_on_unmapped_address(self) -> None:
        emu = FakeEmu()
        assert _safe_read_wide(emu, 0xBEEF) is None


# ---------------------------------------------------------------------------
# setup_api_hooks — hook installation
# ---------------------------------------------------------------------------


class TestSetupApiHooks:

    def test_installs_legacy_and_allowlist_hooks(self) -> None:
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        hooked_names = [c.args[2] for c in se.add_api_hook.call_args_list]
        assert "lstrcpyA" in hooked_names
        assert "lstrcpyW" in hooked_names
        assert "VirtualAlloc" in hooked_names
        assert "InternetConnectA" in hooked_names
        assert "InternetOpenA" in hooked_names

    def test_hook_failure_is_nonfatal(self) -> None:
        se = MagicMock()
        se.add_api_hook.side_effect = RuntimeError("hook engine broken")
        ext = StringExtractor()
        # Must not raise
        setup_api_hooks(se, ext)

    def test_partial_hook_failure_installs_remaining(self) -> None:
        call_count = {"n": 0}
        def flaky_add(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise RuntimeError("one hook fails")
        se = MagicMock()
        se.add_api_hook.side_effect = flaky_add
        ext = StringExtractor()
        setup_api_hooks(se, ext)
        # All hooks attempted despite one failure
        total_expected = 25 + len(_STRING_API_HOOKS)
        assert se.add_api_hook.call_count == total_expected


# ---------------------------------------------------------------------------
# InternetConnectA hook — argument capture
# ---------------------------------------------------------------------------


class TestInternetConnectAHook:

    def _install_and_fire(self, argv, mem_table):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu(mem_table)
        # Find the InternetConnectA callback
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "InternetConnectA":
                cb = c.args[0]
                cb(emu, "InternetConnectA", None, argv)
                break
        return ext

    def test_captures_server_name(self) -> None:
        ext = self._install_and_fire(
            argv=[0xAAAA, 0x5000, 80, 0, 0, 3, 0, 0],
            mem_table={(0x5000, 1): "thecyberyeti.com"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "thecyberyeti.com"
        assert results[0]["encoding"] == "API_ARG"
        assert "InternetConnectA" in results[0]["location"]

    def test_bad_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            argv=[0xAAAA, 0xDEAD, 80, 0, 0, 3, 0, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_null_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            argv=[0xAAAA, 0, 80, 0, 0, 3, 0, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_short_argv_does_not_crash(self) -> None:
        ext = self._install_and_fire(argv=[0xAAAA], mem_table={})
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# InternetOpenA hook — user-agent capture
# ---------------------------------------------------------------------------


class TestInternetOpenAHook:

    def test_captures_user_agent(self) -> None:
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu({(0x3000, 1): "Mozilla/4.0 (TheCyberYeti)"})
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "InternetOpenA":
                cb = c.args[0]
                cb(emu, "InternetOpenA", None, [0x3000, 0, 0, 0, 0])
                break

        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "Mozilla/4.0 (TheCyberYeti)"
        assert "InternetOpenA" in results[0]["location"]


# ---------------------------------------------------------------------------
# HttpOpenRequestA hook — multi-arg capture
# ---------------------------------------------------------------------------


class TestHttpOpenRequestAHook:

    def test_captures_verb_and_path(self) -> None:
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu({
            (0x4000, 1): "POST",
            (0x4100, 1): "/api/beacon",
        })
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "HttpOpenRequestA":
                cb = c.args[0]
                cb(emu, "HttpOpenRequestA", None,
                   [0xBBBB, 0x4000, 0x4100, 0, 0, 0, 0, 0])
                break

        results = ext.get_results()
        contents = {r["content"] for r in results}
        assert "POST" in contents
        assert "/api/beacon" in contents


# ---------------------------------------------------------------------------
# URLDownloadToFileA hook
# ---------------------------------------------------------------------------


class TestURLDownloadToFileAHook:

    def test_captures_url_and_filename(self) -> None:
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu({
            (0x6000, 1): "http://evil.com/payload.exe",
            (0x6100, 1): "C:\\Temp\\payload.exe",
        })
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "URLDownloadToFileA":
                cb = c.args[0]
                cb(emu, "URLDownloadToFileA", None,
                   [0, 0x6000, 0x6100, 0, 0])
                break

        results = ext.get_results()
        contents = {r["content"] for r in results}
        assert "http://evil.com/payload.exe" in contents
        assert "C:\\Temp\\payload.exe" in contents


# ---------------------------------------------------------------------------
# lstrcpyA legacy hook still works
# ---------------------------------------------------------------------------


class TestLstrcpyALegacyHook:

    def test_captures_source_string(self) -> None:
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu({(0x7000, 1): "legacy_copy_test"})
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "lstrcpyA":
                cb = c.args[0]
                cb(emu, "lstrcpyA", None, [0xCCCC, 0x7000])
                break

        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "legacy_copy_test"
        assert "lstrcpyA" in results[0]["location"]


# ---------------------------------------------------------------------------
# WinHttpConnect hook — WinHTTP network server name capture
# ---------------------------------------------------------------------------


class TestWinHttpConnectHook:

    def _install_and_fire(self, argv, mem_table):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu(mem_table)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "WinHttpConnect":
                cb = c.args[0]
                cb(emu, "WinHttpConnect", None, argv)
                break
        return ext

    def test_captures_server_name(self) -> None:
        ext = self._install_and_fire(
            argv=[0xAAAA, 0x5000, 443, 0],
            mem_table={(0x5000, 2): "c2.malware.test"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "c2.malware.test"
        assert "WinHttpConnect" in results[0]["location"]

    def test_bad_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            argv=[0xAAAA, 0xDEAD, 443, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_null_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            argv=[0xAAAA, 0, 443, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_short_argv_does_not_crash(self) -> None:
        ext = self._install_and_fire(argv=[0xAAAA], mem_table={})
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# CreateProcessA / CreateProcessW hooks — process creation
# ---------------------------------------------------------------------------


class TestCreateProcessHook:

    def _install_and_fire(self, api_name, argv, mem_table):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu(mem_table)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == api_name:
                cb = c.args[0]
                cb(emu, api_name, None, argv)
                break
        return ext

    def test_captures_application_name_ansi(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessA",
            argv=[0x5000, 0x5100, 0, 0, 0, 0, 0, 0, 0, 0],
            mem_table={(0x5000, 1): "cmd.exe"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "cmd.exe"
        assert "CreateProcessA" in results[0]["location"]

    def test_captures_command_line_ansi(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessA",
            argv=[0x5000, 0x5100, 0, 0, 0, 0, 0, 0, 0, 0],
            mem_table={(0x5100, 1): "cmd.exe /c whoami"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "cmd.exe /c whoami"
        assert "CreateProcessA" in results[0]["location"]

    def test_captures_application_name_wide(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessW",
            argv=[0x5000, 0x5100, 0, 0, 0, 0, 0, 0, 0, 0],
            mem_table={(0x5000, 2): "powershell.exe"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "powershell.exe"
        assert "CreateProcessW" in results[0]["location"]

    def test_captures_command_line_wide(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessW",
            argv=[0x5000, 0x5100, 0, 0, 0, 0, 0, 0, 0, 0],
            mem_table={(0x5100, 2): "calc.exe"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "calc.exe"
        assert "CreateProcessW" in results[0]["location"]

    def test_bad_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessA",
            argv=[0xDEAD, 0xBEEF, 0, 0, 0, 0, 0, 0, 0, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_null_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessA",
            argv=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_short_argv_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "CreateProcessA",
            argv=[0x5000],
            mem_table={},
        )
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# ShellExecuteA / ShellExecuteW hooks — command / process execution
# ---------------------------------------------------------------------------


class TestShellExecuteHook:

    def _install_and_fire(self, api_name, argv, mem_table):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu(mem_table)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == api_name:
                cb = c.args[0]
                cb(emu, api_name, None, argv)
                break
        return ext

    def test_captures_operation_ansi(self) -> None:
        ext = self._install_and_fire(
            "ShellExecuteA",
            argv=[0, 0x5000, 0x5100, 0x5200, 0, 0],
            mem_table={(0x5100, 1): "https://evil.com/pay.exe"},
        )
        results = ext.get_results()
        assert len(results) >= 1
        assert results[0]["content"] == "https://evil.com/pay.exe"
        assert "ShellExecuteA" in results[0]["location"]

    def test_captures_file_wide(self) -> None:
        ext = self._install_and_fire(
            "ShellExecuteW",
            argv=[0, 0x5000, 0x5100, 0x5200, 0, 0],
            mem_table={(0x5100, 2): "C:\\Malware\\payload.exe"},
        )
        results = ext.get_results()
        assert len(results) >= 1
        assert results[0]["content"] == "C:\\Malware\\payload.exe"
        assert "ShellExecuteW" in results[0]["location"]

    def test_bad_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "ShellExecuteA",
            argv=[0, 0xDEAD, 0xBEEF, 0, 0, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_null_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "ShellExecuteA",
            argv=[0, 0, 0, 0, 0, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_short_argv_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "ShellExecuteA",
            argv=[0, 0x5000],
            mem_table={},
        )
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# RegOpenKeyExA / RegOpenKeyExW hooks — registry access
# ---------------------------------------------------------------------------


class TestRegOpenKeyExHook:

    def _install_and_fire(self, api_name, argv, mem_table):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu(mem_table)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == api_name:
                cb = c.args[0]
                cb(emu, api_name, None, argv)
                break
        return ext

    def test_captures_subkey_ansi(self) -> None:
        ext = self._install_and_fire(
            "RegOpenKeyExA",
            argv=[0x80000002, 0x5000, 0, 0, 0x6000],
            mem_table={(0x5000, 1): "Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert "Software\\Microsoft\\Windows\\CurrentVersion\\Run" in results[0]["content"]
        assert "RegOpenKeyExA" in results[0]["location"]

    def test_captures_subkey_wide(self) -> None:
        ext = self._install_and_fire(
            "RegOpenKeyExW",
            argv=[0x80000002, 0x5000, 0, 0, 0x6000],
            mem_table={(0x5000, 2): "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert "RunOnce" in results[0]["content"]
        assert "RegOpenKeyExW" in results[0]["location"]

    def test_bad_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "RegOpenKeyExA",
            argv=[0x80000002, 0xDEAD, 0, 0, 0x6000],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_null_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "RegOpenKeyExA",
            argv=[0x80000002, 0, 0, 0, 0x6000],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_short_argv_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "RegOpenKeyExA",
            argv=[0x80000002],
            mem_table={},
        )
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# CreateFileA / CreateFileW hooks — filesystem access
# ---------------------------------------------------------------------------


class TestCreateFileHook:

    def _install_and_fire(self, api_name, argv, mem_table):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        emu = FakeEmu(mem_table)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == api_name:
                cb = c.args[0]
                cb(emu, api_name, None, argv)
                break
        return ext

    def test_captures_filename_ansi(self) -> None:
        ext = self._install_and_fire(
            "CreateFileA",
            argv=[0x5000, 0x80000000, 0, 0, 3, 0x80, 0],
            mem_table={(0x5000, 1): "C:\\Windows\\Temp\\malware.dll"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "C:\\Windows\\Temp\\malware.dll"
        assert "CreateFileA" in results[0]["location"]

    def test_captures_filename_wide(self) -> None:
        ext = self._install_and_fire(
            "CreateFileW",
            argv=[0x5000, 0x80000000, 0, 0, 3, 0x80, 0],
            mem_table={(0x5000, 2): "C:\\Users\\Public\\payload.exe"},
        )
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "C:\\Users\\Public\\payload.exe"
        assert "CreateFileW" in results[0]["location"]

    def test_bad_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "CreateFileA",
            argv=[0xDEAD, 0x80000000, 0, 0, 3, 0x80, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_null_pointer_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "CreateFileA",
            argv=[0, 0x80000000, 0, 0, 3, 0x80, 0],
            mem_table={},
        )
        assert ext.get_results() == []

    def test_short_argv_does_not_crash(self) -> None:
        ext = self._install_and_fire(
            "CreateFileA",
            argv=[0x5000],
            mem_table={},
        )
        assert ext.get_results() == []

# ---------------------------------------------------------------------------
# __iob_func hook coverage 
# ---------------------------------------------------------------------------

class TestIobFuncHook:
    def _install_and_fire(self, argv, emu):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)

        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "__iob_func":
                cb = c.args[0]
                return cb(emu, "__iob_func", None, argv), ext
        return None, ext

    def test_allocates_and_returns_stable_pointer(self):
        emu = FakeEmu()
        ptr1, ext1 = self._install_and_fire([], emu)
        ptr2, ext2 = self._install_and_fire([], emu)
        
        assert ptr1 != 0
        assert ptr1 == ptr2
        assert len(ext1.get_results()) == 0

# ---------------------------------------------------------------------------
# getenv hook coverage
# ---------------------------------------------------------------------------

class TestGetEnvHook:
    def _install_and_fire(self, argv, emu):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "getenv":
                cb = c.args[0]
                return cb(emu, "getenv", lambda args: 42, argv), ext
        return None, ext

    def test_returns_lab_malware_pointer_without_host_env(self, monkeypatch):
        monkeypatch.delenv('LAB_MALWARE_ALLOWED', raising=False)
        emu = FakeEmu({(0x8000, 1): "LAB_MALWARE_ALLOWED"})
        ptr, ext = self._install_and_fire([0x8000], emu)
        assert ptr != 0 and ptr != 42
        assert len(ext.get_results()) == 0

    def test_default_returns_func_result(self, monkeypatch):
        emu = FakeEmu({(0x8000, 1): "SOME_OTHER_VAR"})
        ptr, ext = self._install_and_fire([0x8000], emu)
        assert ptr == 42

# ---------------------------------------------------------------------------
# WinHttpSendRequest hook coverage
# ---------------------------------------------------------------------------

class TestWinHttpSendRequestHook:
    def _install_and_fire(self, argv, emu):
        se = MagicMock()
        ext = StringExtractor()
        setup_api_hooks(se, ext)
        for c in se.add_api_hook.call_args_list:
            if c.args[2] == "WinHttpSendRequest":
                cb = c.args[0]
                cb(emu, "WinHttpSendRequest", lambda args: 1, argv)
                break
        return ext

    def test_captures_headers_and_body(self):
        emu = FakeEmu({
            (0x1000, 2): "Content-Type: text/plain",
            (0x2000, 1): "malicious_data_here"
        })
        ext = self._install_and_fire([1, 0x1000, 24, 0x2000, 14, 0, 0], emu)
        res = [r['content'] for r in ext.get_results()]
        assert "Content-Type: text/plain" in res
        assert "malicious_data" in res

