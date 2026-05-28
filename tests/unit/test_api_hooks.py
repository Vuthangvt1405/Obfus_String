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

    def read_mem_string(self, ptr, width=1):
        key = (ptr, width)
        if key in self._mem:
            return self._mem[key]
        raise Exception(f"unmapped address {hex(ptr)} width={width}")


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
        total_expected = 3 + len(_STRING_API_HOOKS)
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
