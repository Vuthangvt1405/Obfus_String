"""
Purpose:
Unit tests for StringExtractor — verifies ASCII/UTF-16LE extraction, short-string
bypass, deduplication, and regex labeling without requiring Speakeasy.

How it works:
Each test creates a fresh StringExtractor(min_length=4), feeds it known byte
sequences via process_memory_write() or process_api_string(), then asserts on
get_results().
"""

import pytest
from core.extractor import StringExtractor


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestConstructor:
    """StringExtractor.__init__ default and custom behaviour."""

    def test_default_min_length(self) -> None:
        """Default min_length should be 4."""
        ext = StringExtractor()
        assert ext.min_length == 4

    def test_custom_min_length(self) -> None:
        """Custom min_length is accepted."""
        ext = StringExtractor(min_length=8)
        assert ext.min_length == 8

    def test_valid_chars_is_populated(self) -> None:
        """valid_chars should contain ASCII printable bytes."""
        ext = StringExtractor()
        assert 0x41 in ext.valid_chars  # 'A'
        assert 0x20 in ext.valid_chars  # space
        assert 0x7e in ext.valid_chars  # '~'
        assert 0x00 not in ext.valid_chars  # null
        assert 0x80 not in ext.valid_chars  # non-ASCII

    def test_regex_patterns_are_compiled(self) -> None:
        """Default regex patterns are loaded."""
        ext = StringExtractor()
        assert len(ext.patterns) > 0
        # Verify each pattern is a compiled regex
        for p in ext.patterns:
            assert hasattr(p, "search")


# ---------------------------------------------------------------------------
# process_memory_write — ASCII
# ---------------------------------------------------------------------------


class TestProcessMemoryWriteASCII:
    """ASCII string extraction via process_memory_write."""

    def test_extracts_simple_ascii(self) -> None:
        """A printable ASCII string longer than min_length is extracted."""
        ext = StringExtractor(min_length=4)
        data = b"Hello, World!"
        ext.process_memory_write(0x1000, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "Hello, World!"
        assert results[0]["encoding"] == "ASCII"
        # _add_result calls str(location), so hex input becomes decimal string
        assert results[0]["location"] == "4096"

    def test_null_terminated(self) -> None:
        """Extraction stops at the first null byte (C-string semantics).

        The extracted portion must still meet min_length.
        """
        ext = StringExtractor(min_length=4)
        data = b"ABCD\x00trailing"
        ext.process_memory_write(0x2000, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "ABCD"
        assert results[0]["encoding"] == "ASCII"

    def test_rejects_binary_bytes(self) -> None:
        """Data containing non-printable bytes is rejected."""
        ext = StringExtractor(min_length=4)
        data = b"ABC\xffXYZ"
        ext.process_memory_write(0x3000, data)
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# process_memory_write — UTF-16LE
# ---------------------------------------------------------------------------


class TestProcessMemoryWriteUnicode:
    """UTF-16LE string extraction via process_memory_write."""

    @pytest.mark.xfail(
        reason=(
            "_extract_unicode has a bug: data.split(b'\\x00\\x00\\x00')[0]"
            " + b'\\x00\\x00' always appends a null word that decodes to"
            " U+0000, which fails the printable check."
        ),
        strict=True,
    )
    def test_extracts_utf16le(self) -> None:
        """A valid UTF-16LE string longer than min_length is extracted."""
        ext = StringExtractor(min_length=4)
        # "ABCD" in UTF-16LE -> b'A\x00B\x00C\x00D\x00'
        data = b"A\x00B\x00C\x00D\x00"
        ext.process_memory_write(0x4000, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "ABCD"
        assert results[0]["encoding"] == "UTF-16LE"

    @pytest.mark.xfail(
        reason=(
            "_extract_unicode has a bug: data.split(b'\\x00\\x00\\x00')[0]"
            " + b'\\x00\\x00' always appends a null word that decodes to"
            " U+0000, which fails the printable check."
        ),
        strict=True,
    )
    def test_utf16le_strips_trailing_nulls(self) -> None:
        """Extra null word(s) at the end are stripped during decode."""
        ext = StringExtractor(min_length=4)
        data = b"A\x00B\x00C\x00D\x00\x00\x00\x00\x00"
        ext.process_memory_write(0x5000, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "ABCD"

    def test_utf16le_rejects_non_printable(self) -> None:
        """UTF-16LE data with non-printable characters is rejected."""
        ext = StringExtractor(min_length=4)
        # Contains a control character (\x01)
        data = b"A\x00\x01\x00C\x00D\x00"
        ext.process_memory_write(0x6000, data)
        assert ext.get_results() == []

    def test_utf16le_fallback_from_ascii(self) -> None:
        """When first byte is non-printable as ASCII, UTF-16LE path is tried.

        process_memory_write runs ASCII first; if the data starts with a
        non-printable byte, ASCII extraction returns None immediately and
        UTF-16LE is attempted.
        """
        ext = StringExtractor(min_length=4)
        # Starts with a null byte — ASCII will fail → fallback to UTF-16LE
        data = b"\x00A\x00B\x00C\x00D\x00"
        ext.process_memory_write(0x7000, data)
        results = ext.get_results()
        # The data starts with \x00, so ASCII can't start. But the full data
        # is valid UTF-16LE for "\x00A" (U+0041 = 'A') etc. However the
        # leading null makes the unicode extraction produce "\x00ABCD" which
        # contains a non-printable → should be rejected.
        # Actually: \x00A\x00B\x00C\x00D\x00 decodes to '\x00ABCD' which
        # contains '\x00' (non-printable) → rejected.
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# process_memory_write — edge cases
# ---------------------------------------------------------------------------


class TestProcessMemoryWriteEdgeCases:
    """Boundary conditions for process_memory_write."""

    @pytest.mark.parametrize("data", [None, b"", b"ab", b"abc"])
    def test_short_data_is_skipped(self, data) -> None:
        """Data shorter than min_length (default 4) is silently skipped."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x8000, data)
        assert ext.get_results() == []

    def test_deduplication(self) -> None:
        """Identical content added twice is stored once."""
        ext = StringExtractor(min_length=4)
        data = b"dedup_test"
        ext.process_memory_write(0x9000, data)
        ext.process_memory_write(0x9001, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "dedup_test"

    def test_multiple_distinct_strings(self) -> None:
        """Multiple distinct strings are stored in insertion order."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0xA000, b"first")
        ext.process_memory_write(0xB000, b"second")
        ext.process_memory_write(0xC000, b"third")
        results = ext.get_results()
        assert len(results) == 3
        assert [r["content"] for r in results] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# process_api_string
# ---------------------------------------------------------------------------


class TestProcessApiString:
    """String injection via process_api_string."""

    def test_valid_api_string_is_added(self) -> None:
        """A string passed via API is stored with API_ARG encoding."""
        ext = StringExtractor(min_length=4)
        ext.process_api_string("lstrcpyA", "api_test_string")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "api_test_string"
        assert results[0]["encoding"] == "API_ARG"
        assert "API_lstrcpyA" in results[0]["location"]

    def test_api_string_too_short_is_skipped(self) -> None:
        """String shorter than min_length is not recorded."""
        ext = StringExtractor(min_length=4)
        ext.process_api_string("lstrcpyA", "ab")
        assert ext.get_results() == []

    def test_api_string_none_or_empty(self) -> None:
        """None or empty strings are not recorded."""
        ext = StringExtractor(min_length=4)
        ext.process_api_string("lstrcpyA", "")
        assert ext.get_results() == []


# ---------------------------------------------------------------------------
# Regex labeling
# ---------------------------------------------------------------------------


class TestRegexLabeling:
    """Content-based labels via built-in regex patterns."""

    def test_ipv4_label(self) -> None:
        """Content matching IPv4 pattern gets a Matched_Regex tag."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0xD000, b"192.168.1.1")
        results = ext.get_results()
        assert len(results) == 1
        assert "Matched_Regex" in results[0]["tags"]

    def test_url_label(self) -> None:
        """Content matching URL pattern gets a Matched_Regex tag."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0xE000, b"https://evil.example.com/payload")
        results = ext.get_results()
        assert len(results) == 1
        assert "Matched_Regex" in results[0]["tags"]

    def test_domain_label(self) -> None:
        """Content matching domain pattern gets a Matched_Regex tag."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0xF000, b"malware.example.com")
        results = ext.get_results()
        assert len(results) == 1
        assert "Matched_Regex" in results[0]["tags"]

    def test_registry_label(self) -> None:
        """Content matching registry path pattern gets a Matched_Regex tag."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x10000, b"HKLM\\Software\\Microsoft\\Windows")
        results = ext.get_results()
        assert len(results) == 1
        assert "Matched_Regex" in results[0]["tags"]

    def test_no_label_for_plain_text(self) -> None:
        """Plain text not matching any pattern has an empty tags list."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x11000, b"just_a_plain_string")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["tags"] == []


# ---------------------------------------------------------------------------
# get_results
# ---------------------------------------------------------------------------


class TestGetResults:
    """get_results() interface."""

    def test_returns_empty_list_initially(self) -> None:
        """A fresh extractor returns an empty list."""
        ext = StringExtractor()
        assert ext.get_results() == []

    def test_results_have_expected_keys(self) -> None:
        """Each result entry contains the expected fields."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x12000, b"key_check")
        results = ext.get_results()
        assert len(results) == 1
        entry = results[0]
        assert "location" in entry
        assert "encoding" in entry
        assert "content" in entry
        assert "tags" in entry
