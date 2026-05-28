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


# ---------------------------------------------------------------------------
# scan_buffer — larger memory scanning
# ---------------------------------------------------------------------------


class TestScanBuffer:
    """scan_buffer() extracts multiple strings from noisy memory dumps."""

    def test_finds_domain_embedded_in_noise(self) -> None:
        """ASCII domain surrounded by cipher noise is extracted."""
        ext = StringExtractor(min_length=4)
        noise_before = bytes(range(0x80, 0xA0))  # 32 non-printable bytes
        noise_after = bytes(range(0xC0, 0xE0))   # 32 non-printable bytes
        payload = b"thecyberyeti.com"
        data = noise_before + payload + noise_after
        ext.scan_buffer(0x40000, data)
        results = ext.get_results()
        contents = [r["content"] for r in results]
        assert "thecyberyeti.com" in contents

    def test_embedded_string_not_at_offset_zero(self) -> None:
        """Strings not starting at offset 0 are found with correct address."""
        ext = StringExtractor(min_length=4)
        data = b"\xff\xfe\xfd" + b"ABCDEFGH" + b"\xff\xfe"
        ext.scan_buffer(0x1000, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "ABCDEFGH"
        assert results[0]["location"] == str(0x1000 + 3)

    def test_multiple_ascii_fragments(self) -> None:
        """Multiple distinct printable runs are each extracted."""
        ext = StringExtractor(min_length=4)
        data = b"\xff" + b"first" + b"\xff\xff" + b"second" + b"\xff"
        ext.scan_buffer(0x2000, data)
        results = ext.get_results()
        contents = [r["content"] for r in results]
        assert "first" in contents
        assert "second" in contents

    def test_rejects_short_noise_fragments(self) -> None:
        """Runs shorter than min_length are not reported."""
        ext = StringExtractor(min_length=4)
        data = b"\xff" + b"ab" + b"\xff" + b"cd" + b"\xff"
        ext.scan_buffer(0x3000, data)
        assert ext.get_results() == []

    def test_utf16le_embedded_in_noise(self) -> None:
        """UTF-16LE string surrounded by noise is extracted."""
        ext = StringExtractor(min_length=4)
        noise = b"\xff\xff\xff\xff"
        payload = b"T\x00e\x00s\x00t\x00"  # "Test" in UTF-16LE
        data = noise + payload + noise
        ext.scan_buffer(0x5000, data)
        results = ext.get_results()
        contents = [r["content"] for r in results]
        assert "Test" in contents

    def test_deduplication_across_scan(self) -> None:
        """Identical strings found at different offsets are stored once."""
        ext = StringExtractor(min_length=4)
        data = b"\xff" + b"dupe" + b"\xff\xff" + b"dupe" + b"\xff"
        ext.scan_buffer(0x6000, data)
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "dupe"

    def test_empty_buffer_is_safe(self) -> None:
        """Passing empty or None data does not crash."""
        ext = StringExtractor(min_length=4)
        ext.scan_buffer(0x7000, b"")
        ext.scan_buffer(0x7000, None)
        assert ext.get_results() == []

    def test_regex_labels_applied_in_scan(self) -> None:
        """Regex labels still apply to strings found by scan_buffer."""
        ext = StringExtractor(min_length=4)
        data = b"\xff\xff" + b"192.168.1.1" + b"\xff\xff"
        ext.scan_buffer(0x8000, data)
        results = ext.get_results()
        assert len(results) >= 1
        matched = [r for r in results if r["content"] == "192.168.1.1"]
        assert len(matched) == 1
        assert "Matched_Regex" in matched[0]["tags"]

    def test_process_memory_write_still_works(self) -> None:
        """Existing process_memory_write is not broken by scan_buffer addition."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x1000, b"Hello")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "Hello"


# ---------------------------------------------------------------------------
# Provenance — backward-compatible source tagging
# ---------------------------------------------------------------------------


class TestProvenance:
    """Optional `source` field tracks where each string was captured."""

    def test_mem_write_has_provenance(self) -> None:
        """process_memory_write results carry source='mem_write'."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x1000, b"mem_write_string")
        entry = ext.get_results()[0]
        assert entry["source"] == "mem_write"

    def test_api_hook_has_provenance(self) -> None:
        """process_api_string results carry source='api_hook'."""
        ext = StringExtractor(min_length=4)
        ext.process_api_string("lstrcpyA", "api_hook_string")
        entry = ext.get_results()[0]
        assert entry["source"] == "api_hook"

    def test_deferred_scan_has_provenance(self) -> None:
        """scan_buffer results carry source='deferred_scan'."""
        ext = StringExtractor(min_length=4)
        data = b"\xff" + b"deferred_string" + b"\xff"
        ext.scan_buffer(0x2000, data)
        entry = ext.get_results()[0]
        assert entry["source"] == "deferred_scan"

    def test_required_keys_still_present_with_source(self) -> None:
        """Entry with source still has all required fields (location, encoding, content, tags)."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x3000, b"key_check_provenance")
        entry = ext.get_results()[0]
        assert "location" in entry
        assert "encoding" in entry
        assert "content" in entry
        assert "tags" in entry
        assert "source" in entry

    def test_dedup_not_affected_by_source(self) -> None:
        """Same content from different sources is stored once (dedup is content-only)."""
        ext = StringExtractor(min_length=4)
        # Add via mem_write and api_hook with same content
        ext.process_memory_write(0x4000, b"shared_content")
        ext.process_api_string("some_api", "shared_content")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "shared_content"
        # api_hook elevates over mem_write (provenance merge)
        assert results[0]["source"] == "api_hook"

    def test_content_only_consumer_ignores_source(self) -> None:
        """A consumer reading only content/encoding/location/tags does not break."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x5000, b"content_only_test")
        ext.process_api_string("lstrcpyA", "api_only_test")
        ext.scan_buffer(0x6000, b"\xff" + b"scan_only_test" + b"\xff")
        for entry in ext.get_results():
            # A legacy consumer that never looks at 'source' must still work
            assert "location" in entry
            assert "encoding" in entry
            assert "content" in entry
            assert "tags" in entry
            # source is optional — accessing it would not fail, but
            # a consumer that ignores it is fine
            assert len(entry["content"]) >= 4

    def test_source_never_overwrites_mandatory_fields(self) -> None:
        """The 'source' key must not collide with or overwrite mandatory fields."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x7000, b"safe_provenance")
        entry = ext.get_results()[0]
        # Verify mandatory fields are strings (or list for tags) as expected
        assert isinstance(entry["location"], str)
        assert isinstance(entry["encoding"], str)
        assert isinstance(entry["content"], str)
        assert isinstance(entry["tags"], list)
        assert isinstance(entry["source"], str)


# ---------------------------------------------------------------------------
# Noise filter — repetitive padding, alphabets, Base64 constants
# ---------------------------------------------------------------------------


class TestNoiseFilter:
    """Repetitive padding, standard alphabets, and Base64 constants are
    recognized as noise and filtered from results."""

    def test_repetitive_padding_filtered(self) -> None:
        """Repetitive padding like '((((...' is not stored."""
        ext = StringExtractor(min_length=4)
        data = b"((((((((((((((((((((((((((("  # 25 parens — all same char
        ext.process_memory_write(0x1000, data)
        assert ext.get_results() == []

    def test_uppercase_alphabet_filtered(self) -> None:
        """Standard uppercase alphabet is not stored."""
        ext = StringExtractor(min_length=4)
        data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ext.process_memory_write(0x2000, data)
        assert ext.get_results() == []

    def test_lowercase_alphabet_filtered(self) -> None:
        """Standard lowercase alphabet is not stored."""
        ext = StringExtractor(min_length=4)
        data = b"abcdefghijklmnopqrstuvwxyz"
        ext.process_memory_write(0x3000, data)
        assert ext.get_results() == []

    def test_base64_alphabet_filtered(self) -> None:
        """Full Base64 alphabet (A-Za-z0-9+/) is not stored."""
        ext = StringExtractor(min_length=4)
        data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        ext.process_memory_write(0x4000, data)
        assert ext.get_results() == []

    def test_useful_string_survives_noise_filter(self) -> None:
        """Useful strings like svchost.exe are NOT filtered."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x5000, b"svchost.exe")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "svchost.exe"

    def test_useful_string_among_noise_in_buffer(self) -> None:
        """scan_buffer finds useful strings while filtering noise."""
        ext = StringExtractor(min_length=4)
        noise = b"((((((((((((((((("  # 17 parens
        useful = b"svchost.exe"
        data = b"\xff" + noise + b"\xff" + useful + b"\xff" + noise + b"\xff"
        ext.scan_buffer(0x6000, data)
        results = ext.get_results()
        contents = [r["content"] for r in results]
        assert "svchost.exe" in contents
        assert "(((((((((((((((((" not in contents


# ---------------------------------------------------------------------------
# Provenance merge / elevation — API priority over memory
# ---------------------------------------------------------------------------


class TestProvenanceMerge:
    """When the same content is observed from multiple sources, the API
    hook source takes priority over memory-write or deferred-scan sources,
    and no duplicate entry is emitted."""

    def test_api_elevates_over_mem_write(self) -> None:
        """String first seen via mem_write then API → source becomes api_hook."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x1000, b"shared_content")
        ext.process_api_string("some_api", "shared_content")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "shared_content"
        assert results[0]["source"] == "api_hook"

    def test_api_elevates_over_deferred_scan(self) -> None:
        """String first seen via deferred_scan then API → source becomes api_hook."""
        ext = StringExtractor(min_length=4)
        data = b"\xff\xff" + b"shared_content" + b"\xff\xff"
        ext.scan_buffer(0x2000, data)
        ext.process_api_string("some_api", "shared_content")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "shared_content"
        assert results[0]["source"] == "api_hook"

    def test_api_stays_when_added_first(self) -> None:
        """String first seen via API then memory → source stays api_hook."""
        ext = StringExtractor(min_length=4)
        ext.process_api_string("some_api", "shared_content")
        ext.process_memory_write(0x3000, b"shared_content")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "shared_content"
        assert results[0]["source"] == "api_hook"

    def test_no_duplicates_after_multi_source_merge(self) -> None:
        """Multiple additions of same content from different sources produce one entry."""
        ext = StringExtractor(min_length=4)
        ext.process_memory_write(0x4000, b"dup_content")
        ext.process_api_string("api1", "dup_content")
        ext.process_api_string("api2", "dup_content")
        ext.process_memory_write(0x5000, b"dup_content")
        results = ext.get_results()
        assert len(results) == 1
        assert results[0]["content"] == "dup_content"
