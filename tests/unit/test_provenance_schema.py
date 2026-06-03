# -*- coding: utf-8 -*-
"""
Purpose:
Additive provenance contract tests — guarantees the minimal JSON schema for
every extracted string entry in the reporter output, and ensures optional
extra fields are preserved (or absent) without breaking legacy readers.

Required fields (every entry MUST have these):
  - location (str)  — hex address or API name where the string was found
  - encoding (str)  — "ASCII", "UTF-16LE", or "API_ARG"
  - content  (str)  — the extracted string value
  - tags     (list) — classification tags; may be empty

Optional fields (MUST survive round-trip when present, ignored when absent):
  - source        (str) — origin descriptor
  - source_detail (str) — detailed origin info
  - (any other opaque keys that consumers may attach)
"""

import json
import pytest
from utils.reporter import ReportGenerator


# ---------------------------------------------------------------------------
# Explicit dictionaries holding the provenance contract
# ---------------------------------------------------------------------------

MINIMAL_ENTRY = {
    "location": "0x1234",
    "encoding": "ASCII",
    "content": "malstring_emu_test_string",
    "tags": [],
}

ENTRY_WITH_EXTRAS = {
    "location": "0x5678",
    "encoding": "UTF-16LE",
    "content": "extra_fields_preserved",
    "tags": ["Matched_Regex"],
    "source": "memory_write",
    "source_detail": "hook_callback_0x5678",
}

ENTRY_API = {
    "location": "API_lstrcpyA",
    "encoding": "API_ARG",
    "content": "api_captured_string",
    "tags": [],
}

ENTRY_DEFERRED_SCAN = {
    "location": "0xABCD",
    "encoding": "ASCII",
    "content": "deferred_scan_result",
    "tags": ["Matched_Regex"],
    "source": "deferred_scan",
}

ENTRY_REGISTER_SCAN = {
    "location": "0xDCBA",
    "encoding": "UTF-16LE",
    "content": "register_scan_result",
    "tags": [],
    "source": "register_scan",
    "register_scan": "eax",
}

# The set of fields that MUST exist in every entry
REQUIRED_FIELDS = {"location", "encoding", "content", "tags"}

# The set of optional extra fields to test for round-trip survival
OPTIONAL_FIELDS = {"source", "source_detail"}


# ---------------------------------------------------------------------------
# Minimum-viable schema assertions
# ---------------------------------------------------------------------------

class TestRequiredFields:
    """Every provenance entry must carry location, encoding, content, tags."""

    @pytest.mark.unit
    def test_minimal_entry_has_all_required(self):
        """Verify a minimal entry contains every required field."""
        entry = MINIMAL_ENTRY.copy()
        for field in REQUIRED_FIELDS:
            assert field in entry, f"Required field '{field}' missing from minimal entry"

    @pytest.mark.unit
    def test_entry_with_extras_has_all_required(self):
        """Entry carrying optional fields must still have all required fields."""
        entry = ENTRY_WITH_EXTRAS.copy()
        for field in REQUIRED_FIELDS:
            assert field in entry, f"Required field '{field}' missing from extras entry"

    @pytest.mark.unit
    def test_api_entry_has_all_required(self):
        """API-captured entries must also satisfy the required-fields contract."""
        entry = ENTRY_API.copy()
        for field in REQUIRED_FIELDS:
            assert field in entry, f"Required field '{field}' missing from API entry"

    @pytest.mark.unit
    def test_required_field_types(self):
        """Each required field must be the correct Python type."""
        entry = MINIMAL_ENTRY.copy()
        assert isinstance(entry["location"], str), "location must be str"
        assert isinstance(entry["encoding"], str), "encoding must be str"
        assert isinstance(entry["content"], str), "content must be str"
        assert isinstance(entry["tags"], list), "tags must be list"

        # tags items must be strings when non-empty
        entry_with_tags = ENTRY_WITH_EXTRAS.copy()
        for t in entry_with_tags["tags"]:
            assert isinstance(t, str), "each tag must be str"

    @pytest.mark.unit
    def test_multiple_entries_all_have_required(self):
        """Every entry in a batch must satisfy required-fields contract."""
        batch = [MINIMAL_ENTRY.copy(), ENTRY_WITH_EXTRAS.copy(), ENTRY_API.copy()]
        for i, entry in enumerate(batch):
            for field in REQUIRED_FIELDS:
                assert field in entry, f"Entry {i} missing required field '{field}'"


# ---------------------------------------------------------------------------
# Optional field survival through ReportGenerator
# ---------------------------------------------------------------------------

class TestOptionalFieldsPreserved:
    """
    Optional extra fields (source, source_detail) must survive the
    ReportGenerator round-trip when present, and must NOT cause failures
    when absent.
    """

    @pytest.mark.unit
    def test_optional_fields_round_trip(self, tmp_path):
        """Optional extra fields survive save → load via ReportGenerator."""
        data_list = [MINIMAL_ENTRY.copy(), ENTRY_WITH_EXTRAS.copy()]
        out = tmp_path / "provenance_round_trip.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        extras_entry = next(
            e for e in report["strings"]
            if e["content"] == "extra_fields_preserved"
        )
        for field in OPTIONAL_FIELDS:
            assert field in extras_entry, f"Optional field '{field}' lost in round-trip"
            assert extras_entry[field] == ENTRY_WITH_EXTRAS[field], (
                f"Optional field '{field}' value changed"
            )

    @pytest.mark.unit
    def test_missing_optional_fields_dont_break(self, tmp_path):
        """Entries without optional fields produce valid output without error."""
        data_list = [MINIMAL_ENTRY.copy()]
        out = tmp_path / "provenance_minimal.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        entry = report["strings"][0]
        # Required fields must be present
        for field in REQUIRED_FIELDS:
            assert field in entry
        # Optional fields — absence must not raise KeyError or similar
        for field in OPTIONAL_FIELDS:
            # field simply won't exist; that's fine
            assert field not in entry or entry[field] is None, (
                f"Unexpected value for absent optional field '{field}'"
            )

    @pytest.mark.unit
    def test_mixed_batch_preserves_each_entry(self, tmp_path):
        """
        A batch mixing entries with and without optional fields must
        preserve each entry's data independently.
        """
        data_list = [
            MINIMAL_ENTRY.copy(),
            ENTRY_WITH_EXTRAS.copy(),
            ENTRY_API.copy(),
        ]
        out = tmp_path / "provenance_mixed.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        assert report["total_strings"] == 3
        assert len(report["strings"]) == 3

        # Confirm each entry still has its required fields
        for i, entry in enumerate(report["strings"]):
            for field in REQUIRED_FIELDS:
                assert field in entry, f"Entry {i} missing required field '{field}'"
            # Confirm type invariants
            assert isinstance(entry["location"], str), f"Entry {i}: location not str"
            assert isinstance(entry["encoding"], str), f"Entry {i}: encoding not str"
            assert isinstance(entry["content"], str), f"Entry {i}: content not str"
            assert isinstance(entry["tags"], list), f"Entry {i}: tags not list"

    @pytest.mark.unit
    def test_source_deferred_scan_round_trip(self, tmp_path):
        """
        An entry with source='deferred_scan' must survive save -> load
        via ReportGenerator without losing the field.
        """
        data_list = [ENTRY_DEFERRED_SCAN.copy()]
        out = tmp_path / "deferred_scan_round_trip.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        saved = report["strings"][0]
        assert saved["source"] == "deferred_scan"
        # Required fields unchanged
        assert saved["location"] == "0xABCD"
        assert saved["content"] == "deferred_scan_result"
        assert saved["encoding"] == "ASCII"
        assert saved["tags"] == ["Matched_Regex"]

    @pytest.mark.unit
    def test_source_deferred_scan_with_multiple_sources(self, tmp_path):
        """
        A batch mixing deferred_scan entries with other sources preserves
        each entry's source value independently.
        """
        data_list = [
            ENTRY_WITH_EXTRAS.copy(),     # source='memory_write'
            ENTRY_DEFERRED_SCAN.copy(),   # source='deferred_scan'
            ENTRY_API.copy(),             # no source field
        ]
        out = tmp_path / "mixed_sources.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        entries = {e["content"]: e for e in report["strings"]}
        assert entries["extra_fields_preserved"]["source"] == "memory_write"
        assert entries["deferred_scan_result"]["source"] == "deferred_scan"
        assert "source" not in entries["api_captured_string"]

    @pytest.mark.unit
    def test_register_scan_round_trip(self, tmp_path):
        """
        An entry with register_scan must survive save -> load
        via ReportGenerator without losing the field.
        """
        data_list = [ENTRY_REGISTER_SCAN.copy()]
        out = tmp_path / "register_scan_round_trip.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        saved = report["strings"][0]
        assert saved["source"] == "register_scan"
        assert saved["register_scan"] == "eax"
        # Required fields unchanged
        assert saved["location"] == "0xDCBA"
        assert saved["content"] == "register_scan_result"
        assert saved["encoding"] == "UTF-16LE"
        assert saved["tags"] == []

    @pytest.mark.unit
    def test_optional_fields_never_overwrite_required(self, tmp_path):
        """
        Extra fields with names differing from required fields must not
        collide with or corrupt the required contract fields.
        """
        entry = {
            "location": "0xdead",
            "encoding": "ASCII",
            "content": "non_overwrite_test",
            "tags": ["Matched_Regex"],
            "extra_meta": "some_metadata",
            "extra_origin": "custom_source",
        }
        data_list = [entry]
        out = tmp_path / "provenance_no_clobber.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        saved = report["strings"][0]
        # Required fields unchanged
        assert saved["location"] == "0xdead"
        assert saved["encoding"] == "ASCII"
        assert saved["content"] == "non_overwrite_test"
        assert saved["tags"] == ["Matched_Regex"]
        # Extra fields preserved
        assert saved["extra_meta"] == "some_metadata"
        assert saved["extra_origin"] == "custom_source"


# ---------------------------------------------------------------------------
# Top-level report envelope contract
# ---------------------------------------------------------------------------

class TestReportEnvelope:
    """Top-level report structure: timestamp, total_strings, strings."""

    @pytest.mark.unit
    def test_report_envelope_has_all_fields(self, tmp_path):
        """The report dict must contain timestamp, total_strings, strings."""
        data_list = [MINIMAL_ENTRY.copy()]
        out = tmp_path / "envelope.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list)

        with open(out) as f:
            report = json.load(f)

        assert "timestamp" in report, "report missing 'timestamp'"
        assert "total_strings" in report, "report missing 'total_strings'"
        assert "strings" in report, "report missing 'strings'"
        assert isinstance(report["timestamp"], str), "timestamp must be str"
        assert isinstance(report["total_strings"], int), "total_strings must be int"
        assert isinstance(report["strings"], list), "strings must be list"
        assert report["total_strings"] == len(report["strings"]), (
            "total_strings does not match len(strings)"
        )

    @pytest.mark.unit
    def test_empty_data_list_returns_none(self, tmp_path):
        """Empty data_list should log warning and return without writing."""
        out = tmp_path / "empty.json"
        reporter = ReportGenerator(str(out))
        result = reporter.save([])
        assert result is None
        # File should not have been created
        assert not out.exists()

    @pytest.mark.unit
    def test_execution_constraints_layer(self, tmp_path):
        """
        execution_constraints injected by save() with metadata must not break
        the top-level envelope contract (timestamp, total_strings, strings).
        """
        data_list = [MINIMAL_ENTRY.copy()]
        meta = {"timeout": 120, "arch": "x86"}
        out = tmp_path / "envelope_with_constraints.json"
        reporter = ReportGenerator(str(out))
        reporter.save(data_list, metadata=meta)

        with open(out) as f:
            report = json.load(f)

        # Envelope contract still satisfied
        assert "timestamp" in report
        assert "total_strings" in report
        assert "strings" in report
        assert report["total_strings"] == 1
        assert len(report["strings"]) == 1

        # execution_constraints present and correct
        assert "execution_constraints" in report
        assert report["execution_constraints"] == meta
