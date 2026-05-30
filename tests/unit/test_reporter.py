"""
Purpose:
Unit tests for ReportGenerator — verifies JSON output structure, empty-data
handling, and the presence of timestamp/total_strings/strings fields without
writing to the real filesystem (uses tmp_path fixture).

How it works:
Each test creates a ReportGenerator pointed at a temporary path inside
tmp_path, calls save() with known data, then reads back and validates the JSON.
"""

import json
import pytest
from utils.reporter import ReportGenerator


class TestReportGenerator:
    """ReportGenerator.save() behaviour."""

    # ------------------------------------------------------------------ 
    # Happy path
    # ------------------------------------------------------------------ 

    def test_save_creates_json_with_expected_keys(self, tmp_path) -> None:
        """
        save() with non-empty data produces a JSON file containing
        timestamp, total_strings, and strings keys.
        """
        output = tmp_path / "output.json"
        generator = ReportGenerator(str(output))
        data = [{"content": "hello"}]
        generator.save(data)

        assert output.exists()
        with open(output, "r") as f:
            report = json.load(f)

        assert "timestamp" in report
        assert "total_strings" in report
        assert "strings" in report

    def test_save_total_strings_matches_input_length(self, tmp_path) -> None:
        """total_strings field accurately reflects len(data_list)."""
        output = tmp_path / "output.json"
        generator = ReportGenerator(str(output))
        data = [
            {"content": "first"},
            {"content": "second"},
            {"content": "third"},
        ]
        generator.save(data)

        with open(output, "r") as f:
            report = json.load(f)

        assert report["total_strings"] == 3
        assert report["strings"] == data

    def test_save_strings_field_contains_items(self, tmp_path) -> None:
        """The strings array preserves the exact items passed in."""
        output = tmp_path / "output.json"
        generator = ReportGenerator(str(output))
        data = [
            {"location": "0x1000", "encoding": "ASCII", "content": "test", "tags": []},
        ]
        generator.save(data)

        with open(output, "r") as f:
            report = json.load(f)

        assert len(report["strings"]) == 1
        assert report["strings"][0]["content"] == "test"
        assert report["strings"][0]["encoding"] == "ASCII"

    def test_save_timestamp_is_isoformat(self, tmp_path) -> None:
        """The timestamp field is an ISO-8601 formatted string."""
        output = tmp_path / "output.json"
        generator = ReportGenerator(str(output))
        generator.save([{"content": "ts_check"}])

        with open(output, "r") as f:
            report = json.load(f)

        # ISO-8601 contains at least a 'T' separator
        assert "T" in report["timestamp"]
        # Can be parsed by datetime
        from datetime import datetime
        parsed = datetime.fromisoformat(report["timestamp"])
        assert parsed is not None

    # ------------------------------------------------------------------ 
    # Empty-data edge cases
    # ------------------------------------------------------------------ 

    def test_save_with_none_data_does_not_create_file(self, tmp_path) -> None:
        """Passing None (a falsy list) does not create any output file."""
        output = tmp_path / "empty_output.json"
        generator = ReportGenerator(str(output))
        generator.save(None)

        assert not output.exists()

    def test_save_with_empty_list_does_not_create_file(self, tmp_path) -> None:
        """Passing an empty list does not create any output file."""
        output = tmp_path / "empty_output.json"
        generator = ReportGenerator(str(output))
        generator.save([])

        assert not output.exists()

    # ------------------------------------------------------------------
    # Metadata / execution_constraints
    # ------------------------------------------------------------------

    def test_save_without_metadata_omits_execution_constraints(self, tmp_path) -> None:
        """save() called without metadata does not inject execution_constraints."""
        output = tmp_path / "no_metadata.json"
        generator = ReportGenerator(str(output))
        generator.save([{"content": "test"}])

        with open(output, "r") as f:
            report = json.load(f)

        assert "execution_constraints" not in report

    def test_save_with_metadata_injects_execution_constraints(self, tmp_path) -> None:
        """save() called with metadata injects it under execution_constraints."""
        output = tmp_path / "with_metadata.json"
        generator = ReportGenerator(str(output))
        meta = {"timeout": 60, "arch": "x86"}
        generator.save([{"content": "test"}], metadata=meta)

        with open(output, "r") as f:
            report = json.load(f)

        assert "execution_constraints" in report
        assert report["execution_constraints"] == meta
        # Legacy keys unchanged
        assert report["total_strings"] == 1
        assert len(report["strings"]) == 1

    def test_save_with_metadata_none_omits_execution_constraints(self, tmp_path) -> None:
        """Passing metadata=None explicitly behaves the same as omitting it."""
        output = tmp_path / "explicit_none.json"
        generator = ReportGenerator(str(output))
        generator.save([{"content": "test"}], metadata=None)

        with open(output, "r") as f:
            report = json.load(f)

        assert "execution_constraints" not in report

    # ------------------------------------------------------------------
    # Execution-status metadata integration (Task 9)
    # ------------------------------------------------------------------

    def test_save_with_stop_reason_metadata(self, tmp_path) -> None:
        """
        save() with stop_reason metadata injects it under
        execution_constraints.  This replicates what main.py does when
        emu.execution_status is set.
        """
        output = tmp_path / "stop_reason.json"
        generator = ReportGenerator(str(output))
        meta = {"stop_reason": "completed"}
        generator.save([{"content": "data"}], metadata=meta)

        with open(output, "r") as f:
            report = json.load(f)

        assert report["execution_constraints"] == {"stop_reason": "completed"}
        assert report["total_strings"] == 1

    def test_save_with_constrained_stop_reason(self, tmp_path) -> None:
        """
        A constrained emulation (e.g. timeout) produces a
        stop_reason that is not 'completed'.
        """
        output = tmp_path / "constrained.json"
        generator = ReportGenerator(str(output))
        meta = {"stop_reason": "timeout"}
        generator.save([{"content": "partial"}], metadata=meta)

        with open(output, "r") as f:
            report = json.load(f)

        assert report["execution_constraints"]["stop_reason"] == "timeout"

    def test_main_metadata_structure(self, tmp_path) -> None:
        """
        The metadata dict structure that main.py builds
        (``{"stop_reason": emu.execution_status}``) is compatible
        with ReportGenerator.save().
        """
        for status in ("completed", "timeout", "unsupported_api", "error"):
            output = tmp_path / f"status_{status}.json"
            generator = ReportGenerator(str(output))
            generator.save([{"content": "x"}], metadata={"stop_reason": status})

            with open(output, "r") as f:
                report = json.load(f)

            assert report["execution_constraints"] == {"stop_reason": status}

    # ------------------------------------------------------------------
    # New capture source metadata (Task 5)
    # ------------------------------------------------------------------

    def test_save_with_overwrite_history_metadata(self, tmp_path) -> None:
        """
        save() with overwrite_history in metadata injects it under
        execution_constraints without breaking the envelope contract.
        """
        output = tmp_path / "overwrite_history.json"
        generator = ReportGenerator(str(output))
        meta = {"overwrite_history": True, "stop_reason": "completed"}
        generator.save([{"content": "test"}], metadata=meta)

        with open(output, "r") as f:
            report = json.load(f)

        assert report["execution_constraints"]["overwrite_history"] is True
        assert report["execution_constraints"]["stop_reason"] == "completed"
        # Envelope unchanged
        assert "timestamp" in report
        assert report["total_strings"] == 1
        assert len(report["strings"]) == 1

    def test_save_with_register_scan_metadata(self, tmp_path) -> None:
        """
        save() with register_scan in metadata injects it under
        execution_constraints without breaking the envelope contract.
        """
        output = tmp_path / "register_scan_meta.json"
        generator = ReportGenerator(str(output))
        meta = {"register_scan": "all", "stop_reason": "completed"}
        generator.save([{"content": "data"}], metadata=meta)

        with open(output, "r") as f:
            report = json.load(f)

        assert report["execution_constraints"]["register_scan"] == "all"
        # Envelope unchanged
        assert report["total_strings"] == 1
        assert len(report["strings"]) == 1

    def test_save_with_both_new_metadata_fields(self, tmp_path) -> None:
        """
        save() with both overwrite_history and register_scan in metadata
        preserves both fields independently.
        """
        output = tmp_path / "both_new_metadata.json"
        generator = ReportGenerator(str(output))
        meta = {
            "overwrite_history": False,
            "register_scan": "ebx",
            "stop_reason": "completed",
        }
        generator.save([{"content": "both"}], metadata=meta)

        with open(output, "r") as f:
            report = json.load(f)

        assert report["execution_constraints"]["overwrite_history"] is False
        assert report["execution_constraints"]["register_scan"] == "ebx"
        assert report["execution_constraints"]["stop_reason"] == "completed"
        assert report["total_strings"] == 1
