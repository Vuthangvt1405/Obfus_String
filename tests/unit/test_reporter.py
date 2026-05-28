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
