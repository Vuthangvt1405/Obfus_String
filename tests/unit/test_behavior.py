# -*- coding: utf-8 -*-
"""Unit tests for best-effort behavior tracing."""

from core.behavior import BehaviorTracer


def test_behavior_tracer_classifies_network_download() -> None:
    tracer = BehaviorTracer()
    tracer.record_api_call(
        "URLDownloadToFileA",
        [0, "http://example.com/a.exe", "C:\\Users\\Public\\a.exe"],
    )

    report = tracer.build_report(strings=[], stop_reason="completed")

    assert report["events"][0]["category"] == "network.download"
    assert "http://example.com/a.exe" in report["iocs"]["urls"]
    assert "Command and Control" in report["tactics"]
    assert report["risk_score"] > 0


def test_behavior_tracer_detects_registry_persistence() -> None:
    tracer = BehaviorTracer()
    tracer.record_api_call(
        "RegSetValueExA",
        [0, "Run", 0, 1, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 32],
    )

    report = tracer.build_report(strings=[], stop_reason="timeout")

    assert report["events"][0]["category"] == "persistence.registry_run"
    assert "Persistence" in report["tactics"]
    assert "timeout" in report["execution_note"]


def test_behavior_tracer_ingests_speakeasy_report() -> None:
    tracer = BehaviorTracer()
    tracer.ingest_speakeasy_report({
        "entry_points": [{
            "apis": [{"api_name": "CreateProcessA", "args": ["cmd.exe /c whoami"]}]
        }]
    })

    report = tracer.build_report(strings=[])

    assert report["events"][0]["category"] == "process.spawn"
    assert "Execution" in report["tactics"]
