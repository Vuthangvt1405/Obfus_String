import pytest
from unittest.mock import MagicMock

from core.emulator import MalwareEmulator


def test_host_lab_env_is_not_forwarded(monkeypatch):
    """Host LAB_MALWARE_ALLOWED is no longer required or forwarded."""
    monkeypatch.setenv("LAB_MALWARE_ALLOWED", "1")

    captured_config = {}
    def fake_speakeasy(config, *args, **kwargs):
        captured_config.update(config)
        return MagicMock()

    monkeypatch.setattr("speakeasy.Speakeasy", fake_speakeasy)

    _ = MalwareEmulator()

    assert "LAB_MALWARE_ALLOWED" not in captured_config.get("env", {})


def test_env_key_still_exists_for_speakeasy_config(monkeypatch):
    """The config keeps an env dict but does not inject lab-gate variables."""
    monkeypatch.delenv("LAB_MALWARE_ALLOWED", raising=False)

    captured_config = {}
    def fake_speakeasy(config, *args, **kwargs):
        captured_config.update(config)
        return MagicMock()

    monkeypatch.setattr("speakeasy.Speakeasy", fake_speakeasy)

    _ = MalwareEmulator()

    assert "env" in captured_config
    assert "LAB_MALWARE_ALLOWED" not in captured_config.get("env", {})
