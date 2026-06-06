import os
import pytest
from unittest.mock import MagicMock

from core.emulator import MalwareEmulator

def test_propagates_lab_malware_allowed(monkeypatch):
    """
    Purpose: 
    Test that LAB_MALWARE_ALLOWED is correctly forwarded into the Speakeasy configuration.
    
    How it works:
    Monkeypatches os.environ to contain LAB_MALWARE_ALLOWED="1".
    Monkeypatches speakeasy.Speakeasy to intercept the config dictionary passed to it.
    Validates that the config['env'] key contains the propagated variable.
    
    Parameters:
    - monkeypatch: pytest fixture for environment and mock application.
    
    Returns:
    None.
    """
    monkeypatch.setenv("LAB_MALWARE_ALLOWED", "1")
    
    captured_config = {}
    def fake_speakeasy(config, *args, **kwargs):
        captured_config.update(config)
        return MagicMock()
        
    monkeypatch.setattr("speakeasy.Speakeasy", fake_speakeasy)
    
    _ = MalwareEmulator()
    
    assert "env" in captured_config
    assert captured_config["env"].get("LAB_MALWARE_ALLOWED") == "1"

def test_missing_env_does_not_add_variable(monkeypatch):
    """
    Purpose: 
    Test that if LAB_MALWARE_ALLOWED is not in the host environment, it's not placed in the config.
    
    How it works:
    Deletes the LAB_MALWARE_ALLOWED key from os.environ.
    Instantiates MalwareEmulator and verifies it is missing from the Speakeasy config dictionary.
    
    Parameters:
    - monkeypatch: pytest fixture.
    
    Returns:
    None.
    """
    monkeypatch.delenv("LAB_MALWARE_ALLOWED", raising=False)
    
    captured_config = {}
    def fake_speakeasy(config, *args, **kwargs):
        captured_config.update(config)
        return MagicMock()
        
    monkeypatch.setattr("speakeasy.Speakeasy", fake_speakeasy)
    
    _ = MalwareEmulator()
    
    assert "LAB_MALWARE_ALLOWED" not in captured_config.get("env", {})
