"""
Purpose:
Integration tests for the emulation pipeline that require PE fixtures
and the Speakeasy library. These tests skip cleanly when dependencies
are unavailable.

How it works:
Each test is decorated with @pytest.mark.requires_speakeasy and/or
@pytest.mark.requires_fixture so conftest.py auto-skips them when
the dependency is missing.
"""

import pytest


@pytest.mark.requires_speakeasy
@pytest.mark.requires_fixture("xor_decrypt_sample.exe")
def test_xor_decrypt_produces_expected_domain():
    """
    Purpose:
    Verify that emulating the XOR-decrypt fixture yields 'thecyberyeti.com'.

    How it works:
    Loads the fixture PE via the emulator, runs it under Speakeasy, and
    asserts the extracted strings contain the expected domain.

    Parameters: None (fixture path resolved by marker).
    Returns: None (assertion-based).
    """
    from core.emulator import SpeakeasyEmulator

    fixture = "tests/fixtures/xor_decrypt_sample.exe"
    emu = SpeakeasyEmulator(fixture)
    results = emu.run()
    domains = [s for s in results if "thecyberyeti.com" in s]
    assert len(domains) > 0, "Expected 'thecyberyeti.com' in emulated output"


@pytest.mark.requires_speakeasy
def test_speakeasy_import_works(speakeasy_available):
    """
    Purpose:
    Smoke test that Speakeasy can be imported.

    How it works:
    Uses the session fixture; if we reach this body, Speakeasy is present.

    Parameters:
    - speakeasy_available: session fixture from conftest.

    Returns: None.
    """
    assert speakeasy_available is True


@pytest.mark.requires_fixture("nonexistent_sample.exe")
def test_missing_fixture_is_skipped():
    """
    Purpose:
    Canary test — always skipped because the fixture doesn't exist.
    Validates that the skip machinery works correctly.

    How it works:
    The marker references a file that will never be present.
    If this test body executes, the skip logic is broken.
    """
    pytest.fail("This should have been skipped — fixture does not exist")
