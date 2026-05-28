"""
Smoke test to verify that the test harness and project imports work correctly.
"""

import pytest


def test_pytest_runs() -> None:
    """Trivial assertion to confirm pytest discovers and executes tests."""
    assert True


def test_project_core_importable() -> None:
    """Verify that the core module can be imported without errors."""
    try:
        import core.emulator  # noqa: F401
        import core.extractor  # noqa: F401
    except ImportError as exc:
        pytest.fail(f"core module failed to import: {exc}")


@pytest.mark.unit
def test_marked_as_unit() -> None:
    """A test explicitly tagged with the 'unit' marker."""
    assert True


@pytest.mark.speakeasy
def test_marked_as_speakeasy_skipped_by_default() -> None:
    """
    A test tagged with 'speakeasy'.  This marker can be used to skip
    Speakeasy-dependent tests during quick CI runs.
    """
    assert True
