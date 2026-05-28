"""
Purpose:
Shared pytest configuration for malstring_emu tests.

How it works:
Provides fixtures and skip-logic so integration tests degrade gracefully
when PE fixture files or the Speakeasy library are unavailable.

- `speakeasy_available`: session-scoped flag (True/False).
- `requires_speakeasy`: auto-use marker that skips tests needing Speakeasy.
- `fixture_path`: helper that resolves a filename inside tests/fixtures/
  and skips the test if the file is missing.
"""

import pathlib
import pytest

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Speakeasy availability probe (runs once per session)
# ---------------------------------------------------------------------------

try:
    import speakeasy  # noqa: F401
    _SPEAKEASY_AVAILABLE = True
except ImportError:
    _SPEAKEASY_AVAILABLE = False


@pytest.fixture(scope="session")
def speakeasy_available():
    """Return whether the speakeasy package can be imported."""
    return _SPEAKEASY_AVAILABLE


# ---------------------------------------------------------------------------
# Auto-skip marker: ``@pytest.mark.requires_speakeasy``
# ---------------------------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_speakeasy: skip test when speakeasy is not installed",
    )
    config.addinivalue_line(
        "markers",
        "requires_fixture(name): skip test when the named fixture file is missing",
    )
    config.addinivalue_line(
        "markers",
        "mem_write_timing: behavior probe tests for mem_read timing inside write hooks",
    )


def pytest_collection_modifyitems(config, items):
    """Auto-skip tests decorated with requires_speakeasy or requires_fixture."""
    for item in items:
        # --- speakeasy marker ---
        if item.get_closest_marker("requires_speakeasy") and not _SPEAKEASY_AVAILABLE:
            item.add_marker(
                pytest.mark.skip(reason="speakeasy is not installed")
            )

        # --- fixture-file marker ---
        fixture_marker = item.get_closest_marker("requires_fixture")
        if fixture_marker:
            name = fixture_marker.args[0] if fixture_marker.args else None
            if name and not (FIXTURES_DIR / name).exists():
                item.add_marker(
                    pytest.mark.skip(
                        reason=f"fixture file missing: tests/fixtures/{name}"
                    )
                )


# ---------------------------------------------------------------------------
# Convenience fixture: resolve a fixture path or skip
# ---------------------------------------------------------------------------

@pytest.fixture()
def fixture_path(request):
    """
    Purpose:
    Return the absolute Path to a file inside tests/fixtures/.
    Skip the test if the file does not exist.

    How it works:
    Accepts 'name' via pytest.mark.parametrize or indirect param.

    Parameters:
    - name (via request.param): filename relative to tests/fixtures/.

    Returns:
    pathlib.Path to the fixture file.
    """
    name = request.param
    path = FIXTURES_DIR / name
    if not path.exists():
        pytest.skip(f"fixture file missing: tests/fixtures/{name}")
    return path
