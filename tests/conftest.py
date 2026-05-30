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
    config.addinivalue_line(
        "markers",
        "tight_loop: tests for tight-loop and constrained emulation scenarios",
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


# ---------------------------------------------------------------------------
# Tight-loop simulation helpers (no real PE files or Speakeasy required)
# ---------------------------------------------------------------------------


class TightLoopEmulator:
    """
    Purpose:
    Simulates a constrained emulation run to test tight-loop behavior
    without requiring real PE files or Speakeasy.

    How it works:
    Exposes a pluggable step function controlled by the test. Tracks
    instruction count and reports when a configurable limit is reached.

    Parameters:
    - max_instructions: instruction limit before emulation stops (default 1000).
    - step: callable invoked per instruction step. Default is a no-op.

    Returns:
    A TightLoopEmulator instance with .instruction_count and .stopped.
    """

    def __init__(self, max_instructions=1000, step=None):
        self.max_instructions = max_instructions
        self.instruction_count = 0
        self.stopped = False
        self._step = step or (lambda: None)

    def run(self):
        """Execute up to max_instructions steps."""
        for _ in range(self.max_instructions):
            self._step()
            self.instruction_count += 1
        self.stopped = True
        return self

    @property
    def did_hit_limit(self):
        """True when the instruction limit was reached."""
        return self.instruction_count >= self.max_instructions


class FakeMemoryRegion:
    """
    Purpose:
    Simulates a memory region for testing constrained emulation
    scenarios without real PE files.

    How it works:
    Stores raw bytes and an optional read-failure flag so tests can
    exercise error-handling paths in the emulator.

    Parameters:
    - data: bytes to expose as the region content.
    - read_ok: if False, mem_read() raises OSError (default True).

    Returns:
    A FakeMemoryRegion instance.
    """

    def __init__(self, data=b"", read_ok=True):
        self._data = data
        self.read_ok = read_ok

    def mem_read(self, offset, size):
        if not self.read_ok:
            raise OSError(f"cannot read memory at offset {offset}")
        return self._data[offset : offset + size]


# Well-known timing constants for tight-loop test scenarios
TIMEOUT_SHORT = 0.1     # seconds
TIMEOUT_MEDIUM = 1.0    # seconds
INSTRUCTION_LIMIT = 1000

# ---------------------------------------------------------------------------
# Deterministic byte buffers for static scan tests (no PE files needed)
# ---------------------------------------------------------------------------

DETERMINISTIC_SEED = b"thecyberyeti.com"


def fake_static_buffer(
    seed_string: bytes | None = None,
    noise_before_len: int = 32,
    noise_after_len: int = 32,
) -> bytes:
    """
    Purpose:
    Create a deterministic byte buffer with an embedded printable string
    surrounded by non-printable noise, for static scan testing without
    requiring real PE files or Speakeasy.

    How it works:
    Wraps the seed string with non-printable bytes (0x80-0x9f before,
    0xc0-0xdf after) so scan_buffer must find the string amid cipher noise.
    Both noise sections are capped at 32 bytes so the output stays bounded.

    Parameters:
    - seed_string: the printable string to embed (default 'thecyberyeti.com').
    - noise_before_len: number of noise bytes before the string, max 32.
    - noise_after_len: number of noise bytes after the string, max 32.

    Returns:
    bytes: noise + seed + noise.
    """
    if seed_string is None:
        seed_string = DETERMINISTIC_SEED
    before = bytes(range(0x80, 0x80 + min(noise_before_len, 32)))
    after = bytes(range(0xC0, 0xC0 + min(noise_after_len, 32)))
    return before + seed_string + after


# ---------------------------------------------------------------------------
# Deterministic overwrite region descriptors for WriteTracker testing
# ---------------------------------------------------------------------------


def fake_overwrite_regions() -> list[tuple[int, int]]:
    """
    Purpose:
    Return a list of deterministic (start, end) dirty-memory tuples
    representing coalesced writes from a simulated decryptor loop.

    How it works:
    Returns four non-overlapping regions at known offsets that test code
    can use to exercise WriteTracker coalescing, hot-region detection,
    and edge cases (short writes below min_length).

    Returns:
    list of (start_address, end_address) tuples.
    """
    return [
        (0x1000, 0x100A),   # 10-byte XOR output region
        (0x2000, 0x2004),   # 4-byte isolated write
        (0x3000, 0x3010),   # 16-byte wide write
        (0x4000, 0x4002),   # 2-byte write (below min_length for strings)
    ]


def fake_overwrite_buffer(region_spec: tuple[int, int]) -> bytes:
    """
    Purpose:
    Fill a memory region with a recognisable byte pattern for overwrite
    tracking tests.

    Parameters:
    - region_spec: (start, end) from fake_overwrite_regions().

    Returns:
    bytes of length (end - start) filled with repeating 0x41 ('A').
    """
    start, end = region_spec
    return b"\x41" * (end - start)


# ---------------------------------------------------------------------------
# Fake emulator engine for API hook registration tests
# ---------------------------------------------------------------------------


class FakeRegisterEngine:
    """
    Purpose:
    Simulate a Speakeasy engine to test API hook registration without
    requiring Speakeasy or real emulation.

    How it works:
    Records every add_api_hook and add_mem_write_hook call into lists
    for later inspection. Optionally fails on a configured set of
    (module, api_name) pairs so error-handling paths can be exercised.
    Provides mem_read() and read_mem_string() backed by a lightweight
    in-memory dict.

    Parameters:
    - fail_on: optional set of (module, api_name) tuples that should raise.

    Returns:
    A FakeRegisterEngine instance.
    """

    def __init__(self, fail_on: set[tuple[str, str]] | None = None):
        self.hooks: list[tuple[str, str]] = []
        self.mem_write_hooks: list[object] = []
        self._fail_on = fail_on or set()
        self._memory: dict[int, bytes] = {}

    def add_api_hook(
        self, callback: object, module: str, api_name: str
    ) -> tuple[str, str]:
        """
        Register an API hook. Raises RuntimeError for fail_on entries.

        Parameters:
        - callback: hook function (unused, recorded for inspection).
        - module: DLL module name (e.g. 'kernel32').
        - api_name: exported function name (e.g. 'CreateFileA').

        Returns:
        (module, api_name) tuple as a reference key.
        """
        key = (module, api_name)
        if key in self._fail_on:
            raise RuntimeError(f"Cannot hook {module}!{api_name}")
        self.hooks.append(key)
        return key

    def add_mem_write_hook(self, callback: object) -> None:
        """Register a memory-write hook callback."""
        self.mem_write_hooks.append(callback)

    def mem_read(self, address: int, size: int) -> bytes:
        """
        Read bytes from internal memory dict. Falls back to null bytes.

        Parameters:
        - address: virtual address to read from.
        - size: number of bytes requested.

        Returns:
        bytes of length size (padded with zeros if address is unmapped).
        """
        data = self._memory.get(address)
        if data is None:
            return b"\x00" * size
        return data[:size]

    def read_mem_string(self, ptr: int, width: int = 1) -> str:
        """
        Read a null-terminated string from internal memory.

        Parameters:
        - ptr: virtual address to read from.
        - width: 1 for ANSI, 2 for UTF-16LE.

        Returns:
        Decoded string (empty if no null terminator found).
        """
        data = self._memory.get(ptr, b"\x00")
        if width == 1:
            term = data.find(b"\x00")
            return data[:term].decode("ascii", errors="replace") if term >= 0 else ""
        else:
            term = data.find(b"\x00\x00")
            chunk = data[:term] if term >= 0 else data
            # Ensure even length for UTF-16LE decoding
            if len(chunk) % 2 != 0:
                chunk = chunk[:-1]
            return chunk.decode("utf-16-le", errors="replace")
