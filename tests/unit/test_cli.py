# pyright: reportUnknownVariableType=false, reportInvalidCast=false
"""
Contract tests for CLI argument parsing in ``main.parse_args``.

Verifies that every declared flag is accepted, defaults are correct, and
constraints (type, choices, required) are enforced by argparse itself.
"""

from collections.abc import Callable, Sequence
from typing import Protocol, cast

from main import parse_args


class ParsedArgs(Protocol):
    file: str
    arch: str
    timeout: int
    max_instructions: int | None
    output: str
    debug: bool


def parse_cli(args: Sequence[str]) -> ParsedArgs:
    """
    Purpose:
    Parse CLI arguments with a typed return shape for assertions.

    How it works:
    Calls main.parse_args() and casts the argparse namespace to the fields
    covered by these CLI contract tests.

    Parameters:
    - args: command-line arguments to parse.

    Returns:
    Parsed arguments with the CLI fields under test.
    """
    return cast(ParsedArgs, parse_args(list(args)))


def assert_raises_system_exit(action: Callable[[], object]) -> None:
    """
    Purpose:
    Assert argparse rejects invalid CLI arguments.

    How it works:
    Calls the provided action and passes only when it raises SystemExit.

    Parameters:
    - action: zero-argument callable expected to raise SystemExit.

    Returns:
    void
    """
    try:
        _ = action()
    except SystemExit:
        return
    raise AssertionError("Expected SystemExit")


# ── Happy path: each flag is accepted ────────────────────────────────────

class TestHappyPath:
    """Each flag parses correctly when given a valid value."""

    def test_all_flags(self) -> None:
        """All flags at once — no conflict."""
        args = parse_cli([
            "-f", "sample.exe",
            "-a", "x64",
            "-t", "120",
            "--max-instructions", "1000000",
            "-o", "out.json",
            "-d",
        ])
        assert args.file == "sample.exe"
        assert args.arch == "x64"
        assert args.timeout == 120
        assert args.max_instructions == 1_000_000
        assert args.output == "out.json"
        assert args.debug is True

    def test_default_timeout_is_60(self) -> None:
        """-t defaults to 60 when not provided."""
        args = parse_cli(["-f", "x.exe"])
        assert args.timeout == 60

    def test_max_instructions_is_optional(self) -> None:
        """--max-instructions is None when not provided."""
        args = parse_cli(["-f", "x.exe"])
        assert args.max_instructions is None

    def test_max_instructions_int(self) -> None:
        """Accepts a reasonable instruction count."""
        args = parse_cli(["-f", "x.exe", "--max-instructions", "5000000"])
        assert args.max_instructions == 5_000_000

    def test_arch_defaults_x86(self) -> None:
        """-a defaults to 'x86'."""
        args = parse_cli(["-f", "x.exe"])
        assert args.arch == "x86"

    def test_output_defaults_report_json(self) -> None:
        """-o defaults to 'report.json'."""
        args = parse_cli(["-f", "x.exe"])
        assert args.output == "report.json"

    def test_debug_false_by_default(self) -> None:
        """-d is False when not passed."""
        args = parse_cli(["-f", "x.exe"])
        assert args.debug is False


# ── Sad path: argparse rejects invalid input ────────────────────────────

class TestSadPath:
    """Invalid flag values raise SystemExit via argparse."""

    def test_non_int_max_instructions(self) -> None:
        """A non-integer value for --max-instructions is rejected."""
        assert_raises_system_exit(
            lambda: parse_args(["-f", "x.exe", "--max-instructions", "not-a-number"])
        )

    def test_invalid_arch(self) -> None:
        """A value outside the choices set is rejected."""
        assert_raises_system_exit(lambda: parse_args(["-f", "x.exe", "-a", "arm"]))

    def test_negative_timeout(self) -> None:
        """Negative timeout is accepted by argparse (int), but handled later."""
        args = parse_cli(["-f", "x.exe", "-t", "-5"])
        assert args.timeout == -5

    def test_negative_max_instructions(self) -> None:
        """Negative int is accepted by argparse (no range constraint)."""
        args = parse_cli(["-f", "x.exe", "--max-instructions", "-1"])
        assert args.max_instructions == -1


# ── Required flags ──────────────────────────────────────────────────────

class TestRequired:
    """The only truly required flag is -f/--file."""

    def test_file_is_required(self) -> None:
        """Omitting -f raises SystemExit."""
        assert_raises_system_exit(lambda: parse_args(["-t", "30"]))

    def test_max_instructions_not_required(self) -> None:
        """--max-instructions is optional — no error when absent."""
        args = parse_cli(["-f", "x.exe"])
        assert args.max_instructions is None
