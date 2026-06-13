#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compare a malstring_emu report against an optional lab expected-string file.

This is a lab/QA helper only. Real-world samples normally do not have an
expected oracle; use confidence/source/api fields for triage there.
"""

import argparse
import ast
import json
import re
from pathlib import Path


def _decode_report_escapes(s: str) -> str:
    """Normalize report display escapes such as literal \\n / \\r."""
    return s.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t")


def load_expected(path: str) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    values: list[str] = []
    for match in re.finditer(r'"((?:\\.|[^"\\])*)"', text):
        values.append(ast.literal_eval('"' + match.group(1) + '"'))
    return values


def _decode_reverse_shift(s: str) -> str | None:
    """Decode sample reverse+shift literals used by malware5 docs/tests."""
    if len(s) < 4:
        return None
    try:
        decoded = "".join(chr((ord(c) - 1) & 0xFF) for c in s)[::-1].strip("\x00")
    except Exception:
        return None
    if not decoded or sum(ch.isprintable() for ch in decoded) < max(4, len(decoded) * 0.8):
        return None
    return decoded


def _found_variants(content: str) -> set[str]:
    """Return comparison variants for one report string.

    Large runtime blobs and lab prefixes should still satisfy expected-string
    oracles when they contain the expected value.  Variants keep the validator
    strict by default while supporting substring checks in main().
    """
    normalized = _decode_report_escapes(content)
    variants = {normalized}
    for line in normalized.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        variants.add(stripped)
        for prefix in ("SIMULATED: ", "[LAB] "):
            if stripped.startswith(prefix):
                variants.add(stripped[len(prefix):])
    return variants


def load_found(path: str, api_only: bool = False, min_confidence: int | None = None) -> set[str]:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    found: set[str] = set()
    for item in report.get("strings", []):
        if api_only and item.get("source") != "api_hook":
            continue
        if min_confidence is not None and item.get("confidence", 50) < min_confidence:
            continue
        content = item.get("content")
        if isinstance(content, str):
            found.update(_found_variants(content))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate report.json against a lab expected string list.")
    parser.add_argument("-r", "--report", required=True, help="Path to report.json")
    parser.add_argument("-e", "--expected", required=True, help="Path to expected strings text file")
    parser.add_argument("--api-only", action="store_true", help="Only count strings captured by api_hook")
    parser.add_argument("--min-confidence", type=int, help="Only count strings with confidence >= this value")
    args = parser.parse_args()

    expected = load_expected(args.expected)
    found = load_found(args.report, api_only=args.api_only, min_confidence=args.min_confidence)
    found_blob = "\n".join(found)
    missing = []
    for s in expected:
        candidates = [s]
        decoded = _decode_reverse_shift(s)
        if decoded:
            candidates.append(decoded)
        if not any(candidate in found or candidate in found_blob for candidate in candidates):
            missing.append(s)

    print(f"expected={len(expected)} found={len(found)} missing={len(missing)}")
    if expected:
        recovered = len(expected) - len(missing)
        print(f"recovery={recovered}/{len(expected)} ({recovered / len(expected):.1%})")
    for s in missing:
        print(f"MISSING: {s!r}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
