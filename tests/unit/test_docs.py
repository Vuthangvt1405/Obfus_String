"""Documentation guardrails for tight-loop behavior claims."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


# Purpose: Verify top-level README language avoids unsupported tight-loop claims.
# How it works: Reads README.md and checks for forbidden overpromise phrases.
# Parameters: None.
# Returns: None.
def test_readme_avoids_tight_loop_overpromises() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    assert "static decryption" not in readme_text
    assert "bypass all loops" not in readme_text


# Purpose: Verify README language does not promise perfect extraction.
# How it works: Reads README.md and rejects phrases that imply complete recovery.
# Parameters: None.
# Returns: None.
def test_readme_rejects_perfect_extraction_claims() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    forbidden_claims = (
        "perfect extraction",
        "perfect decoding",
        "extracts every string",
        "recovers every string",
        "giải mã tĩnh hoàn hảo",
    )

    for forbidden_claim in forbidden_claims:
        assert forbidden_claim not in readme_text


# Purpose: Verify README language does not guarantee decoder recovery or loop bypass.
# How it works: Reads README.md and rejects unsupported decoder and loop claims.
# Parameters: None.
# Returns: None.
def test_readme_rejects_guaranteed_decoder_recovery_and_loop_bypass() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    forbidden_claims = (
        "guaranteed decoder recovery",
        "guarantees decoder recovery",
        "guaranteed recovery",
        "bypass loop",
        "bypass loops",
        "loop bypass",
        "đảm bảo giải",
    )

    for forbidden_claim in forbidden_claims:
        assert forbidden_claim not in readme_text


# Purpose: Verify README documents default static scan coverage.
# How it works: Reads README.md and checks required static scanner terms.
# Parameters: None.
# Returns: None.
def test_readme_documents_default_static_scan() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    assert "core.static_scanner" in readme_text
    assert "default raw-file scan" in readme_text
    assert "ascii/utf-8-compatible" in readme_text
    assert "utf-16le" in readme_text
    assert "static_scan" in readme_text


# Purpose: Verify README documents pre-overwrite stack and heap capture.
# How it works: Reads README.md and checks overwrite-history and dirty-scan terms.
# Parameters: None.
# Returns: None.
def test_readme_documents_pre_overwrite_stack_heap_capture() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    assert "overwrite_history" in readme_text
    assert "pre-overwrite" in readme_text
    assert "dirty-region scan" in readme_text
    assert "stack" in readme_text
    assert "heap" in readme_text


# Purpose: Verify README documents register-held plaintext capture limits.
# How it works: Reads README.md and checks register scan behavior and caveats.
# Parameters: None.
# Returns: None.
def test_readme_documents_bounded_register_tracking() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    assert "hooks/register_hooks.py" in readme_text
    assert "register_scan" in readme_text
    assert "bounded" in readme_text
    assert "function thật sự chạy" in readme_text
    assert "plaintext" in readme_text


# Purpose: Verify README documents source provenance and bounded limitations.
# How it works: Reads README.md and checks full source labels plus caveat terms.
# Parameters: None.
# Returns: None.
def test_readme_documents_source_flow_and_limitations() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8").lower()

    required_sources = (
        "static_scan",
        "deferred_scan",
        "overwrite_history",
        "mem_write",
        "register_scan",
        "api_hook",
    )

    for source in required_sources:
        assert source in readme_text

    assert "best-effort" in readme_text
    assert "bounded" in readme_text
    assert "behavior path" in readme_text
    assert "not static" in readme_text
    assert "không bảo đảm khôi phục decoder" in readme_text


# Purpose: Verify fixture documentation keeps tests safe and reproducible.
# How it works: Reads tests/fixtures/README.md and checks required policy terms.
# Parameters: None.
# Returns: None.
def test_fixture_policy_requires_offline_benign_deterministic_inputs() -> None:
    fixture_policy = (
        REPO_ROOT / "tests" / "fixtures" / "README.md"
    ).read_text(encoding="utf-8").lower()

    assert "offline" in fixture_policy
    assert "benign" in fixture_policy
    assert "deterministic" in fixture_policy
