# Test Fixtures Policy

## Purpose

This directory holds **benign, deterministic PE fixtures** used by integration tests to verify the malstring_emu emulation pipeline end-to-end.

## Rules

1. **Offline only** — Fixtures must never be fetched from the internet at test time. All samples are committed to the repo or generated locally by a build script.
2. **Benign** — No real malware. Fixtures are minimal PE files compiled from safe, self-contained C source (e.g., an XOR-decrypt loop that reveals a hardcoded domain string). They contain no destructive, replicating, or exfiltrating capability.
3. **Deterministic** — Every fixture has a pinned SHA-256 hash recorded below. CI and local test runs verify the hash before emulation so results are reproducible.
4. **Expected plaintext** — After emulation, the decrypted string output **must** be exactly `thecyberyeti.com`. Any fixture that produces a different plaintext is out-of-spec.

## Reference source

The canonical behaviour we replicate comes from `test.c` in the repo root: an XOR-decrypt loop writing `thecyberyeti.com` into a stack buffer, followed by `InternetConnectA`.

## Fixture manifest

| Filename | Arch | SHA-256 | Notes |
|----------|------|---------|-------|
| *(none yet)* | — | — | Add entries as fixtures are created |

When adding a new fixture:

```bash
sha256sum tests/fixtures/<file>.exe
```

Paste the hash into the table above and commit alongside the binary.

## What happens when fixtures are missing

Pytest will **skip** (not fail) any integration test that requires a fixture file which is not present on disk. This is handled by markers and conftest logic in `tests/conftest.py`. A clear skip reason is printed so developers know which fixture to supply.
