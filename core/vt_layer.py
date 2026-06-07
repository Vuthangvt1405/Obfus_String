# -*- coding: utf-8 -*-
"""Optional VirusTotal enrichment by sample hash.

API keys must be supplied through the VIRUSTOTAL_API_KEY environment variable.
Never hard-code analyst keys in source code or reports.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
MAX_DIRECT_UPLOAD_BYTES = 32 * 1024 * 1024


def lookup_virustotal(sha256: str, *, timeout: int = 20) -> dict[str, Any]:
    """Return a compact VirusTotal report for a SHA256, or a safe error object."""
    api_key = _get_api_key()
    if not api_key:
        return {
            "enabled": False,
            "status": "missing_api_key",
            "message": "Set VIRUSTOTAL_API_KEY to enable VirusTotal enrichment.",
        }
    if not sha256:
        return {"enabled": True, "status": "missing_hash"}

    req = Request(
        VT_FILE_URL.format(sha256=sha256),
        headers={
            "accept": "application/json",
            "x-apikey": api_key,
        },
        method="GET",
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        if exc.code == 404:
            return {
                "enabled": True,
                "status": "not_found",
                "http_status": 404,
                "message": "VirusTotal has no record for this SHA256 hash. The file may be new, private, locally built, or never uploaded.",
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        return {
            "enabled": True,
            "status": "http_error",
            "http_status": exc.code,
            "message": _shorten(body or str(exc)),
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {"enabled": True, "status": "network_error", "message": str(exc)}
    except Exception as exc:
        return {"enabled": True, "status": "error", "message": str(exc)}

    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    names = attrs.get("names") or []
    engines = attrs.get("last_analysis_results") or {}
    detections = [
        {
            "engine": engine,
            "category": result.get("category"),
            "result": result.get("result"),
        }
        for engine, result in engines.items()
        if result.get("category") in {"malicious", "suspicious"}
    ]

    return {
        "enabled": True,
        "status": "ok",
        "id": data.get("id"),
        "link": f"https://www.virustotal.com/gui/file/{sha256}",
        "reputation": attrs.get("reputation"),
        "meaningful_name": attrs.get("meaningful_name"),
        "popular_names": names[:8],
        "last_analysis_date": attrs.get("last_analysis_date"),
        "last_submission_date": attrs.get("last_submission_date"),
        "stats": {name: int(stats.get(name) or 0) for name in (
            "malicious",
            "suspicious",
            "undetected",
            "harmless",
            "timeout",
        )},
        "detections": detections[:20],
    }


def upload_file_to_virustotal(file_path: str, *, timeout: int = 60) -> dict[str, Any]:
    """Upload a file to VirusTotal for remote analysis.

    This sends the sample bytes to VirusTotal. Only call this when the analyst
    explicitly opts in.
    """
    api_key = _get_api_key()
    if not api_key:
        return {
            "enabled": False,
            "status": "missing_api_key",
            "message": "Set VIRUSTOTAL_API_KEY to enable VirusTotal upload.",
        }

    path = Path(file_path)
    if not path.exists():
        return {"enabled": True, "status": "missing_file", "message": str(path)}

    size = path.stat().st_size
    if size > MAX_DIRECT_UPLOAD_BYTES:
        return {
            "enabled": True,
            "status": "too_large_for_direct_upload",
            "size_bytes": size,
            "message": "Direct public API upload is limited to 32MB in this tool. Use a small sample or add upload-url support for your VT plan.",
        }

    boundary = "----malstringemu-vt-boundary"
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        path.read_bytes(),
        b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])

    req = Request(
        VT_UPLOAD_URL,
        data=body,
        headers={
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": f"multipart/form-data; boundary={boundary}",
            "content-length": str(len(body)),
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        return {
            "enabled": True,
            "status": "http_error",
            "http_status": exc.code,
            "message": _shorten(body_text or str(exc)),
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {"enabled": True, "status": "network_error", "message": str(exc)}
    except Exception as exc:
        return {"enabled": True, "status": "error", "message": str(exc)}

    data = payload.get("data") or {}
    analysis_id = data.get("id")
    return {
        "enabled": True,
        "status": "submitted",
        "analysis_id": analysis_id,
        "analysis_link": f"https://www.virustotal.com/gui/file-analysis/{analysis_id}" if analysis_id else None,
        "message": "File submitted to VirusTotal. Analysis results may take time; rerun hash lookup later.",
    }


def _get_api_key() -> str:
    """Read VT API key from environment or a local .env file."""
    env_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if env_key:
        return env_key

    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return ""
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == "VIRUSTOTAL_API_KEY":
                return value.strip().strip('"').strip("'")
    except Exception:
        return ""
    return ""


def _shorten(value: str, limit: int = 500) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[:limit] + "..."
