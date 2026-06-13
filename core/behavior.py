# -*- coding: utf-8 -*-
"""Best-effort behavior tracing for emulated malware samples.

This module converts observed API calls and extracted indicators into a compact
analyst-facing behavior report. It does not claim complete behavioral coverage;
it summarizes only what the emulator observed on the executed path.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
from typing import Any, Iterable, Mapping, Sequence


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:[a-zA-Z]:\\[^\s\"'<>]+|%[A-Z_]+%\\[^\s\"'<>]+)")
_REG_RE = re.compile(r"(?:HKCU|HKLM|HKEY_|Software\\|System\\|CurrentVersion\\Run)", re.IGNORECASE)
_REG_PATH_START_RE = re.compile(r"(?:HKCU|HKLM|HKEY_[A-Z_]+|Software\\|System\\)[^\r\n]{0,220}", re.IGNORECASE)
_EXE_RE = re.compile(r"\b[\w. -]+\.(?:exe|dll|bat|cmd|ps1|vbs|scr)\b", re.IGNORECASE)

_PERSISTENCE_KEYS = (
    "currentversion\\run",
    "currentversion\\runonce",
    "currentcontrolset\\services",
    "winlogon",
    "startup",
)

_SUSPICIOUS_TOOLS = (
    "vmware", "virtualbox", "vbox", "sandbox", "wireshark", "procmon",
    "processhacker", "ida", "x64dbg", "ollydbg", "debugger",
)


@dataclass
class BehaviorEvent:
    api: str
    category: str
    description: str
    indicators: list[str] = field(default_factory=list)
    confidence: int = 50
    source: str = "api_report"
    time: float | None = None


class BehaviorTracer:
    """Collect and summarize observed malware behavior events."""

    def __init__(self, max_events: int = 2000) -> None:
        self.max_events = max_events
        self.events: list[BehaviorEvent] = []
        self._seen: set[tuple[str, str, tuple[str, ...]]] = set()

    def record_api_call(
        self,
        api_name: str,
        args: Sequence[Any] | None = None,
        *,
        source: str = "api_hook",
        time: float | None = None,
    ) -> None:
        """Classify and record one observed API call if behavior-relevant."""
        if len(self.events) >= self.max_events:
            return
        indicators = _extract_indicators(args or [])
        classified = _classify_api(api_name, indicators, args or [])
        if classified is None:
            return
        category, description, confidence = classified
        key = (api_name.lower(), category, tuple(sorted(indicators))[:8])
        if key in self._seen:
            return
        self._seen.add(key)
        self.events.append(BehaviorEvent(
            api=api_name,
            category=category,
            description=description,
            indicators=indicators[:12],
            confidence=confidence,
            source=source,
            time=time,
        ))

    def ingest_speakeasy_report(self, report_json: Mapping[str, Any]) -> None:
        """Record behavior from Speakeasy's JSON report API call lists."""
        for entry in report_json.get("entry_points", []) or []:
            for api_call in entry.get("apis", []) or []:
                api_name = str(api_call.get("api_name") or api_call.get("name") or "")
                if not api_name:
                    continue
                args = api_call.get("args") or []
                t = api_call.get("time") or api_call.get("ts")
                self.record_api_call(api_name, args, source="speakeasy_report", time=t if isinstance(t, (int, float)) else None)

    def build_report(self, strings: Iterable[Mapping[str, Any]] | None = None, stop_reason: str | None = None) -> dict[str, Any]:
        """Build a compact report with summary, risk, events, and IOCs."""
        iocs = _collect_iocs(strings or [], self.events)
        report_events = list(self.events)
        report_events.extend(_indicator_events(iocs))
        summary = _summarize(report_events, iocs)
        risk_score = _risk_score(report_events, iocs)
        if risk_score >= 70:
            verdict = "high"
        elif risk_score >= 35:
            verdict = "medium"
        else:
            verdict = "low"
        tactics = _tactics(report_events)
        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "summary": summary,
            "tactics": tactics,
            "iocs": iocs,
            "events": [asdict(e) for e in report_events],
            "execution_note": _execution_note(stop_reason),
        }


def _extract_indicators(values: Sequence[Any]) -> list[str]:
    text = " ".join(str(v) for v in values if v is not None)
    found: list[str] = []
    for rx in (_URL_RE, _IP_RE, _PATH_RE, _EXE_RE):
        found.extend(m.group(0).strip(" ,;\x00") for m in rx.finditer(text))
    # Domains after URLs so hosts are still available when URL parsing is partial.
    found.extend(
        domain for domain in (m.group(0).strip(" ,;\x00") for m in _DOMAIN_RE.finditer(text))
        if _is_domain_ioc(domain)
    )
    for match in _REG_PATH_START_RE.finditer(text):
        found.append(match.group(0).strip(" ,;\x00")[:300])
    lowered = text.lower()
    found.extend(tool for tool in _SUSPICIOUS_TOOLS if tool in lowered)
    return _dedupe(found)


def _classify_api(api_name: str, indicators: list[str], args: Sequence[Any]) -> tuple[str, str, int] | None:
    api = api_name.lower().rsplit('.', 1)[-1]
    joined = " ".join(str(a) for a in args if a is not None).lower()

    if api in {"internetopenurla", "internetopenurlw", "urldownloadtofilea", "urldownloadtofilew"}:
        return "network.download", "Opens or downloads from a remote URL", 90
    if api.startswith("winhttp") or api in {"internetconnecta", "internetconnectw", "httpopenrequesta", "httpopenrequestw", "httpsendrequesta", "httpsendrequestw"}:
        return "network.http", "Uses HTTP/WinINet/WinHTTP networking", 80
    if api in {"connect", "send", "recv", "wsastartup", "gethostbyname", "dnsquery_a", "dnsquery_w", "dnsquerya", "dnsqueryw"}:
        return "network.socket", "Uses socket or DNS networking", 75

    if api in {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew", "winexec", "system"}:
        return "process.spawn", "Launches a child process or command", 85
    if api in {"createtoolhelp32snapshot", "process32first", "process32next"}:
        return "process.enumerate", "Enumerates running processes", 70
    if api in {"openprocess", "terminateprocess"}:
        return ("process.kill" if api == "terminateprocess" else "process.open", "Opens or manipulates another process", 75)

    if api in {"createfilea", "createfilew"}:
        return "file.open_or_create", "Opens or creates a file", 65
    if api in {"writefile", "fwrite"}:
        return "file.write", "Writes data to a file or stream", 70
    if api in {"deletefilea", "deletefilew", "movefilea", "movefilew", "copyfilea", "copyfilew"}:
        return "file.modify", "Modifies, moves, copies, or deletes files", 70

    if api.startswith("reg"):
        if any(k in joined for k in _PERSISTENCE_KEYS):
            return "persistence.registry_run", "Touches registry locations commonly used for persistence", 90
        if "setvalue" in api or "createkey" in api or "delete" in api:
            return "registry.write", "Creates, modifies, or deletes registry data", 75
        return "registry.read", "Reads or opens registry data", 60

    if api in {"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "resumethread"}:
        if api in {"virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex"}:
            return "injection.possible", "Uses APIs commonly seen in process injection", 85
        return "memory.allocate_or_thread", "Allocates memory or manipulates thread execution", 65

    if api in {
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstringa",
        "outputdebugstringw",
    }:
        return "evasion.debugger_check", "Checks for debugger or emits debug-probing output", 80
    if api in {"sleep", "getticks", "gettickcount", "queryperformancecounter"}:
        return "evasion.timing", "Uses timing or delay APIs", 55

    if any(tool in joined for tool in _SUSPICIOUS_TOOLS):
        return "evasion.tool_detection", "References sandbox, VM, or analysis tools", 70
    return None


def _collect_iocs(strings: Iterable[Mapping[str, Any]], events: Sequence[BehaviorEvent]) -> dict[str, list[str]]:
    vals: list[str] = []
    for item in strings:
        content = item.get("content")
        if isinstance(content, str):
            vals.append(content)
    for event in events:
        vals.extend(event.indicators)
    text = "\n".join(vals)
    urls = _dedupe(m.group(0).strip(" ,;\x00") for m in _URL_RE.finditer(text))
    ips = _dedupe(m.group(0).strip(" ,;\x00") for m in _IP_RE.finditer(text))
    domains = _dedupe(
        domain for domain in (m.group(0).strip(" ,;\x00") for m in _DOMAIN_RE.finditer(text))
        if _is_domain_ioc(domain)
    )
    files = _dedupe(m.group(0).strip(" ,;\x00") for m in _PATH_RE.finditer(text))
    processes = _dedupe(m.group(0).strip(" ,;\x00") for m in _EXE_RE.finditer(text))
    registry_keys = _dedupe(v[:300] for v in vals if _REG_RE.search(v))
    network_artifacts = _dedupe(
        v[:300] for v in vals
        if (
            v.startswith("/")
            or "content-type:" in v.lower()
            or "user-agent" in v.lower()
            or "agent/" in v.lower()
            or "beacon" in v.lower()
            or "c2" in v.lower()
        )
    )
    capability_markers = _dedupe(
        v[:300] for v in vals
        if any(
            needle in v.lower()
            for needle in (
                "keylog", "clipboard", "credential", "login data", "password",
                "screenshot", "screen", "webcam", "inject", "hollow",
                "ransom", "encrypt", "evasion", "debugger", "vmware",
                "virtualbox", "sandbox", "worm", "exploit", "trojan",
                "persistence", "uninstall", "polymorph", "fileless",
            )
        )
    )
    return {
        "urls": urls[:100],
        "domains": domains[:100],
        "ips": ips[:100],
        "files": files[:100],
        "registry_keys": registry_keys[:100],
        "processes": processes[:100],
        "network_artifacts": network_artifacts[:100],
        "capability_markers": capability_markers[:100],
    }


def _is_domain_ioc(value: str) -> bool:
    lowered = value.lower().strip(".")
    if not lowered or "%" in lowered:
        return False
    if lowered.endswith((".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".scr")):
        return False
    first_label = lowered.split(".", 1)[0]
    if first_label and first_label[0].isdigit():
        return False
    return True


def _indicator_events(iocs: Mapping[str, list[str]]) -> list[BehaviorEvent]:
    """Create low/medium-confidence events from extracted string IOCs.

    String-only reports are common when samples emit decoded lab markers via
    OutputDebugStringA or when Speakeasy observes config but not the real API
    path.  These events keep the analyst behavior summary useful without
    overstating that the action executed.
    """
    events: list[BehaviorEvent] = []
    all_iocs = "\n".join(v for values in iocs.values() for v in values).lower()
    if iocs.get("urls"):
        events.append(BehaviorEvent(
            api="extracted_strings",
            category="network.indicator",
            description="Extracted strings contain URL indicators",
            indicators=iocs["urls"][:8],
            confidence=45,
            source="string_ioc",
        ))
    elif iocs.get("domains") or iocs.get("ips") or iocs.get("network_artifacts"):
        events.append(BehaviorEvent(
            api="extracted_strings",
            category="network.indicator",
            description="Extracted strings contain network/C2 indicators",
            indicators=(iocs.get("domains", []) + iocs.get("ips", []) + iocs.get("network_artifacts", []))[:8],
            confidence=40,
            source="string_ioc",
        ))
    if iocs.get("registry_keys"):
        reg_indicators = iocs["registry_keys"][:8]
        joined = " ".join(reg_indicators).lower()
        category = "persistence.registry_run" if any(k in joined for k in _PERSISTENCE_KEYS) else "registry.indicator"
        events.append(BehaviorEvent(
            api="extracted_strings",
            category=category,
            description="Extracted strings contain registry indicators",
            indicators=reg_indicators,
            confidence=55 if category.startswith("persistence") else 40,
            source="string_ioc",
        ))
    if iocs.get("files"):
        events.append(BehaviorEvent(
            api="extracted_strings",
            category="file.indicator",
            description="Extracted strings contain file path indicators",
            indicators=iocs["files"][:8],
            confidence=35,
            source="string_ioc",
        ))
    if iocs.get("processes"):
        events.append(BehaviorEvent(
            api="extracted_strings",
            category="process.indicator",
            description="Extracted strings contain executable or script names",
            indicators=iocs["processes"][:8],
            confidence=35,
            source="string_ioc",
        ))
    keyword_specs = [
        (("keylog", "clipboard", "credential", "login data", "password"), "collection.input_or_credentials", "Extracted strings reference keylogging, clipboard, or credential collection", 45),
        (("screenshot", "screen", "webcam"), "collection.screen_or_camera", "Extracted strings reference screen or webcam capture", 40),
        (("inject", "hollow", "writeprocessmemory", "virtualallocex", "createremotethread"), "injection.possible", "Extracted strings reference process injection or hollowing", 55),
        (("ransom", "encrypt", "encrypted"), "impact.ransomware_indicator", "Extracted strings reference ransomware or file encryption behavior", 45),
        (("evasion", "debugger", "vmware", "virtualbox", "sandbox"), "evasion.indicator", "Extracted strings reference anti-analysis or VM checks", 45),
    ]
    for needles, category, description, confidence in keyword_specs:
        if any(needle in all_iocs for needle in needles):
            indicators = [v for values in iocs.values() for v in values if any(n in v.lower() for n in needles)][:8]
            events.append(BehaviorEvent(
                api="extracted_strings",
                category=category,
                description=description,
                indicators=indicators,
                confidence=confidence,
                source="string_ioc",
            ))
    return events


def _summarize(events: Sequence[BehaviorEvent], iocs: Mapping[str, list[str]]) -> list[str]:
    cats = {e.category for e in events}
    out: list[str] = []
    if any(c.startswith("network") for c in cats) or iocs.get("urls") or iocs.get("domains"):
        out.append("Observed behavior indicates possible network communication or payload download")
    if "process.spawn" in cats:
        out.append("Observed behavior indicates child process or command execution")
    elif any(c.startswith("process") for c in cats):
        out.append("Observed strings indicate process or command artifacts")
    if any(c.startswith("file") for c in cats) or iocs.get("files"):
        out.append("Observed behavior indicates file-system activity")
    if any(c.startswith("persistence") for c in cats):
        out.append("Observed behavior indicates possible persistence via registry/startup locations")
    elif any(c.startswith("registry") for c in cats):
        out.append("Observed behavior indicates registry access")
    if any(c.startswith("injection") for c in cats):
        out.append("Observed behavior indicates possible process injection")
    if any(c.startswith("collection") for c in cats):
        out.append("Observed strings indicate possible collection capability such as keylogging, clipboard, screenshot, webcam, or credential access")
    if any(c.startswith("impact") for c in cats):
        out.append("Observed strings indicate possible impact behavior such as ransomware or encryption")
    if any(c.startswith("evasion") for c in cats):
        out.append("Observed behavior indicates anti-analysis or timing checks")
    return out or ["No high-level behavior was confidently classified from the observed path"]


def _risk_score(events: Sequence[BehaviorEvent], iocs: Mapping[str, list[str]]) -> int:
    score = 0
    weights = {
        "network.download": 25,
        "network.http": 18,
        "process.spawn": 18,
        "persistence.registry_run": 25,
        "injection.possible": 28,
        "evasion.debugger_check": 15,
        "evasion.indicator": 8,
        "collection.input_or_credentials": 12,
        "collection.screen_or_camera": 8,
        "impact.ransomware_indicator": 12,
        "file.write": 12,
        "file.open_or_create": 8,
        "registry.write": 12,
    }
    cats = {e.category for e in events}
    for cat, weight in weights.items():
        if cat in cats:
            score += weight
    if iocs.get("urls"):
        score += 10
    if iocs.get("ips") or iocs.get("domains") or iocs.get("network_artifacts"):
        score += 5
    return min(score, 100)


def _tactics(events: Sequence[BehaviorEvent]) -> list[str]:
    out: list[str] = []
    cats = {e.category for e in events}
    if any(c.startswith("network") for c in cats):
        out.append("Command and Control")
    if "process.spawn" in cats:
        out.append("Execution")
    if any(c.startswith("persistence") for c in cats):
        out.append("Persistence")
    if any(c.startswith("injection") for c in cats):
        out.append("Defense Evasion")
    if any(c.startswith("collection") for c in cats):
        out.append("Collection")
    if any(c.startswith("impact") for c in cats):
        out.append("Impact")
    if any(c.startswith("evasion") for c in cats):
        out.append("Discovery / Evasion")
    if any(c.startswith("file") or c.startswith("registry") for c in cats):
        out.append("System Modification")
    return _dedupe(out)


def _execution_note(stop_reason: str | None) -> str:
    if stop_reason and stop_reason != "completed":
        return f"Behavior is path-limited; emulation stopped due to {stop_reason}."
    return "Behavior is based only on APIs and strings observed during emulation."


def _dedupe(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for val in values:
        if not val:
            continue
        key = val.lower()
        if key not in seen:
            seen.add(key)
            out.append(val)
    return out
