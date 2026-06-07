#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Browser GUI for Malware String Emulator.

Dependency-free web UI using only Python stdlib. It starts a local server,
runs main.py as a subprocess, streams logs by polling, and renders strings plus
behavior results from the JSON report.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = str(ROOT / "report_gui.json")


class AnalysisJob:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.proc: subprocess.Popen[str] | None = None
        self.logs: list[str] = []
        self.status = "idle"
        self.output = DEFAULT_OUTPUT
        self.started_at: float | None = None
        self.ended_at: float | None = None
        self.exit_code: int | None = None
        self.command: list[str] = []

    def start(self, payload: dict[str, Any]) -> bool:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return False
            sample = str(payload.get("file") or "").strip()
            if not sample:
                raise ValueError("Missing sample file")
            if not Path(sample).exists():
                raise ValueError("Sample file does not exist")

            self.output = str(payload.get("output") or DEFAULT_OUTPUT).strip() or DEFAULT_OUTPUT
            cmd = [
                sys.executable,
                str(ROOT / "main.py"),
                "-f", sample,
                "-a", str(payload.get("arch") or "x86"),
                "-t", str(payload.get("timeout") or "60"),
                "--max-instructions", str(payload.get("max_instructions") or "5000000"),
                "-o", self.output,
            ]
            if payload.get("clean_output", True):
                cmd.append("--clean-output")
            if payload.get("vt_lookup", False):
                cmd.append("--vt-lookup")
            if payload.get("vt_upload", False):
                cmd.append("--vt-upload")
            min_conf = str(payload.get("min_confidence") or "").strip()
            if min_conf:
                cmd.extend(["--min-confidence", min_conf])

            self.logs = ["$ " + " ".join(cmd) + "\n"]
            self.status = "running"
            self.started_at = time.time()
            self.ended_at = None
            self.exit_code = None
            self.command = cmd
            self.proc = subprocess.Popen(
                cmd,
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            threading.Thread(target=self._read_stdout, daemon=True).start()
            threading.Thread(target=self._wait, daemon=True).start()
            return True

    def _read_stdout(self) -> None:
        proc = self.proc
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            with self.lock:
                self.logs.append(line)

    def _wait(self) -> None:
        proc = self.proc
        if not proc:
            return
        code = proc.wait()
        with self.lock:
            self.exit_code = code
            self.ended_at = time.time()
            self.status = "completed" if code == 0 else "failed"
            self.logs.append(f"\n[GUI] Process exited with code {code}\n")

    def stop(self) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                self.status = "stopping"
                self.logs.append("\n[GUI] Stop requested\n")

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "status": self.status,
                "logs": "".join(self.logs[-2500:]),
                "output": self.output,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "exit_code": self.exit_code,
                "command": self.command,
            }


JOB = AnalysisJob()


HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>MalString Emu Workbench</title>
<style>
:root{
  color-scheme: dark;
  --bg:#0d1117; --panel:#141a22; --panel2:#10161d; --line:#263241;
  --text:#e8eef6; --muted:#94a3b8; --accent:#65d6a3; --accent2:#7aa7ff;
  --warn:#f7c76b; --bad:#ff8585; --radius:18px;
}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at 20% -20%,#20364a 0,#0d1117 36rem),var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial,sans-serif;}
button,input,select{font:inherit} button{border:0;border-radius:999px;padding:.75rem 1rem;background:#223044;color:var(--text);cursor:pointer;transition:transform .16s ease,background .16s ease} button:hover{background:#2b3b54} button:active{transform:translateY(1px) scale(.99)} button.primary{background:var(--accent);color:#07110d;font-weight:800} button.danger{background:#3b2026;color:#ffc7c7}.shell{max-width:1440px;margin:0 auto;padding:24px}.top{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:18px}.brand h1{font-size:clamp(28px,4vw,52px);letter-spacing:-.055em;line-height:.95;margin:0}.brand p{color:var(--muted);margin:.6rem 0 0}.status{padding:.6rem .85rem;border:1px solid var(--line);border-radius:999px;background:rgba(20,26,34,.72);color:var(--accent);font-weight:800}.grid{display:grid;grid-template-columns:380px 1fr;gap:18px}.card{background:linear-gradient(180deg,rgba(255,255,255,.035),rgba(255,255,255,.015)),var(--panel);border:1px solid var(--line);border-radius:var(--radius);box-shadow:0 20px 80px rgba(0,0,0,.28)}.setup{padding:18px;position:sticky;top:18px;height:max-content}.setup h2,.card h2{margin:.2rem 0 1rem;font-size:18px;letter-spacing:-.02em}.field{display:grid;gap:7px;margin:13px 0}.field label{color:var(--muted);font-size:13px}.field input,.field select{width:100%;border:1px solid var(--line);border-radius:12px;background:#0c1219;color:var(--text);padding:.78rem .85rem;outline:none}.field input:focus,.field select:focus{border-color:var(--accent)}.twocol{display:grid;grid-template-columns:1fr 1fr;gap:10px}.check{display:flex;gap:10px;align-items:center;color:var(--muted);font-size:14px;margin:14px 0}.actions{display:flex;gap:10px;margin-top:16px}.tabs{display:flex;gap:8px;padding:8px;border-bottom:1px solid var(--line)}.tab{background:transparent;color:var(--muted);border-radius:12px}.tab.active{background:#203044;color:var(--text)}.view{display:none;padding:16px}.view.active{display:block}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}.metric{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:14px}.metric b{font-size:24px;letter-spacing:-.04em}.metric span{display:block;color:var(--muted);font-size:12px;margin-top:4px}.log{height:540px;overflow:auto;background:#06090d;border-radius:14px;border:1px solid var(--line);padding:14px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;white-space:pre-wrap;color:#c8d3df}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:14px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:#b8c5d6;background:#101822;position:sticky;top:0}td{color:#dce6f1}.pill{display:inline-block;padding:.2rem .5rem;border:1px solid var(--line);border-radius:999px;color:#b7c5d7;background:#101822;margin:.1rem}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:12px}.toolbar input,.toolbar select{border:1px solid var(--line);border-radius:999px;background:#0c1219;color:var(--text);padding:.65rem .85rem}.behaviorText{background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:12px;color:#dce6f1}.muted{color:var(--muted)}.risk-high{color:var(--bad)}.risk-medium{color:var(--warn)}.risk-low{color:var(--accent)}
.behaviorHero{display:grid;grid-template-columns:1.1fr .9fr;gap:14px;margin-bottom:14px}.verdictPanel{position:relative;overflow:hidden;background:linear-gradient(135deg,rgba(101,214,163,.12),rgba(122,167,255,.035)),#0c1219;border:1px solid var(--line);border-radius:22px;padding:18px;min-height:178px}.verdictPanel:before{content:"";position:absolute;inset:auto -20% -55% 25%;height:190px;background:radial-gradient(circle,rgba(101,214,163,.16),transparent 62%);pointer-events:none}.verdictKicker{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;text-transform:uppercase;letter-spacing:.18em;color:var(--muted);font-size:11px}.verdictTitle{font-size:44px;line-height:.92;letter-spacing:-.06em;margin:12px 0 10px}.riskRail{height:8px;background:#1b2634;border-radius:999px;overflow:hidden;border:1px solid rgba(255,255,255,.04)}.riskFill{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--warn),var(--bad));border-radius:999px;transition:width .45s cubic-bezier(.16,1,.3,1)}.riskMeta{display:flex;justify-content:space-between;color:var(--muted);font-size:12px;margin-top:8px}.behaviorStats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.behaviorStat{background:#0c1219;border:1px solid var(--line);border-radius:18px;padding:14px}.behaviorStat b{display:block;font-size:26px;letter-spacing:-.04em}.behaviorStat span{display:block;color:var(--muted);font-size:12px;margin-top:4px}.behaviorGrid{display:grid;grid-template-columns:.92fr 1.08fr;gap:14px;margin-bottom:14px}.insightList,.iocBoard,.timelinePanel{background:var(--panel2);border:1px solid var(--line);border-radius:18px;padding:14px}.sectionLabel{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.14em;color:#b8c5d6}.insightItem{display:grid;grid-template-columns:7px 1fr;gap:10px;align-items:start;padding:10px 0;border-top:1px solid rgba(255,255,255,.06)}.insightItem:first-of-type{border-top:0}.insightDot{width:7px;height:7px;border-radius:99px;background:var(--accent);margin-top:7px;box-shadow:0 0 0 4px rgba(101,214,163,.08)}.iocGroups{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.iocGroup{border:1px solid rgba(255,255,255,.06);border-radius:14px;padding:10px;background:#0a1017}.iocGroup h4{margin:0 0 8px;font-size:12px;color:var(--muted);font-weight:700}.iocValue{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#dce6f1;padding:5px 0;border-top:1px solid rgba(255,255,255,.045)}.iocValue:first-of-type{border-top:0}.emptyState{border:1px dashed var(--line);border-radius:16px;padding:18px;color:var(--muted);background:#0a1017}.hashPanel{background:var(--panel2);border:1px solid var(--line);border-radius:18px;padding:14px;margin-bottom:14px}.hashGrid{display:grid;grid-template-columns:120px 1fr;gap:8px 12px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.hashGrid span{color:var(--muted)}.hashGrid code{overflow:auto;white-space:nowrap;color:#dce6f1}.vtHero{display:grid;grid-template-columns:1fr 1.2fr;gap:14px;margin-bottom:14px}.vtScore{background:linear-gradient(135deg,rgba(247,199,107,.12),rgba(255,133,133,.04)),#0c1219;border:1px solid var(--line);border-radius:22px;padding:18px}.vtScore b{display:block;font-size:54px;letter-spacing:-.07em;line-height:.9}.vtStats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.vtStat{border:1px solid rgba(255,255,255,.06);border-radius:16px;background:#0a1017;padding:14px}.vtStat b{display:block;font-size:28px;letter-spacing:-.04em}.vtStat span{display:block;color:var(--muted);font-size:12px;margin-top:4px}.vtPanel{background:var(--panel2);border:1px solid var(--line);border-radius:18px;padding:14px;margin-bottom:14px}.vtDetections{display:grid;gap:8px}.vtDetection{display:grid;grid-template-columns:180px 120px 1fr;gap:10px;align-items:center;border:1px solid rgba(255,255,255,.06);border-radius:14px;background:#0a1017;padding:10px;font-size:13px}.vtEngine{font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.vtCategory{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--warn)}.vtResult{color:#dce6f1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.timelinePanel{margin-bottom:14px}.timeline{display:grid;gap:10px}.timelineItem{display:grid;grid-template-columns:110px 1fr 74px;gap:12px;align-items:start;border:1px solid rgba(255,255,255,.06);border-radius:16px;background:#0a1017;padding:12px;animation:riseIn .45s cubic-bezier(.16,1,.3,1) both;animation-delay:calc(var(--i) * 55ms)}.timelineCat{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:var(--accent);overflow:hidden;text-overflow:ellipsis}.timelineTitle{font-weight:800;color:#eef5ff}.timelineDesc{color:var(--muted);font-size:12px;margin-top:4px}.confidenceBar{height:6px;border-radius:999px;background:#1b2634;overflow:hidden;margin-top:6px}.confidenceBar i{display:block;height:100%;background:var(--accent);border-radius:inherit}.eventSearch{justify-content:space-between}.eventSearch input{width:min(360px,100%)}@keyframes riseIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:900px){.grid{grid-template-columns:1fr}.setup{position:static}.summary{grid-template-columns:1fr 1fr}.top{align-items:start;flex-direction:column}.behaviorHero,.behaviorGrid,.vtHero{grid-template-columns:1fr}.timelineItem,.vtDetection{grid-template-columns:1fr}.iocGroups{grid-template-columns:1fr}.verdictTitle{font-size:36px}}
</style>
</head>
<body>
<div class="shell">
  <div class="top"><div class="brand"><h1>MalString Emu Workbench</h1><p>Runtime string extraction with behavior tracing for PE malware analysis.</p></div><div id="status" class="status">idle</div></div>
  <div class="grid">
    <aside class="card setup">
      <h2>Analysis setup</h2>
      <div class="field"><label>PE sample path</label><input id="file" value="sample/malware3.exe"></div>
      <div class="field"><label>Output report</label><input id="output" value="report_gui.json"></div>
      <div class="twocol"><div class="field"><label>Architecture</label><select id="arch"><option>x86</option><option>x64</option></select></div><div class="field"><label>Timeout</label><input id="timeout" value="60"></div></div>
      <div class="field"><label>Max instructions</label><input id="maxInstructions" value="5000000"></div>
      <div class="field"><label>Min confidence</label><input id="minConfidence" placeholder="blank = any"></div>
      <label class="check"><input id="cleanOutput" type="checkbox" checked> Clean noisy deferred_scan strings</label>
      <label class="check"><input id="vtLookup" type="checkbox"> Enrich with VirusTotal hash lookup</label>
      <label class="check"><input id="vtUpload" type="checkbox"> Upload to VirusTotal if hash is unknown</label>
      <div class="actions"><button class="primary" onclick="startAnalysis()">Start</button><button class="danger" onclick="stopAnalysis()">Stop</button></div>
      <p class="muted">Run only in an isolated malware lab. Behavior is best-effort and path-limited.</p>
    </aside>
    <main class="card">
      <div class="tabs"><button class="tab active" data-tab="overview" onclick="showTab('overview')">Overview</button><button class="tab" data-tab="logs" onclick="showTab('logs')">Live logs</button><button class="tab" data-tab="strings" onclick="showTab('strings')">Strings</button><button class="tab" data-tab="behavior" onclick="showTab('behavior')">Behavior</button></div>
      <section id="overview" class="view active"><div class="summary"><div class="metric"><b id="mStrings">0</b><span>strings</span></div><div class="metric"><b id="mEvents">0</b><span>behavior events</span></div><div class="metric"><b id="mRisk">0</b><span>risk score</span></div><div class="metric"><b id="mVerdict">n/a</b><span>verdict</span></div></div><div id="hashPanel" class="hashPanel">No sample hash loaded yet.</div><div id="summary" class="behaviorText">No report loaded yet.</div><div id="vtText" class="vtPanel">No VirusTotal lookup loaded yet. Enable VirusTotal hash lookup and rerun analysis.</div><div class="toolbar eventSearch"><input id="vtSearch" placeholder="Search VirusTotal engines or detections" oninput="renderVirusTotal()"><button onclick="exportVtCsv()">Export VT CSV</button></div><div id="vtDetections" class="vtDetections"></div></section>
      <section id="logs" class="view"><pre id="log" class="log"></pre></section>
      <section id="strings" class="view"><div class="toolbar"><input id="stringSearch" placeholder="Search strings" oninput="renderStrings()"><select id="sourceFilter" onchange="renderStrings()"><option>All sources</option></select><button onclick="exportCsv()">Export CSV</button></div><div class="tablewrap"><table><thead><tr><th>String</th><th>Source</th><th>Tags</th><th>Encoding</th><th>Confidence</th></tr></thead><tbody id="stringsBody"></tbody></table></div></section>
      <section id="behavior" class="view">
        <div id="behaviorText">No behavior report loaded yet.</div>
        <div class="toolbar eventSearch"><input id="behaviorSearch" placeholder="Search behavior, IOCs, tactics" oninput="renderBehavior()"><button onclick="exportBehaviorCsv()">Export Behavior CSV</button></div>
        <div class="tablewrap"><table><thead><tr><th>Category</th><th>Description</th><th>Indicators</th><th>Confidence</th><th>Source</th></tr></thead><tbody id="behaviorBody"></tbody></table></div>
      </section>
    </main>
  </div>
</div>
<script>
let report=null, strings=[], events=[];
let lastStatus='', lastLogs='', lastReportRaw='', lastReportOutput='', reportLoadedForRun=false;
const renderCache=new Map();
function el(id){return document.getElementById(id)}
function setHtml(id,html){if(renderCache.get(id)===html)return false; renderCache.set(id,html); el(id).innerHTML=html; return true;}
function setText(id,text){text=String(text??''); if(renderCache.get(id)===text)return false; renderCache.set(id,text); el(id).textContent=text; return true;}
function setClass(id,cls){if(el(id).className!==cls)el(id).className=cls;}
function showTab(id){document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===id));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id===id))}
async function startAnalysis(){
  const payload={file:el('file').value,output:el('output').value,arch:el('arch').value,timeout:el('timeout').value,max_instructions:el('maxInstructions').value,min_confidence:el('minConfidence').value,clean_output:el('cleanOutput').checked,vt_lookup:el('vtLookup').checked,vt_upload:el('vtUpload').checked};
  reportLoadedForRun=false; lastReportRaw=''; lastReportOutput=payload.output||'';
  const r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}); const j=await r.json(); if(!j.ok) alert(j.error||'Could not start');
}
async function stopAnalysis(){await fetch('/api/stop',{method:'POST'});}
async function poll(){
  const s=await (await fetch('/api/status')).json();
  if(s.status!==lastStatus){lastStatus=s.status; setText('status',s.status); if(s.status==='running'||s.status==='idle') reportLoadedForRun=false;}
  const logs=s.logs||'';
  if(logs!==lastLogs){lastLogs=logs; setText('log',logs); el('log').scrollTop=el('log').scrollHeight;}
  const done=s.status==='completed'||s.status==='failed';
  if(done && !reportLoadedForRun){reportLoadedForRun=await loadReport(s.output||'');}
}
async function loadReport(outputKey=''){try{const r=await fetch('/api/report'); if(!r.ok)return false; const raw=await r.text(); if(raw===lastReportRaw && outputKey===lastReportOutput)return true; lastReportRaw=raw; lastReportOutput=outputKey; report=JSON.parse(raw); strings=report.strings||[]; const b=report.behavior||{}; events=b.events||[]; renderAll(); return true;}catch(e){return false;}}
function renderAll(){const b=report.behavior||{}; setText('mStrings',report.total_strings||strings.length); setText('mEvents',events.length); setText('mRisk',b.risk_score??0); setText('mVerdict',b.verdict||'n/a'); setClass('mRisk','risk-'+(b.verdict||'low')); renderHashPanel(); setHtml('summary',(b.summary||[]).map(x=>'<div>- '+escapeHtml(x)+'</div>').join('')||'No behavior summary.'); renderSourceFilter(); renderStrings(); renderBehavior(); renderVirusTotal();}
function renderHashPanel(){const s=report?.sample||{}, h=s.hashes||{}, pe=s.pe||{}, vt=s.virustotal||{}; if(!Object.keys(s).length){setText('hashPanel','No sample hash loaded yet.'); return;} const vtStats=vt.stats?`${vt.stats.malicious} malicious, ${vt.stats.suspicious} suspicious, ${vt.stats.undetected} undetected`:vt.message||'not queried'; setHtml('hashPanel',`<h3 class="sectionLabel">Sample identity</h3><div class="hashGrid"><span>File</span><code>${escapeHtml(s.file_name||'')}</code><span>Size</span><code>${escapeHtml(String(s.size_bytes??''))} bytes</code><span>MD5</span><code>${escapeHtml(h.md5||'')}</code><span>SHA1</span><code>${escapeHtml(h.sha1||'')}</code><span>SHA256</span><code>${escapeHtml(h.sha256||'')}</code><span>ImpHash</span><code>${escapeHtml(pe.imphash||pe.error||'n/a')}</code><span>VirusTotal</span><code>${vt.link?`<a href="${escapeHtml(vt.link)}" target="_blank" rel="noreferrer">${escapeHtml(vtStats)}</a>`:escapeHtml(vtStats)}</code></div>`);}
function renderSourceFilter(){const old=el('sourceFilter').value; const vals=['All sources',...new Set(strings.map(s=>s.source).filter(Boolean).sort())]; const html=vals.map(v=>`<option>${escapeHtml(v)}</option>`).join(''); if(setHtml('sourceFilter',html)) el('sourceFilter').value=vals.includes(old)?old:'All sources';}
function renderStrings(){const q=el('stringSearch').value.toLowerCase(), src=el('sourceFilter').value; setHtml('stringsBody',strings.filter(s=>(src==='All sources'||s.source===src)&&JSON.stringify(s).toLowerCase().includes(q)).map(s=>`<tr><td>${escapeHtml(s.content||'')}</td><td>${escapeHtml(s.source||'')}</td><td>${(s.tags||[]).map(t=>`<span class="pill">${escapeHtml(t)}</span>`).join('')}</td><td>${escapeHtml(s.encoding||'')}</td><td>${escapeHtml(String(s.confidence??''))}</td></tr>`).join(''));}
function renderBehavior(){
  const b=report?.behavior||{}; const iocs=b.iocs||{}; const q=(el('behaviorSearch')?.value||'').toLowerCase();
  const filtered=events.filter(e=>JSON.stringify(e).toLowerCase().includes(q));
  const nonEmptyIocs=Object.entries(iocs).filter(([k,v])=>Array.isArray(v)&&v.length);
  const tactics=b.tactics||[]; const verdict=b.verdict||'low'; const risk=Number(b.risk_score||0);
  el('behaviorText').innerHTML=`
    <div class="behaviorHero">
      <div class="verdictPanel">
        <div class="verdictKicker">Behavior verdict</div>
        <div class="verdictTitle risk-${escapeHtml(verdict)}">${escapeHtml(verdict)}</div>
        <div class="riskRail"><div class="riskFill" style="width:${Math.max(0,Math.min(100,risk))}%"></div></div>
        <div class="riskMeta"><span>Risk score</span><b>${escapeHtml(String(risk))}/100</b></div>
      </div>
      <div class="behaviorStats">
        <div class="behaviorStat"><b>${events.length}</b><span>observed events</span></div>
        <div class="behaviorStat"><b>${nonEmptyIocs.reduce((n,[,v])=>n+v.length,0)}</b><span>IOC values</span></div>
        <div class="behaviorStat"><b>${tactics.length}</b><span>tactics</span></div>
        <div class="behaviorStat"><b>${strings.length}</b><span>supporting strings</span></div>
      </div>
    </div>
    <div class="behaviorGrid">
      <div class="insightList"><h3 class="sectionLabel">Analyst summary</h3>${(b.summary||[]).length?(b.summary||[]).map(x=>`<div class="insightItem"><span class="insightDot"></span><span>${escapeHtml(x)}</span></div>`).join(''):'<div class="emptyState">No classified behavior summary for this path.</div>'}</div>
      <div class="iocBoard"><h3 class="sectionLabel">IOC board</h3>${nonEmptyIocs.length?`<div class="iocGroups">${nonEmptyIocs.map(([k,v])=>`<div class="iocGroup"><h4>${escapeHtml(k)}</h4>${v.slice(0,6).map(x=>`<span class="iocValue" title="${escapeHtml(x)}">${escapeHtml(x)}</span>`).join('')}${v.length>6?`<span class="iocValue">+${v.length-6} more</span>`:''}</div>`).join('')}</div>`:'<div class="emptyState">No IOC buckets populated.</div>'}</div>
    </div>`;
  el('behaviorBody').innerHTML=filtered.map(e=>`<tr><td>${escapeHtml(e.category||'')}</td><td>${escapeHtml(e.description||'')}</td><td>${escapeHtml((e.indicators||[]).join(', '))}</td><td>${escapeHtml(String(e.confidence??''))}</td><td>${escapeHtml(e.source||'')}</td></tr>`).join('');
}
function exportCsv(){let rows=[['content','source','tags','encoding','confidence'],...strings.map(s=>[s.content||'',s.source||'',(s.tags||[]).join('|'),s.encoding||'',s.confidence??''])]; let csv=rows.map(r=>r.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(',')).join('\n'); let a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download='strings.csv'; a.click();}
function exportBehaviorCsv(){let rows=[['category','api','description','indicators','confidence','source'],...events.map(e=>[e.category||'',e.api||'',e.description||'',(e.indicators||[]).join('|'),e.confidence??'',e.source||''])]; let csv=rows.map(r=>r.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(',')).join('\n'); let a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download='behavior.csv'; a.click();}
function renderVirusTotal(){
  const vt=report?.sample?.virustotal||{}, h=report?.sample?.hashes||{}; const stats=vt.stats||{}; const detections=vt.detections||[]; const upload=vt.upload||{}; const q=(el('vtSearch')?.value||'').toLowerCase();
  if(!Object.keys(vt).length){
    el('vtText').innerHTML='<div class="emptyState"><b>VirusTotal not queried.</b><br>Enable VirusTotal hash lookup, then rerun analysis. Upload is optional and only happens when the hash is unknown.</div>';
    el('vtDetections').innerHTML=''; return;
  }
  if(vt.status!=='ok'){
    const isNotFound=vt.status==='not_found';
    const uploaded=Object.keys(upload).length>0;
    const uploadLine=uploaded?`<br><br><b>Remote upload:</b> ${escapeHtml(upload.status||'unknown')}<br>${escapeHtml(upload.message||'')}${upload.analysis_link?`<br><a href="${escapeHtml(upload.analysis_link)}" target="_blank" rel="noreferrer">Open VT analysis queue</a>`:''}`:'';
    el('vtText').innerHTML=`
      <div class="vtHero">
        <div class="vtScore"><div class="verdictKicker">VirusTotal hash lookup</div><b class="${isNotFound?'risk-medium':'risk-low'}">${isNotFound?'not found':'n/a'}</b><div class="riskMeta"><span>Status</span><span>${escapeHtml(vt.status||'unknown')}</span></div></div>
        <div class="vtPanel" style="margin-bottom:0"><h3 class="sectionLabel">Clear analyst summary</h3><div class="emptyState"><b>Finding:</b> ${isNotFound?'VirusTotal has no database record for this SHA256.':'VirusTotal lookup did not return a completed report.'}<br><b>Meaning:</b> ${isNotFound?'No vendor detections are available yet. This does not mean the sample is clean.':'Check API status/message below.'}<br><b>Action:</b> ${uploaded?'Sample was submitted for remote analysis. Rerun hash lookup later to pull vendor verdicts.':'If approved by lab policy, enable remote upload and rerun.'}<br><br>${escapeHtml(vt.message||'No extra message.')}${uploadLine}<br><br>${vt.link?`<a href="${escapeHtml(vt.link)}" target="_blank" rel="noreferrer">Open VT hash page</a>`:''}</div></div>
      </div>`;
    el('vtDetections').innerHTML='<div class="emptyState">Detection table is empty because no completed VT report exists for this hash yet.</div>';
    return;
  }
  const malicious=Number(stats.malicious||0), suspicious=Number(stats.suspicious||0), total=Object.values(stats).reduce((a,b)=>a+Number(b||0),0); const ratio=total?`${malicious+suspicious}/${total}`:`${malicious+suspicious}`;
  const verdictText=malicious?'Known malicious by VT vendors':suspicious?'Suspicious by at least one VT vendor':'No VT vendor flagged this hash in the latest report';
  el('vtText').innerHTML=`
    <div class="vtHero">
      <div class="vtScore"><div class="verdictKicker">VirusTotal detection ratio</div><b class="${malicious?'risk-high':suspicious?'risk-medium':'risk-low'}">${escapeHtml(ratio)}</b><div class="riskMeta"><span>SHA256</span><span>${escapeHtml((h.sha256||'').slice(0,16))}...</span></div></div>
      <div class="vtStats">
        <div class="vtStat"><b class="risk-high">${escapeHtml(stats.malicious??0)}</b><span>malicious</span></div>
        <div class="vtStat"><b class="risk-medium">${escapeHtml(stats.suspicious??0)}</b><span>suspicious</span></div>
        <div class="vtStat"><b>${escapeHtml(stats.undetected??0)}</b><span>undetected</span></div>
        <div class="vtStat"><b>${escapeHtml(vt.reputation??'n/a')}</b><span>reputation</span></div>
      </div>
    </div>
    <div class="vtPanel"><h3 class="sectionLabel">Clear analyst summary</h3><div class="emptyState"><b>Finding:</b> ${escapeHtml(verdictText)}.<br><b>Use with caution:</b> VT results are reputation signals, not proof of full behavior. Combine with emulation strings, behavior events, hashes, and lab notes.</div></div>
    <div class="vtPanel"><h3 class="sectionLabel">VT identity</h3><div class="hashGrid"><span>Name</span><code>${escapeHtml(vt.meaningful_name||'n/a')}</code><span>Popular names</span><code>${escapeHtml((vt.popular_names||[]).join(', ')||'n/a')}</code><span>Last analysis</span><code>${escapeHtml(vt.last_analysis_date||'n/a')}</code><span>VT link</span><code>${vt.link?`<a href="${escapeHtml(vt.link)}" target="_blank" rel="noreferrer">${escapeHtml(vt.link)}</a>`:'n/a'}</code></div></div>`;
  const filtered=detections.filter(d=>JSON.stringify(d).toLowerCase().includes(q));
  el('vtDetections').innerHTML=filtered.length?filtered.map(d=>`<div class="vtDetection"><div class="vtEngine">${escapeHtml(d.engine||'')}</div><div class="vtCategory">${escapeHtml(d.category||'')}</div><div class="vtResult">${escapeHtml(d.result||'')}</div></div>`).join(''):'<div class="emptyState">No malicious/suspicious detections match the current filter.</div>';
}
function exportVtCsv(){const detections=report?.sample?.virustotal?.detections||[]; let rows=[['engine','category','result'],...detections.map(d=>[d.engine||'',d.category||'',d.result||''])]; let csv=rows.map(r=>r.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(',')).join('\n'); let a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download='virustotal.csv'; a.click();}
function escapeHtml(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
setInterval(poll,900); poll(); loadReport();
</script>
</body>
</html>'''


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, data: Any) -> None:
        self._send(code, json.dumps(data).encode("utf-8"))

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/status":
            self._json(200, JOB.snapshot())
        elif path == "/api/report":
            output = Path(JOB.snapshot()["output"])
            if not output.exists():
                self._json(404, {"error": "report not found"})
                return
            try:
                self._send(200, output.read_bytes())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            payload = {}
        if path == "/api/start":
            try:
                ok = JOB.start(payload)
                self._json(200, {"ok": ok, "error": None if ok else "analysis already running"})
            except Exception as exc:
                self._json(400, {"ok": False, "error": str(exc)})
        elif path == "/api/stop":
            JOB.stop()
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch MalString Emu Workbench GUI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"MalString Emu Workbench: {url}")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        JOB.stop()
        print("\nStopped")


if __name__ == "__main__":
    main()
