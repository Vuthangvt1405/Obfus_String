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
@media(max-width:900px){.grid{grid-template-columns:1fr}.setup{position:static}.summary{grid-template-columns:1fr 1fr}.top{align-items:start;flex-direction:column}}
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
      <div class="actions"><button class="primary" onclick="startAnalysis()">Start</button><button class="danger" onclick="stopAnalysis()">Stop</button></div>
      <p class="muted">Run only in an isolated malware lab. Behavior is best-effort and path-limited.</p>
    </aside>
    <main class="card">
      <div class="tabs"><button class="tab active" data-tab="overview" onclick="showTab('overview')">Overview</button><button class="tab" data-tab="logs" onclick="showTab('logs')">Live logs</button><button class="tab" data-tab="strings" onclick="showTab('strings')">Strings</button><button class="tab" data-tab="behavior" onclick="showTab('behavior')">Behavior</button></div>
      <section id="overview" class="view active"><div class="summary"><div class="metric"><b id="mStrings">0</b><span>strings</span></div><div class="metric"><b id="mEvents">0</b><span>behavior events</span></div><div class="metric"><b id="mRisk">0</b><span>risk score</span></div><div class="metric"><b id="mVerdict">n/a</b><span>verdict</span></div></div><div id="summary" class="behaviorText">No report loaded yet.</div></section>
      <section id="logs" class="view"><pre id="log" class="log"></pre></section>
      <section id="strings" class="view"><div class="toolbar"><input id="stringSearch" placeholder="Search strings" oninput="renderStrings()"><select id="sourceFilter" onchange="renderStrings()"><option>All sources</option></select><button onclick="exportCsv()">Export CSV</button></div><div class="tablewrap"><table><thead><tr><th>String</th><th>Source</th><th>Tags</th><th>Encoding</th><th>Confidence</th></tr></thead><tbody id="stringsBody"></tbody></table></div></section>
      <section id="behavior" class="view"><div id="behaviorText" class="behaviorText">No behavior report loaded yet.</div><div class="toolbar"><input id="behaviorSearch" placeholder="Search behavior" oninput="renderBehavior()"></div><div class="tablewrap"><table><thead><tr><th>Category</th><th>Description</th><th>Indicators</th><th>Confidence</th><th>Source</th></tr></thead><tbody id="behaviorBody"></tbody></table></div></section>
    </main>
  </div>
</div>
<script>
let report=null, strings=[], events=[];
function el(id){return document.getElementById(id)}
function showTab(id){document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',b.dataset.tab===id));document.querySelectorAll('.view').forEach(v=>v.classList.toggle('active',v.id===id))}
async function startAnalysis(){
  const payload={file:el('file').value,output:el('output').value,arch:el('arch').value,timeout:el('timeout').value,max_instructions:el('maxInstructions').value,min_confidence:el('minConfidence').value,clean_output:el('cleanOutput').checked};
  const r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}); const j=await r.json(); if(!j.ok) alert(j.error||'Could not start');
}
async function stopAnalysis(){await fetch('/api/stop',{method:'POST'});}
async function poll(){
  const s=await (await fetch('/api/status')).json(); el('status').textContent=s.status; el('log').textContent=s.logs||''; el('log').scrollTop=el('log').scrollHeight;
  if(s.status==='completed'||s.status==='failed'){loadReport();}
}
async function loadReport(){try{const r=await fetch('/api/report'); if(!r.ok)return; report=await r.json(); strings=report.strings||[]; const b=report.behavior||{}; events=b.events||[]; renderAll();}catch(e){}}
function renderAll(){const b=report.behavior||{}; el('mStrings').textContent=report.total_strings||strings.length; el('mEvents').textContent=events.length; el('mRisk').textContent=b.risk_score??0; el('mVerdict').textContent=b.verdict||'n/a'; el('mRisk').className='risk-'+(b.verdict||'low'); el('summary').innerHTML=(b.summary||[]).map(x=>'<div>- '+escapeHtml(x)+'</div>').join('')||'No behavior summary.'; renderSourceFilter(); renderStrings(); renderBehavior();}
function renderSourceFilter(){const old=el('sourceFilter').value; const vals=['All sources',...new Set(strings.map(s=>s.source).filter(Boolean).sort())]; el('sourceFilter').innerHTML=vals.map(v=>`<option>${escapeHtml(v)}</option>`).join(''); el('sourceFilter').value=vals.includes(old)?old:'All sources';}
function renderStrings(){const q=el('stringSearch').value.toLowerCase(), src=el('sourceFilter').value; el('stringsBody').innerHTML=strings.filter(s=>(src==='All sources'||s.source===src)&&JSON.stringify(s).toLowerCase().includes(q)).map(s=>`<tr><td>${escapeHtml(s.content||'')}</td><td>${escapeHtml(s.source||'')}</td><td>${(s.tags||[]).map(t=>`<span class="pill">${escapeHtml(t)}</span>`).join('')}</td><td>${escapeHtml(s.encoding||'')}</td><td>${escapeHtml(String(s.confidence??''))}</td></tr>`).join('');}
function renderBehavior(){const b=report?.behavior||{}; const iocs=b.iocs||{}; el('behaviorText').innerHTML='<b>Summary</b><br>'+(b.summary||[]).map(x=>'- '+escapeHtml(x)).join('<br>')+'<br><br><b>IOCs</b><br>'+Object.entries(iocs).filter(([k,v])=>v&&v.length).map(([k,v])=>`${escapeHtml(k)}: ${escapeHtml(v.slice(0,10).join(', '))}`).join('<br>'); const q=el('behaviorSearch').value.toLowerCase(); el('behaviorBody').innerHTML=events.filter(e=>JSON.stringify(e).toLowerCase().includes(q)).map(e=>`<tr><td>${escapeHtml(e.category||'')}</td><td>${escapeHtml(e.description||'')}</td><td>${escapeHtml((e.indicators||[]).join(', '))}</td><td>${escapeHtml(String(e.confidence??''))}</td><td>${escapeHtml(e.source||'')}</td></tr>`).join('');}
function exportCsv(){let rows=[['content','source','tags','encoding','confidence'],...strings.map(s=>[s.content||'',s.source||'',(s.tags||[]).join('|'),s.encoding||'',s.confidence??''])]; let csv=rows.map(r=>r.map(v=>'"'+String(v).replaceAll('"','""')+'"').join(',')).join('\n'); let a=document.createElement('a'); a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); a.download='strings.csv'; a.click();}
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
