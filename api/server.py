from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from monitor.store import get_events, get_trace, get_stats, get_flagged_events, get_traces, get_trace_rollup, count_events, clear_events
from monitor.risk import _ALLOWED_TOOLS, _STANDARDS, SEVERITY_ORDER
from agents.pipeline import run_pipeline
import os
import html
import json
import asyncio
import urllib.request

app = FastAPI(title="Agent Activity Monitor")
app.mount("/ui", StaticFiles(directory=Path(__file__).parent.parent / "ui"), name="ui")

@app.on_event("startup")
async def _startup():
    from monitor import tracer as _tracer
    import asyncio as _asyncio
    loop = _asyncio.get_event_loop()
    def _on_event(event: dict):
        _pipeline_state["current_agent"] = event["agent_name"]
        _pipeline_state["status"] = "running"
        _pipeline_state["aborted"] = event.get("action") == "block"
        if event.get("flagged"):
            asyncio.run_coroutine_threadsafe(
                _broadcast("flagged_event", {"agent": event["agent_name"], "severity": event.get("severity")}),
                loop,
            )
            _fire_webhooks(event)
        asyncio.run_coroutine_threadsafe(
            _broadcast("pipeline_state", {"agent": event["agent_name"], "aborted": _pipeline_state["aborted"]}),
            loop,
        )
    _tracer.set_event_hook(_on_event)

# SSE broadcast queue — all connected clients share updates
_sse_clients: list[asyncio.Queue] = []

def _fire_webhooks(event: dict):
    from monitor.risk import _POLICIES
    for p in _POLICIES:
        url = p.get("webhook_url")
        if not url or p.get("disabled"):
            continue
        if p["condition"] not in (event.get("flag_reason") or ""):
            continue
        payload = json.dumps({
            "policy": p["id"],
            "severity": event.get("severity"),
            "agent": event.get("agent_name"),
            "reason": event.get("flag_reason"),
            "trace_id": event.get("trace_id"),
        }).encode()
        try:
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass  # webhook failures are non-fatal


# Live pipeline state for graph visualization
_pipeline_state: dict = {"status": "idle", "current_agent": None, "last_trace": None, "aborted": False}

async def _broadcast(event_type: str, data: dict):
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    for q in list(_sse_clients):
        await q.put(payload)


class RunRequest(BaseModel):
    query: str


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent.parent / "ui" / "index.html").read_text()


@app.get("/events")
def events(limit: int = 100):
    return get_events(limit=limit)


@app.get("/events/rows", response_class=HTMLResponse)
def event_rows(limit: int = 25, offset: int = 0):
    rows = get_events(limit=limit)
    total = count_events()
    if not rows:
        return '<tr><td colspan="9" style="color:#444;padding:20px 10px;">No events yet — run a query above.</td></tr>'

    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    parts = []
    for e in rows:
        ts = e["timestamp"][:19].replace("T", " ")
        trace = e["trace_id"][:8] + "…"
        sev = e.get("severity")
        sev_color = _sev_colors.get(sev, "#52525b")
        sev_cell = f'<span style="color:{sev_color};font-weight:600">{sev}</span>' if sev else '<span class="flag-no">—</span>'
        flag_cell = (
            f'<span class="flag-yes">⚠ {html.escape(e["flag_reason"])}</span>'
            if e["flagged"]
            else '<span class="flag-no">—</span>'
        )
        action = e.get("action", "log")
        action_color = "#f87171" if action == "block" else "#52525b"
        action_cell = f'<span style="color:{action_color}">{action}</span>'
        dur = f'{e["duration_ms"]:.0f}ms' if e["duration_ms"] is not None else "—"
        standards = e.get("standards") or []
        std_cell = " ".join(f'<span class="standard">{html.escape(s)}</span>' for s in standards) or '<span class="flag-no">—</span>'
        parts.append(f"""
        <tr>
          <td class="ts">{ts}</td>
          <td class="trace-id">{trace}</td>
          <td class="agent">{html.escape(e['agent_name'])}</td>
          <td>{html.escape(e['event_type'])}</td>
          <td class="tool">{html.escape(e['tool'] or '—')}</td>
          <td class="ms">{dur}</td>
          <td>{sev_cell}</td>
          <td>{flag_cell}</td>
          <td>{std_cell}</td>
        </tr>""")
    # pagination row
    prev_btn = f'<button class="sev-btn" hx-get="/events/rows?offset={max(0,offset-limit)}&limit={limit}" hx-target="#feed" hx-swap="innerHTML">← prev</button>' if offset > 0 else ''
    next_btn = f'<button class="sev-btn" hx-get="/events/rows?offset={offset+limit}&limit={limit}" hx-target="#feed" hx-swap="innerHTML">next →</button>' if offset + limit < total else ''
    if prev_btn or next_btn:
        parts.append(f'<tr><td colspan="9" style="padding:10px 12px;border:none">{prev_btn} <span style="color:#3f3f46;font-size:0.75rem">{offset+1}–{min(offset+limit,total)} of {total}</span> {next_btn}</td></tr>')
    return "\n".join(parts)


@app.get("/events/violations", response_class=HTMLResponse)
def violation_rows(severity: str = ""):
    rows = get_flagged_events(severity=severity or None, limit=100)
    if not rows:
        return '<tr><td colspan="9" style="color:#444;padding:20px 10px;">No violations found.</td></tr>'
    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    parts = []
    for e in rows:
        ts = e["timestamp"][:19].replace("T", " ")
        trace = e["trace_id"][:8] + "…"
        sev = e.get("severity", "")
        sev_color = _sev_colors.get(sev, "#52525b")
        sev_cell = f'<span style="color:{sev_color};font-weight:600">{sev}</span>'
        action = e.get("action", "log")
        action_color = "#f87171" if action == "block" else "#52525b"
        standards = e.get("standards") or []
        std_cell = " ".join(f'<span class="standard">{html.escape(s)}</span>' for s in standards) or "—"
        inp = json.dumps(e.get("input") or {}, indent=2)
        out = json.dumps(e.get("output") or {}, indent=2)
        row_id = f"row-{e['id']}"
        parts.append(f"""
        <tr class="violation-row" onclick="toggleDetail('{row_id}')" style="cursor:pointer">
          <td class="ts">{ts}</td>
          <td class="trace-id">{trace}</td>
          <td class="agent">{html.escape(e['agent_name'])}</td>
          <td>{html.escape(e['event_type'])}</td>
          <td class="tool">{html.escape(e['tool'] or '—')}</td>
          <td class="ms">{(str(round(e["duration_ms"])) + "ms") if e["duration_ms"] else "—"}</td>
          <td>{sev_cell}</td>
          <td><span class="flag-yes">⚠ {html.escape(e["flag_reason"] or "")}</span></td>
          <td>{std_cell}</td>
        </tr>
        <tr id="{row_id}" class="detail-row" style="display:none">
          <td colspan="9">
            <div class="detail-box">
              <div class="detail-col"><div class="detail-label">input</div><pre>{html.escape(inp)}</pre></div>
              <div class="detail-col"><div class="detail-label">output</div><pre>{html.escape(out)}</pre></div>
            </div>
          </td>
        </tr>""")
    return "\n".join(parts)


@app.get("/traces/rows", response_class=HTMLResponse)
def trace_rows():
    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    traces = get_traces(limit=50)
    if not traces:
        return '<tr><td colspan="5" style="color:#444;padding:20px 10px;">No traces yet.</td></tr>'
    parts = []
    for t in traces:
        rollup = get_trace_rollup(t["trace_id"])
        sev = rollup.get("severity") or ""
        sev_color = _sev_colors.get(sev, "#3f3f46")
        sev_cell = f'<span style="color:{sev_color};font-weight:600">{sev}</span>' if sev else '<span class="flag-no">clean</span>'
        action = rollup.get("action", "log")
        action_color = "#f87171" if action == "block" else "#52525b"
        ts = t["started_at"][:19].replace("T", " ")
        tid = t["trace_id"]
        detail_id = f"tl-{tid[:8]}"
        parts.append(f"""
        <tr style="cursor:pointer" onclick="toggleTimeline('{detail_id}', '{tid}')">
          <td class="ts">{ts}</td>
          <td class="trace-id">{tid[:8]}…</td>
          <td class="ms">{t["event_count"]} events</td>
          <td>{sev_cell}</td>
          <td><span style="color:{action_color}">{action}</span></td>
        </tr>
        <tr id="{detail_id}" style="display:none"><td colspan="5" style="padding:0"></td></tr>""")
    return "\n".join(parts)


@app.get("/traces/{trace_id}/timeline", response_class=HTMLResponse)
def trace_timeline(trace_id: str):
    events = get_trace(trace_id)
    if not events:
        return f'<td colspan="5" style="color:#444;padding:12px">No events found for trace.</td>'
    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    _agent_colors = {"researcher": "#60a5fa", "summarizer": "#a78bfa"}

    # compute relative timeline positions
    from datetime import datetime, timezone
    times = [datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) for e in events]
    t0 = times[0]
    total_ms = max((t - t0).total_seconds() * 1000 for t in times) or 1
    # add each event's duration to get end time
    max_end = max(
        (t - t0).total_seconds() * 1000 + (e.get("duration_ms") or 0)
        for t, e in zip(times, events)
    ) or 1

    W, ROW_H, LABEL_W, PAD = 560, 32, 90, 16
    H = ROW_H * len(events) + PAD * 2
    bars = ""
    for i, (e, t) in enumerate(zip(events, times)):
        start_ms = (t - t0).total_seconds() * 1000
        dur = e.get("duration_ms") or 0
        x0 = LABEL_W + (start_ms / max_end) * (W - LABEL_W - PAD)
        bw = max((dur / max_end) * (W - LABEL_W - PAD), 4)
        y = PAD + i * ROW_H
        agent = e["agent_name"]
        color = _agent_colors.get(agent, "#60a5fa")
        flag_mark = ""
        if e.get("flagged"):
            sev = e.get("severity", "low")
            fc = _sev_colors.get(sev, "#f87171")
            flag_mark = f'<circle cx="{x0+bw+6}" cy="{y+ROW_H//2}" r="4" fill="{fc}"/>'
        bars += f'''
        <text x="{LABEL_W-6}" y="{y+ROW_H//2+4}" text-anchor="end" fill="#52525b" font-size="9" font-family="monospace">{html.escape(agent)}</text>
        <rect x="{x0}" y="{y+4}" width="{bw}" height="{ROW_H-10}" rx="3" fill="{color}" opacity="0.8"/>
        <text x="{x0+bw+14}" y="{y+ROW_H//2+4}" fill="#3f3f46" font-size="8" font-family="monospace">{dur:.0f}ms</text>
        {flag_mark}'''

    svg = f'''<svg viewBox="0 0 {W} {H}" width="{W}" height="{H}" xmlns="http://www.w3.org/2000/svg">
      <rect width="{W}" height="{H}" fill="#0d0d18"/>{bars}
    </svg>'''
    return f'<td colspan="5" style="padding:0;background:#0d0d18">{svg}</td>'


@app.get("/events/{trace_id}")
def trace(trace_id: str):
    events = get_trace(trace_id)
    if not events:
        raise HTTPException(status_code=404, detail="Trace not found")
    return events


@app.get("/posture")
def posture():
    model = "claude-haiku-4-5-20251001" if os.environ.get("ANTHROPIC_API_KEY") else "mock-llm"
    return {
        "agents": [
            {
                "name": "researcher",
                "allowed_tools": sorted(_ALLOWED_TOOLS.get("researcher", [])),
                "model": None,
                "enforcement": "abort pipeline on prompt injection",
            },
            {
                "name": "summarizer",
                "allowed_tools": sorted(_ALLOWED_TOOLS.get("summarizer", [])),
                "model": model,
                "enforcement": "flag unexpected tool usage",
            },
        ],
        "risk_standards": _STANDARDS,
    }


@app.get("/policies")
def get_policies():
    from monitor.risk import _POLICIES
    return _POLICIES

@app.post("/policies/{policy_id}/toggle", response_class=HTMLResponse)
def toggle_policy(policy_id: str):
    import yaml as _yaml
    from monitor import risk as _risk
    policies_path = Path(__file__).parent.parent / "monitor" / "policies.yaml"
    with open(policies_path) as f:
        data = _yaml.safe_load(f)
    for p in data["policies"]:
        if p["id"] == policy_id:
            p["disabled"] = not p.get("disabled", False)
    with open(policies_path, "w") as f:
        _yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    # hot-reload policies
    _risk._POLICIES = _risk._load_policies()
    return policies_panel()

@app.get("/policies/panel", response_class=HTMLResponse)
def policies_panel():
    from monitor.risk import _POLICIES
    _action_colors = {"block": "#f87171", "flag": "#facc15", "log": "#52525b"}
    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    rows = ""
    for p in _POLICIES:
        disabled = p.get("disabled", False)
        sev_color = _sev_colors.get(p["severity"], "#e4e4e7")
        act_color = _action_colors.get(p["action"], "#e4e4e7")
        opacity = "0.4" if disabled else "1"
        toggle_label = "enable" if disabled else "disable"
        rows += f"""
        <tr style="opacity:{opacity}">
          <td style="color:#e4e4e7">{html.escape(p['id'])}</td>
          <td style="color:{sev_color};font-weight:600">{p['severity']}</td>
          <td style="color:{act_color}">{p['action']}</td>
          <td style="color:#52525b">{', '.join(p.get('applies_to', ['all']))}</td>
          <td style="color:#71717a;font-size:0.75rem">{html.escape(p.get('description',''))}</td>
          <td>
            <button class="sev-btn" style="font-size:0.7rem;padding:2px 10px"
              hx-post="/policies/{html.escape(p['id'])}/toggle"
              hx-target="#policy-table"
              hx-swap="outerHTML">{toggle_label}</button>
          </td>
        </tr>"""
    return f"""
    <table id="policy-table" style="width:100%;border-collapse:collapse;font-size:0.78rem">
      <thead><tr>
        <th style="text-align:left;padding:6px 10px;color:#3f3f46;font-size:0.68rem;letter-spacing:.1em;text-transform:uppercase">id</th>
        <th style="text-align:left;padding:6px 10px;color:#3f3f46;font-size:0.68rem;letter-spacing:.1em;text-transform:uppercase">severity</th>
        <th style="text-align:left;padding:6px 10px;color:#3f3f46;font-size:0.68rem;letter-spacing:.1em;text-transform:uppercase">action</th>
        <th style="text-align:left;padding:6px 10px;color:#3f3f46;font-size:0.68rem;letter-spacing:.1em;text-transform:uppercase">applies to</th>
        <th style="text-align:left;padding:6px 10px;color:#3f3f46;font-size:0.68rem;letter-spacing:.1em;text-transform:uppercase">description</th>
        <th></th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>"""

@app.get("/posture/panel", response_class=HTMLResponse)
def posture_panel():
    model = "claude-haiku-4-5-20251001" if os.environ.get("ANTHROPIC_API_KEY") else "mock-llm"
    agents = [
        {"name": "researcher", "model": "—", "enforcement": "abort on prompt injection"},
        {"name": "summarizer", "model": model, "enforcement": "flag unexpected tool"},
    ]
    cards = ""
    for a in agents:
        allowed = ", ".join(sorted(_ALLOWED_TOOLS.get(a["name"], [])))
        cards += f"""
        <div class="agent-card">
          <h3>{html.escape(a['name'])}</h3>
          <div class="posture-row"><span class="posture-label">allowed tools</span><span class="posture-value green">{html.escape(allowed)}</span></div>
          <div class="posture-row"><span class="posture-label">model</span><span class="posture-value">{html.escape(a['model'])}</span></div>
          <div class="posture-row"><span class="posture-label">enforcement</span><span class="posture-value purple">{html.escape(a['enforcement'])}</span></div>
        </div>"""

    std_rows = "".join(
        f'<tr><td style="padding:6px 12px;color:#52525b">{html.escape(rule)}</td>'
        f'<td style="padding:6px 12px;color:#a78bfa">{html.escape(ref)}</td></tr>'
        for rule, ref in _STANDARDS.items()
    )
    pol_panel = policies_panel()
    return f"""
    <div class="posture-grid">{cards}</div>
    <table class="standards-table" style="margin-bottom:32px">
      <thead><tr><th>rule</th><th>standard</th></tr></thead>
      <tbody>{std_rows}</tbody>
    </table>
    <div style="font-size:0.7rem;letter-spacing:0.1em;text-transform:uppercase;color:#3f3f46;margin-bottom:12px">policies</div>
    {pol_panel}"""


@app.get("/export/violations.json")
def export_json(severity: str = ""):
    rows = get_flagged_events(severity=severity or None, limit=10000)
    content = json.dumps(rows, default=str, indent=2)
    return Response(content, media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=violations.json"})

@app.get("/export/violations.csv")
def export_csv(severity: str = ""):
    import csv, io
    rows = get_flagged_events(severity=severity or None, limit=10000)
    buf = io.StringIO()
    fields = ["timestamp", "trace_id", "agent_name", "event_type", "tool", "duration_ms", "severity", "flag_reason", "action"]
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=violations.csv"})

@app.get("/stats/panel", response_class=HTMLResponse)
def stats_panel():
    s = get_stats()
    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    sev_rows_parts = []
    for sev in ["critical", "high", "medium", "low"]:
        count = s["by_severity"].get(sev, 0)
        color = _sev_colors.get(sev, "#e4e4e7")
        sev_rows_parts.append(
            f'<div class="posture-row"><span class="posture-label">{sev}</span>'
            f'<span class="posture-value" style="color:{color}">{count}</span></div>'
        )
    sev_rows = "".join(sev_rows_parts)
    agent_rows = "".join(
        f'<div class="posture-row"><span class="posture-label">{html.escape(agent)}</span>'
        f'<span class="posture-value">{count}</span></div>'
        for agent, count in s["by_agent"].items()
    )
    pct = f'{s["flagged_events"] / s["total_events"] * 100:.0f}%' if s["total_events"] else "0%"
    return f"""
    <div class="posture-grid">
      <div class="agent-card">
        <h3>overview</h3>
        <div class="posture-row"><span class="posture-label">total events</span><span class="posture-value">{s['total_events']}</span></div>
        <div class="posture-row"><span class="posture-label">flagged</span><span class="posture-value" style="color:#f87171">{s['flagged_events']} ({pct})</span></div>
        <div class="posture-row"><span class="posture-label">blocked</span><span class="posture-value" style="color:#f87171">{s['blocked_events']}</span></div>
      </div>
      <div class="agent-card">
        <h3>by severity</h3>
        {sev_rows or '<span style="color:#3f3f46">no flags yet</span>'}
      </div>
      <div class="agent-card">
        <h3>flags by agent</h3>
        {agent_rows or '<span style="color:#3f3f46">no flags yet</span>'}
      </div>
    </div>"""


@app.get("/stream")
async def stream(request: Request):
    queue: asyncio.Queue = asyncio.Queue()
    _sse_clients.append(queue)
    async def generate():
        try:
            yield "data: connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            _sse_clients.remove(queue)
    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/graph/panel", response_class=HTMLResponse)
def graph_panel():
    s = _pipeline_state
    def node_color(agent):
        if s["status"] == "idle" or s["current_agent"] is None:
            return "#27272a"
        if s["aborted"] and s["current_agent"] == agent:
            return "#7f1d1d"
        if s["current_agent"] == agent:
            return "#1e3a5f"
        agents = ["researcher", "summarizer"]
        cur_idx = agents.index(s["current_agent"]) if s["current_agent"] in agents else -1
        this_idx = agents.index(agent) if agent in agents else -1
        if this_idx < cur_idx:
            return "#14532d"
        return "#27272a"

    def node_label_color(agent):
        if s["status"] == "idle":
            return "#52525b"
        if s["aborted"] and s["current_agent"] == agent:
            return "#f87171"
        if s["current_agent"] == agent:
            return "#60a5fa"
        agents = ["researcher", "summarizer"]
        cur_idx = agents.index(s["current_agent"]) if s["current_agent"] in agents else -1
        this_idx = agents.index(agent) if agent in agents else -1
        if this_idx < cur_idx:
            return "#86efac"
        return "#52525b"

    def status_dot(agent):
        if s["aborted"] and s["current_agent"] == agent:
            return "⊗"
        if s["current_agent"] == agent and s["status"] == "running":
            return "●"
        agents = ["researcher", "summarizer"]
        cur_idx = agents.index(s["current_agent"]) if s["current_agent"] in agents else -1
        this_idx = agents.index(agent) if agent in agents else -1
        if this_idx < cur_idx:
            return "✓"
        return "○"

    edge_color = "#f87171" if s["aborted"] else ("#3b82f6" if s["status"] == "running" else "#27272a")
    status_text = "idle"
    if s["status"] == "running":
        status_text = f"blocked — {s['current_agent']}" if s["aborted"] else f"running — {s['current_agent']}"

    is_running = s["status"] == "running" and not s["aborted"]
    r_pulse = 'class="pulse-node"' if is_running and s["current_agent"] == "researcher" else ""
    s_pulse = 'class="pulse-node"' if is_running and s["current_agent"] == "summarizer" else ""

    return f"""
    <style>
      @keyframes pulse {{
        0%   {{ filter: drop-shadow(0 0 3px #3b82f6); opacity: 1; }}
        50%  {{ filter: drop-shadow(0 0 10px #3b82f6); opacity: 0.85; }}
        100% {{ filter: drop-shadow(0 0 3px #3b82f6); opacity: 1; }}
      }}
      .pulse-node {{ animation: pulse 1s ease-in-out infinite; }}
    </style>
    <div style="text-align:center;padding:32px 0 8px">
      <svg viewBox="0 0 520 140" width="520" height="140" xmlns="http://www.w3.org/2000/svg" style="font-family:'SF Mono',monospace">
        <!-- researcher node -->
        <g {r_pulse}>
          <rect x="30" y="40" width="160" height="60" rx="8" fill="{node_color("researcher")}" stroke="{node_label_color("researcher")}" stroke-width="1.5"/>
          <text x="110" y="67" text-anchor="middle" fill="{node_label_color("researcher")}" font-size="11" letter-spacing="1">{status_dot("researcher")} researcher</text>
          <text x="110" y="86" text-anchor="middle" fill="#52525b" font-size="9">tool: search</text>
        </g>

        <!-- arrow -->
        <line x1="190" y1="70" x2="330" y2="70" stroke="{edge_color}" stroke-width="1.5" marker-end="url(#arrow)"/>
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="{edge_color}"/>
          </marker>
        </defs>

        <!-- summarizer node -->
        <g {s_pulse}>
          <rect x="330" y="40" width="160" height="60" rx="8" fill="{node_color("summarizer")}" stroke="{node_label_color("summarizer")}" stroke-width="1.5"/>
          <text x="410" y="67" text-anchor="middle" fill="{node_label_color("summarizer")}" font-size="11" letter-spacing="1">{status_dot("summarizer")} summarizer</text>
          <text x="410" y="86" text-anchor="middle" fill="#52525b" font-size="9">tool: llm</text>
        </g>

        <!-- status label -->
        <text x="260" y="128" text-anchor="middle" fill="#3f3f46" font-size="9" letter-spacing="1">{status_text}</text>
      </svg>
    </div>"""


@app.post("/clear", response_class=HTMLResponse)
async def clear_db():
    clear_events()
    await _broadcast("trace_complete", {})
    return '<span style="color:#86efac">✓ events cleared</span>'


@app.post("/run")
async def run(req: RunRequest):
    _pipeline_state.update({"status": "running", "current_agent": "researcher", "aborted": False})
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, run_pipeline, req.query)
    _pipeline_state.update({"status": "idle", "current_agent": None, "last_trace": result["trace_id"]})
    await _broadcast("trace_complete", {"trace_id": result["trace_id"], "summary": result["summary"]})
    await _broadcast("pipeline_state", {"status": "idle"})
    return result
