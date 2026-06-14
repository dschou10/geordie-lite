from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from monitor.store import get_events, get_trace, get_stats
from monitor.risk import _ALLOWED_TOOLS, _STANDARDS
from agents.pipeline import run_pipeline
import os
import html

app = FastAPI(title="Agent Activity Monitor")
app.mount("/ui", StaticFiles(directory=Path(__file__).parent.parent / "ui"), name="ui")


class RunRequest(BaseModel):
    query: str


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent.parent / "ui" / "index.html").read_text()


@app.get("/events")
def events(limit: int = 100):
    return get_events(limit=limit)


@app.get("/events/rows", response_class=HTMLResponse)
def event_rows(limit: int = 100):
    rows = get_events(limit=limit)
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
    return "\n".join(parts)


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
    return f"""
    <div class="posture-grid">{cards}</div>
    <table class="standards-table">
      <thead><tr><th>rule</th><th>standard</th></tr></thead>
      <tbody>{std_rows}</tbody>
    </table>"""


@app.get("/stats/panel", response_class=HTMLResponse)
def stats_panel():
    s = get_stats()
    _sev_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#facc15", "low": "#86efac"}
    sev_rows = "".join(
        f'<div class="posture-row"><span class="posture-label">{sev}</span>'
        f'<span class="posture-value" style="color:{_sev_colors.get(sev,\"#e4e4e7\")}">{count}</span></div>'
        for sev in ["critical", "high", "medium", "low"]
        if (count := s["by_severity"].get(sev, 0)) is not None
    )
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


@app.post("/run")
def run(req: RunRequest):
    result = run_pipeline(req.query)
    return result
