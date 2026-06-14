from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from monitor.store import get_events, get_trace
from agents.pipeline import run_pipeline
import html
import os

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
        return '<tr><td colspan="7" style="color:#444;padding:20px 10px;">No events yet — run a query above.</td></tr>'
    parts = []
    for e in rows:
        ts = e["timestamp"][:19].replace("T", " ")
        trace = e["trace_id"][:8] + "…"
        flag_cell = (
            f'<span class="flag-yes">⚠ {html.escape(e["flag_reason"])}</span>'
            if e["flagged"]
            else '<span class="flag-no">—</span>'
        )
        dur = f'{e["duration_ms"]:.0f}ms' if e["duration_ms"] is not None else "—"
        parts.append(f"""
        <tr>
          <td class="ts">{ts}</td>
          <td class="trace-id">{trace}</td>
          <td class="agent">{html.escape(e['agent_name'])}</td>
          <td>{html.escape(e['event_type'])}</td>
          <td class="tool">{html.escape(e['tool'] or '—')}</td>
          <td class="ms">{dur}</td>
          <td>{flag_cell}</td>
        </tr>""")
    return "\n".join(parts)


@app.get("/events/{trace_id}")
def trace(trace_id: str):
    events = get_trace(trace_id)
    if not events:
        raise HTTPException(status_code=404, detail="Trace not found")
    return events


@app.post("/run")
def run(req: RunRequest):
    result = run_pipeline(req.query)
    return result
