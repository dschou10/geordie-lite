# Agent Activity Monitor

A small multi-agent system with a real-time observability and risk layer built on top of it.

Two agents collaborate to answer a research query. Every action they take — tool calls, LLM invocations, inputs and outputs — is captured as a structured trace event, evaluated against risk rules, and displayed in a live web UI.

![Architecture](https://placeholder)

## What it does

- **Researcher agent** takes a query and calls a search tool
- **Summarizer agent** takes the search results and produces a concise summary
- **Monitor layer** captures every agent action as a timestamped span with: agent name, event type, tool used, input/output, duration, and a risk verdict
- **Risk rules** flag events that look anomalous:
  - PII detected in inputs or outputs (email addresses, SSNs)
  - Slow events exceeding 5000ms
  - Repeated tool calls within the same trace (>3 calls to the same tool)
- **Live UI** polls for new events every 2 seconds and displays them in a feed with risk flags highlighted

## Architecture

```
agents/
  pipeline.py      LangGraph graph: researcher → summarizer
  researcher.py    Calls a search tool, emits a trace event
  summarizer.py    Calls an LLM, emits a trace event

monitor/
  tracer.py        Single emit() function agents call to record a span
  store.py         SQLite-backed event persistence
  risk.py          Policy rules evaluated against each event

api/
  server.py        FastAPI: serves the UI and exposes /events, /run

ui/
  index.html       HTMX live feed — polls /events/rows every 2s

tests/
  test_store.py    Persistence layer tests
  test_risk.py     Risk rule tests
  test_tracer.py   Tracer integration tests
```

The monitor layer is intentionally decoupled from the agents — agents call `tracer.emit()` and know nothing about storage or risk evaluation. This makes it easy to add new agents, new risk rules, or swap the storage backend independently.

## Running locally

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python -m uvicorn api.server:app --reload --port 8123
```

Open http://localhost:8123, type a query, and hit Run. The event feed updates live.

To use real Claude instead of the mock LLM, set your API key:
```bash
export ANTHROPIC_API_KEY=your-key-here
```

## Running tests

```bash
python -m pytest tests/ -v
```

Tests use an isolated in-memory SQLite database via `tmp_path` fixtures — no cleanup needed between runs.

## Deploying to Render

The `render.yaml` at the project root configures a Render web service. To deploy:

1. Push this repo to GitHub
2. Create a new Web Service on [render.com](https://render.com) and connect the repo
3. Render detects `render.yaml` automatically — hit Deploy
4. Optionally set `ANTHROPIC_API_KEY` in the Render environment dashboard to enable real LLM calls

## Design decisions

**SQLite over Postgres** — sufficient for a single-instance demo, zero configuration, and keeps the dependency count low. The store module is the only place that knows about the database, so swapping backends is a one-file change.

**HTMX over a JS framework** — the UI only needs to poll and render a table. HTMX handles this with HTML attributes and no build step, keeping the frontend minimal and the interesting code in the backend where it belongs.

**Mock LLM by default** — the pipeline runs without any API key. Swapping in real Claude is an environment variable, not a code change.

**Risk rules as pure functions** — each rule in `monitor/risk.py` is a separate function returning `(flagged, reason)`. Adding a new rule means adding one function and one test, with no changes to the calling code.
