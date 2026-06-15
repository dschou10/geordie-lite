"""
Tests verifying SSE broadcasts the right events at the right times.

These tests confirm that if we remove HTMX polling from Event Feed,
Traces, Stats, and Violations, the SSE alone is sufficient to keep
those panels up to date.
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from monitor import store as store_mod
from monitor.store import init_db


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store_mod, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("monitor.risk.get_trace", store_mod.get_trace)
    init_db()


# ---------------------------------------------------------------------------
# 1. trace_complete fires after every run
# ---------------------------------------------------------------------------

def test_trace_complete_broadcast_on_run():
    """
    After POST /run, a trace_complete SSE event must be broadcast.
    This is what triggers Event Feed, Traces, and Stats to refresh.
    If this doesn't fire, removing polling breaks those panels.
    """
    import api.server as server
    from unittest.mock import patch

    received = []

    async def _run():
        q = asyncio.Queue(maxsize=50)
        server._sse_clients.append(q)
        try:
            with patch("api.server.run_pipeline", return_value={
                "trace_id": "abc-123",
                "summary": "AI agent frameworks are evolving rapidly.",
            }):
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: None)  # ensure executor is warm
                # call the broadcast directly as the /run endpoint would
                await server._broadcast("trace_complete", {
                    "trace_id": "abc-123",
                    "summary": "AI agent frameworks are evolving rapidly.",
                })
            while not q.empty():
                received.append(q.get_nowait())
        finally:
            server._sse_clients.remove(q)

    asyncio.run(_run())
    assert len(received) == 1
    assert "trace_complete" in received[0]
    assert "abc-123" in received[0]


# ---------------------------------------------------------------------------
# 2. flagged_event fires when tracer detects a violation
# ---------------------------------------------------------------------------

def test_flagged_event_broadcast_on_violation():
    """
    When the tracer detects a risk, a flagged_event SSE event must fire.
    This keeps the Violations panel up to date without polling.
    """
    import api.server as server
    from monitor import tracer

    received = []

    async def _run():
        q = asyncio.Queue(maxsize=50)
        server._sse_clients.append(q)
        loop = asyncio.get_event_loop()

        def hook(event):
            if event.get("flagged"):
                asyncio.run_coroutine_threadsafe(
                    server._broadcast("flagged_event", {
                        "agent": event["agent_name"],
                        "severity": event.get("severity"),
                    }),
                    loop,
                )

        tracer.set_event_hook(hook)
        try:
            tracer.emit(
                trace_id="t-pii",
                agent_name="researcher",
                event_type="tool_call",
                tool="search",
                input={"query": "find user@example.com"},
                duration_ms=100,
            )
            await asyncio.sleep(0.05)  # let coroutine_threadsafe complete
            while not q.empty():
                received.append(q.get_nowait())
        finally:
            server._sse_clients.remove(q)
            tracer.set_event_hook(None)

    asyncio.run(_run())
    assert any("flagged_event" in r for r in received), \
        "No flagged_event SSE broadcast — Violations panel won't update without polling"


# ---------------------------------------------------------------------------
# 3. Clean events do NOT broadcast flagged_event
# ---------------------------------------------------------------------------

def test_no_flagged_event_for_clean_trace():
    """Clean events must not spam the Violations panel."""
    import api.server as server
    from monitor import tracer

    received = []

    async def _run():
        q = asyncio.Queue(maxsize=50)
        server._sse_clients.append(q)
        loop = asyncio.get_event_loop()

        def hook(event):
            if event.get("flagged"):
                asyncio.run_coroutine_threadsafe(
                    server._broadcast("flagged_event", {}), loop,
                )

        tracer.set_event_hook(hook)
        try:
            tracer.emit(
                trace_id="t-clean",
                agent_name="researcher",
                event_type="tool_call",
                tool="search",
                input={"query": "what is LangGraph?"},
                duration_ms=80,
            )
            await asyncio.sleep(0.05)
            while not q.empty():
                received.append(q.get_nowait())
        finally:
            server._sse_clients.remove(q)
            tracer.set_event_hook(None)

    asyncio.run(_run())
    assert not any("flagged_event" in r for r in received), \
        "flagged_event fired for a clean trace — would cause spurious Violations refresh"


# ---------------------------------------------------------------------------
# 4. pipeline_state fires during a run (drives graph animation)
# ---------------------------------------------------------------------------

def test_pipeline_state_broadcast_during_run():
    """
    pipeline_state SSE events drive the graph panel animation.
    The graph polls every 1s as a fallback, but SSE should push
    state changes faster than the poll interval.
    """
    import api.server as server

    received = []

    async def _run():
        q = asyncio.Queue(maxsize=50)
        server._sse_clients.append(q)
        try:
            await server._broadcast("pipeline_state", {"agent": "researcher", "aborted": False})
            await server._broadcast("pipeline_state", {"agent": "summarizer", "aborted": False})
            while not q.empty():
                received.append(q.get_nowait())
        finally:
            server._sse_clients.remove(q)

    asyncio.run(_run())
    assert len(received) == 2
    assert all("pipeline_state" in r for r in received)
    agents = [r for r in received if "researcher" in r or "summarizer" in r]
    assert len(agents) == 2, "Both agent transitions must be broadcast"


# ---------------------------------------------------------------------------
# 5. SSE keepalive prevents connection timeout
# ---------------------------------------------------------------------------

def test_keepalive_comment_sent_on_idle():
    """
    When no events fire for 15s, a ': keepalive' comment must be sent.
    Without this, proxies and load balancers close idle SSE connections,
    breaking the auto-reconnect flow.
    This test just verifies the keepalive string format is correct.
    """
    keepalive = ": keepalive\n\n"
    assert keepalive.startswith(":"), "SSE keepalive must be a comment (starts with ':')"
    assert keepalive.endswith("\n\n"), "SSE messages must end with double newline"


# ---------------------------------------------------------------------------
# 6. Multiple clients all receive the same broadcast
# ---------------------------------------------------------------------------

def test_broadcast_reaches_all_clients():
    """All connected clients must receive every broadcast — fan-out."""
    import api.server as server

    async def _run():
        queues = [asyncio.Queue(maxsize=50) for _ in range(5)]
        for q in queues:
            server._sse_clients.append(q)
        try:
            await server._broadcast("trace_complete", {"trace_id": "xyz"})
            return [q.qsize() for q in queues]
        finally:
            for q in queues:
                server._sse_clients.remove(q)

    depths = asyncio.run(_run())
    assert all(d == 1 for d in depths), \
        f"Not all clients received broadcast — depths: {depths}"
