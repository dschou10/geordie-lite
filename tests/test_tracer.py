import pytest
from monitor import store as store_mod
from monitor.store import init_db, get_events, get_trace
from monitor import tracer


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store_mod, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr("monitor.risk.get_trace", store_mod.get_trace)
    init_db()


def test_emit_writes_to_store():
    tracer.emit(
        trace_id="t1",
        agent_name="researcher",
        event_type="tool_call",
        tool="search",
        input={"query": "hello"},
        output={"results": ["a"]},
        duration_ms=50.0,
    )
    events = get_events()
    assert len(events) == 1
    assert events[0]["agent_name"] == "researcher"
    assert events[0]["tool"] == "search"


def test_emit_returns_event_with_risk_verdict():
    event = tracer.emit(
        trace_id="t1",
        agent_name="researcher",
        event_type="tool_call",
        tool="search",
        input={"query": "contact user@example.com"},
        duration_ms=50.0,
    )
    assert event["flagged"] is True
    assert "email" in event["flag_reason"]


def test_emit_adds_timestamp():
    event = tracer.emit(
        trace_id="t1",
        agent_name="summarizer",
        event_type="llm_call",
    )
    assert "timestamp" in event
    assert event["timestamp"]


def test_emit_clean_event_not_flagged():
    event = tracer.emit(
        trace_id="t1",
        agent_name="researcher",
        event_type="tool_call",
        tool="search",
        input={"query": "latest AI research"},
        duration_ms=200.0,
    )
    assert event["flagged"] is False
    assert event["flag_reason"] is None
