import pytest
from datetime import datetime, timezone
from monitor.store import init_db, insert_event, get_events, get_trace


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr("monitor.store.DB_PATH", tmp_path / "test.db")
    init_db()


def _event(**overrides) -> dict:
    base = {
        "trace_id":    "trace-1",
        "agent_name":  "researcher",
        "event_type":  "tool_call",
        "tool":        "search",
        "input":       {"query": "hello"},
        "output":      {"results": ["a", "b"]},
        "duration_ms": 120.5,
        "flagged":     False,
        "flag_reason": None,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }
    return {**base, **overrides}


def test_insert_and_get_events():
    insert_event(_event(trace_id="trace-1"))
    insert_event(_event(trace_id="trace-2"))
    events = get_events()
    assert len(events) == 2


def test_get_events_newest_first():
    insert_event(_event(trace_id="trace-1"))
    insert_event(_event(trace_id="trace-2"))
    events = get_events()
    assert events[0]["trace_id"] == "trace-2"


def test_get_trace_filters_by_trace_id():
    insert_event(_event(trace_id="trace-1"))
    insert_event(_event(trace_id="trace-2"))
    events = get_trace("trace-1")
    assert len(events) == 1
    assert events[0]["trace_id"] == "trace-1"


def test_get_trace_ordered_by_id_asc():
    insert_event(_event(trace_id="trace-1", tool="search"))
    insert_event(_event(trace_id="trace-1", tool="fetch"))
    events = get_trace("trace-1")
    assert events[0]["tool"] == "search"
    assert events[1]["tool"] == "fetch"


def test_flagged_stored_as_bool():
    insert_event(_event(flagged=True, flag_reason="PII detected: email address"))
    events = get_events()
    assert events[0]["flagged"] is True


def test_json_fields_roundtrip():
    payload = {"query": "test", "nested": {"key": [1, 2, 3]}}
    insert_event(_event(input=payload))
    events = get_events()
    assert events[0]["input"] == payload


def test_get_events_limit():
    for i in range(5):
        insert_event(_event(trace_id=f"trace-{i}"))
    events = get_events(limit=3)
    assert len(events) == 3
