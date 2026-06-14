from datetime import datetime, timezone
from typing import Optional
from . import risk, store

store.init_db()


def emit(
    *,
    trace_id: str,
    agent_name: str,
    event_type: str,
    tool: Optional[str] = None,
    input: Optional[dict] = None,
    output: Optional[dict] = None,
    duration_ms: Optional[float] = None,
) -> dict:
    event = {
        "trace_id":    trace_id,
        "agent_name":  agent_name,
        "event_type":  event_type,
        "tool":        tool,
        "input":       input,
        "output":      output,
        "duration_ms": duration_ms,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }
    verdict = risk.evaluate(event)
    event["flagged"] = verdict["flagged"]
    event["flag_reason"] = verdict["reason"]
    store.insert_event(event)
    return event
