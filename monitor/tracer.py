from datetime import datetime, timezone
from typing import Optional, Callable

from . import risk, store

store.init_db()

# Optional hook called after each event is stored. Set by the API layer.
_on_event: Optional[Callable[[dict], None]] = None

def set_event_hook(fn: Callable[[dict], None]) -> None:
    global _on_event
    _on_event = fn


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
    event["severity"] = verdict.get("severity")
    event["action"] = verdict.get("action", "log")
    event["standards"] = verdict.get("standards", [])
    store.insert_event(event)
    if _on_event:
        _on_event(event)
    return event
