import re
from .store import get_trace

_PII_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "email address"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
]

_SLOW_THRESHOLD_MS = 5000
_MAX_TOOL_CALLS = 3


def evaluate(event: dict) -> dict:
    """Return {"flagged": bool, "reason": str | None} for a single event."""
    checks = [
        _check_pii(event),
        _check_slow(event),
        _check_tool_repetition(event),
    ]
    failures = [reason for flagged, reason in checks if flagged]
    if failures:
        return {"flagged": True, "reason": "; ".join(failures)}
    return {"flagged": False, "reason": None}


def _check_pii(event: dict) -> tuple[bool, str]:
    text = _extract_text(event.get("input")) + _extract_text(event.get("output"))
    for pattern, label in _PII_PATTERNS:
        if pattern.search(text):
            return True, f"PII detected: {label}"
    return False, ""


def _check_slow(event: dict) -> tuple[bool, str]:
    duration = event.get("duration_ms")
    if duration is not None and duration > _SLOW_THRESHOLD_MS:
        return True, f"slow event: {duration:.0f}ms > {_SLOW_THRESHOLD_MS}ms threshold"
    return False, ""


def _check_tool_repetition(event: dict) -> tuple[bool, str]:
    tool = event.get("tool")
    if not tool:
        return False, ""
    trace_id = event.get("trace_id")
    if not trace_id:
        return False, ""
    prior_events = get_trace(trace_id)
    call_count = sum(1 for e in prior_events if e.get("tool") == tool)
    if call_count >= _MAX_TOOL_CALLS:
        return True, f"tool '{tool}' called {call_count + 1} times in trace (max {_MAX_TOOL_CALLS})"
    return False, ""


def _extract_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
