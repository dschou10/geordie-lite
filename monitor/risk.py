import re
from .store import get_trace

_PII_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "email address"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
]

_SLOW_THRESHOLD_MS = 5000
_MAX_TOOL_CALLS = 3

_INJECTION_PATTERNS = re.compile(
    r"ignore (previous|prior|all) instructions?|"
    r"disregard (previous|prior|all)|"
    r"you are now|"
    r"new persona|"
    r"jailbreak|"
    r"do anything now|"
    r"DAN\b|"
    r"system prompt",
    re.IGNORECASE,
)

# Which tools each agent is permitted to call
_ALLOWED_TOOLS: dict[str, set[str]] = {
    "researcher": {"search"},
    "summarizer": {"mock-llm", "claude-haiku-4-5-20251001"},
}


def evaluate(event: dict) -> dict:
    """Return {"flagged": bool, "reason": str | None} for a single event."""
    checks = [
        _check_pii(event),
        _check_slow(event),
        _check_tool_repetition(event),
        _check_prompt_injection(event),
        _check_unexpected_tool(event),
        _check_ungrounded_output(event),
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


def _check_prompt_injection(event: dict) -> tuple[bool, str]:
    input_text = _extract_text(event.get("input"))
    if _INJECTION_PATTERNS.search(input_text):
        return True, "prompt injection attempt detected in input"
    return False, ""


def _check_unexpected_tool(event: dict) -> tuple[bool, str]:
    tool = event.get("tool")
    agent = event.get("agent_name")
    if not tool or not agent:
        return False, ""
    allowed = _ALLOWED_TOOLS.get(agent)
    if allowed is not None and tool not in allowed:
        return True, f"unexpected tool '{tool}' for agent '{agent}'"
    return False, ""


def _check_ungrounded_output(event: dict) -> tuple[bool, str]:
    """Flag summarizer output that contains named entities not present in its input."""
    if event.get("agent_name") != "summarizer" or event.get("event_type") != "llm_call":
        return False, ""
    input_val = event.get("input") or {}
    results = input_val.get("results", [])
    input_text = " ".join(_extract_text(r) for r in results).lower()
    output_text = _extract_text((event.get("output") or {}).get("summary", "")).lower()
    # Look for capitalised words (likely named entities) in output absent from input
    named_entities = re.findall(r"\b[A-Z][a-z]{2,}\b", _extract_text((event.get("output") or {}).get("summary", "")))
    ungrounded = [w for w in named_entities if w.lower() not in input_text]
    if ungrounded:
        sample = ", ".join(sorted(set(ungrounded))[:3])
        return True, f"ungrounded output: terms not in source ({sample})"
    return False, ""


def _extract_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)
