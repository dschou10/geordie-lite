import re
import yaml
from pathlib import Path
from .store import get_trace, get_baseline

# --- Config ---

_POLICIES_PATH = Path(__file__).parent / "policies.yaml"

def _load_policies() -> list[dict]:
    with open(_POLICIES_PATH) as f:
        return yaml.safe_load(f)["policies"]

_POLICIES = _load_policies()

_PII_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "email address"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN"),
]

_SLOW_THRESHOLD_MS = 5000
_MAX_TOOL_CALLS = 3
_BASELINE_ANOMALY_MULTIPLIER = 3.0

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

_ALLOWED_TOOLS: dict[str, set[str]] = {
    "researcher": {"search"},
    "summarizer": {"mock-llm", "claude-haiku-4-5-20251001"},
}

_STANDARDS = {
    "pii":              "NIST PR.DS-5",
    "slow":             "internal SLO",
    "tool_repetition":  "OWASP LLM07",
    "prompt_injection": "OWASP LLM01",
    "unexpected_tool":  "OWASP LLM08",
    "ungrounded":       "OWASP LLM09",
    "baseline_anomaly": "internal baseline",
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

_COMMON_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "her", "was",
    "one", "our", "out", "day", "get", "has", "him", "his", "how", "its", "may",
    "new", "now", "old", "see", "two", "way", "who", "boy", "did", "she", "use",
    "summary", "findings", "result", "results", "overview", "recent", "expert",
    "analysis", "topic", "developments", "according", "based", "these", "their",
    "this", "that", "with", "from", "they", "been", "have", "more", "also",
}

# --- Rule functions: return (condition_name, reason) | None ---

def _rules(event: dict) -> list[tuple[str, str]]:
    triggered = []
    checks = [
        ("pii",              _check_pii(event)),
        ("slow",             _check_slow(event)),
        ("tool_repetition",  _check_tool_repetition(event)),
        ("prompt_injection", _check_prompt_injection(event)),
        ("unexpected_tool",  _check_unexpected_tool(event)),
        ("ungrounded",       _check_ungrounded_output(event)),
        ("baseline_anomaly", _check_baseline_anomaly(event)),
    ]
    for condition, (flagged, reason) in checks:
        if flagged:
            triggered.append((condition, reason))
    return triggered


def evaluate(event: dict) -> dict:
    triggered = _rules(event)
    if not triggered:
        return {"flagged": False, "reason": None, "severity": None, "standards": [], "action": "log"}

    agent = event.get("agent_name", "")
    applicable_policies = [
        p for p in _POLICIES
        if p["condition"] in {c for c, _ in triggered}
        and (not p.get("applies_to") or agent in p["applies_to"])
    ]

    if not applicable_policies:
        # triggered rules but no matching policy for this agent — still flag
        top_severity = "low"
        action = "flag"
    else:
        top_severity = max(
            (p["severity"] for p in applicable_policies),
            key=lambda s: SEVERITY_ORDER.index(s),
        )
        # take the strongest action across matching policies
        action = "block" if any(p["action"] == "block" for p in applicable_policies) else "flag"

    return {
        "flagged": True,
        "reason": "; ".join(r for _, r in triggered),
        "severity": top_severity,
        "standards": [_STANDARDS[c] for c, _ in triggered if c in _STANDARDS],
        "action": action,
    }


# --- Individual rule checks ---

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


def _check_baseline_anomaly(event: dict) -> tuple[bool, str]:
    duration = event.get("duration_ms")
    if duration is None:
        return False, ""
    agent = event.get("agent_name")
    event_type = event.get("event_type")
    baseline = get_baseline(agent, event_type, exclude_trace_id=event.get("trace_id"))
    if baseline is None or baseline == 0:
        return False, ""
    if duration > baseline * _BASELINE_ANOMALY_MULTIPLIER:
        return True, f"duration {duration:.0f}ms is {duration/baseline:.1f}x above baseline ({baseline:.0f}ms avg)"
    return False, ""


def _check_ungrounded_output(event: dict) -> tuple[bool, str]:
    if event.get("agent_name") != "summarizer" or event.get("event_type") != "llm_call":
        return False, ""
    input_val = event.get("input") or {}
    results = input_val.get("results", [])
    input_text = " ".join(_extract_text(r) for r in results).lower()
    summary = _extract_text((event.get("output") or {}).get("summary", ""))
    named_entities = re.findall(r"\b[A-Z][a-z]{2,}\b", summary)
    ungrounded = [
        w for w in named_entities
        if w.lower() not in input_text and w.lower() not in _COMMON_WORDS
    ]
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
