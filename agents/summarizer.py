import os
import time
from monitor import tracer


def _llm_summarize(results: list[str]) -> str:
    """
    Call Claude if ANTHROPIC_API_KEY is set, otherwise return a mock summary.
    To use real Claude: pip install langchain-anthropic and set ANTHROPIC_API_KEY.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage
        llm = ChatAnthropic(model="claude-haiku-4-5-20251001")
        joined = "\n".join(results)
        response = llm.invoke([HumanMessage(content=f"Summarize these findings concisely:\n{joined}")])
        return response.content
    else:
        time.sleep(0.03)
        return f"Summary of {len(results)} findings: " + " | ".join(r.split(":")[1].strip() for r in results)


def run(results: list[str], trace_id: str) -> str:
    start = time.monotonic()
    summary = _llm_summarize(results)
    duration_ms = (time.monotonic() - start) * 1000

    tracer.emit(
        trace_id=trace_id,
        agent_name="summarizer",
        event_type="llm_call",
        tool="claude-haiku-4-5-20251001" if os.environ.get("ANTHROPIC_API_KEY") else "mock-llm",
        input={"results": results},
        output={"summary": summary},
        duration_ms=duration_ms,
    )
    return summary
