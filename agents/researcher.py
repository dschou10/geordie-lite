import os
import time
from monitor import tracer


def _search(query: str) -> list[str]:
    if os.environ.get("TAVILY_API_KEY"):
        from tavily import TavilyClient
        client = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])
        response = client.search(query, max_results=3)
        return [r["content"] for r in response.get("results", [])]
    time.sleep(0.05)
    return [
        f"Result 1 for '{query}': Overview of the topic.",
        f"Result 2 for '{query}': Recent developments.",
        f"Result 3 for '{query}': Expert analysis.",
    ]


def run(query: str, trace_id: str) -> list[str]:
    start = time.monotonic()
    results = _search(query)
    duration_ms = (time.monotonic() - start) * 1000

    event = tracer.emit(
        trace_id=trace_id,
        agent_name="researcher",
        event_type="tool_call",
        tool="search",
        input={"query": query},
        output={"results": results},
        duration_ms=duration_ms,
    )
    return results, event
