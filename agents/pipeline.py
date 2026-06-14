import uuid
from typing import TypedDict
from langgraph.graph import StateGraph, END
from agents import researcher, summarizer


class PipelineState(TypedDict):
    query: str
    trace_id: str
    research_results: list[str]
    summary: str
    aborted: bool


def _research_node(state: PipelineState) -> PipelineState:
    results, event = researcher.run(state["query"], state["trace_id"])
    aborted = event.get("flagged", False) and "injection" in (event.get("flag_reason") or "")
    return {**state, "research_results": results, "aborted": aborted}


def _route_after_research(state: PipelineState) -> str:
    return END if state.get("aborted") else "summarizer"


def _summarize_node(state: PipelineState) -> PipelineState:
    summary = summarizer.run(state["research_results"], state["trace_id"])
    return {**state, "summary": summary}


def _build_graph() -> StateGraph:
    graph = StateGraph(PipelineState)
    graph.add_node("researcher", _research_node)
    graph.add_node("summarizer", _summarize_node)
    graph.set_entry_point("researcher")
    graph.add_conditional_edges("researcher", _route_after_research)
    graph.add_edge("summarizer", END)
    return graph.compile()


_graph = _build_graph()


def run_pipeline(query: str) -> dict:
    trace_id = str(uuid.uuid4())
    result = _graph.invoke({
        "query": query, "trace_id": trace_id,
        "research_results": [], "summary": "", "aborted": False,
    })
    if result.get("aborted"):
        return {"trace_id": trace_id, "summary": "[aborted: prompt injection detected]"}
    return {"trace_id": trace_id, "summary": result["summary"]}
