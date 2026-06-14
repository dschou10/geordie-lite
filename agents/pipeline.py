import uuid
from typing import TypedDict
from langgraph.graph import StateGraph, END
from agents import researcher, summarizer


class PipelineState(TypedDict):
    query: str
    trace_id: str
    research_results: list[str]
    summary: str


def _research_node(state: PipelineState) -> PipelineState:
    results = researcher.run(state["query"], state["trace_id"])
    return {**state, "research_results": results}


def _summarize_node(state: PipelineState) -> PipelineState:
    summary = summarizer.run(state["research_results"], state["trace_id"])
    return {**state, "summary": summary}


def _build_graph() -> StateGraph:
    graph = StateGraph(PipelineState)
    graph.add_node("researcher", _research_node)
    graph.add_node("summarizer", _summarize_node)
    graph.set_entry_point("researcher")
    graph.add_edge("researcher", "summarizer")
    graph.add_edge("summarizer", END)
    return graph.compile()


_graph = _build_graph()


def run_pipeline(query: str) -> dict:
    trace_id = str(uuid.uuid4())
    result = _graph.invoke({"query": query, "trace_id": trace_id, "research_results": [], "summary": ""})
    return {"trace_id": trace_id, "summary": result["summary"]}
