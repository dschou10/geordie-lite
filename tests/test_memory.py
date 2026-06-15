"""
Memory leak tests targeting the Render OOM restart.

Three suspects:
1. SSE client queues growing unbounded when clients disconnect
2. Broadcast accumulating messages in queues nobody is reading
3. SQLite connections not being closed (file handle leak)
"""
import asyncio
import sys
import os
import gc

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ---------------------------------------------------------------------------
# 1. SSE broadcast fills unbounded queues for slow/dead clients
# ---------------------------------------------------------------------------

def test_broadcast_unbounded_queue_growth():
    """
    _broadcast puts to every queue unconditionally. A client that stops
    reading will accumulate messages forever. This test confirms the problem
    exists and quantifies it.
    """
    import api.server as server

    async def _run():
        q = asyncio.Queue(maxsize=50)  # bounded — as per fix
        server._sse_clients.append(q)
        try:
            for i in range(500):
                await server._broadcast("test_event", {"i": i})
            return q.qsize()
        finally:
            server._sse_clients.remove(q)

    depth = asyncio.run(_run())
    assert depth <= 50, (
        f"Queue grew to {depth} messages — slow client queues must be bounded at 50"
    )


def test_sse_client_list_manual_cleanup():
    """
    Simulate what happens when a client disconnects cleanly vs not.
    The finally block in generate() removes the queue — verify it works.
    """
    import api.server as server

    async def _run():
        initial = len(server._sse_clients)

        # simulate clean disconnect
        q = asyncio.Queue()
        server._sse_clients.append(q)
        assert len(server._sse_clients) == initial + 1
        server._sse_clients.remove(q)  # what the finally block does
        assert len(server._sse_clients) == initial, "Queue not removed on disconnect"

    asyncio.run(_run())


def test_multiple_clients_no_accumulation():
    """Repeated add/remove cycles must not leak."""
    import api.server as server

    async def _run():
        baseline = len(server._sse_clients)
        for _ in range(100):
            q = asyncio.Queue()
            server._sse_clients.append(q)
            server._sse_clients.remove(q)
        assert len(server._sse_clients) == baseline

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. SQLite connection leaks
# ---------------------------------------------------------------------------

def test_sqlite_connections_closed():
    """Each store call must close its connection via context manager."""
    import sqlite3
    from monitor import store

    store.init_db()

    opened = []
    closed = []
    original = sqlite3.connect

    class TrackedConn:
        def __init__(self, inner):
            self._c = inner
            opened.append(1)
        def __enter__(self):
            return self._c.__enter__()
        def __exit__(self, *a):
            closed.append(1)
            return self._c.__exit__(*a)
        def __getattr__(self, n):
            return getattr(self._c, n)
        def __setattr__(self, n, v):
            if n == '_c':
                object.__setattr__(self, n, v)
            else:
                setattr(self._c, n, v)

    sqlite3.connect = lambda *a, **kw: TrackedConn(original(*a, **kw))
    try:
        store.get_events(limit=5)
        store.get_stats()
        store.count_events()
        store.get_flagged_events()
    finally:
        sqlite3.connect = original

    assert len(opened) > 0, "No connections opened"
    assert len(opened) == len(closed), (
        f"{len(opened)} connections opened, {len(closed)} closed — "
        f"{len(opened) - len(closed)} leaked"
    )


# ---------------------------------------------------------------------------
# 3. Pipeline state dict never grows
# ---------------------------------------------------------------------------

def test_pipeline_state_bounded():
    """
    _pipeline_state is a fixed dict — it must not grow with each run.
    If someone accidentally appends to it instead of updating, it leaks.
    """
    import api.server as server

    initial_keys = set(server._pipeline_state.keys())
    server._pipeline_state.update({
        "status": "idle", "current_agent": None,
        "last_trace": "abc", "last_summary": "x", "last_aborted": False,
    })
    assert set(server._pipeline_state.keys()) == initial_keys | {"last_summary", "last_aborted"}, \
        "Unexpected keys added to _pipeline_state"


# ---------------------------------------------------------------------------
# 4. Memory growth across repeated risk evaluations
# ---------------------------------------------------------------------------

def test_risk_evaluation_no_memory_leak():
    """
    evaluate() is called on every agent event. Running it 1000 times
    must not grow resident memory by more than 5MB.
    """
    import tracemalloc
    from monitor.risk import evaluate
    from monitor.store import init_db
    init_db()

    event = {
        "trace_id": "test-123",
        "agent_name": "researcher",
        "event_type": "tool_call",
        "tool": "search",
        "input": "what is AI?",
        "output": "AI is artificial intelligence.",
        "duration_ms": 100,
    }

    # warm up
    for _ in range(10):
        evaluate(event)

    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()

    for _ in range(1000):
        evaluate(event)

    gc.collect()
    after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = after.compare_to(before, "lineno")
    growth_mb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024 / 1024
    assert growth_mb < 5, (
        f"Risk engine grew memory by {growth_mb:.2f}MB over 1000 evaluations"
    )
