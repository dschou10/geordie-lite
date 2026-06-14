import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "events.db"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id    TEXT    NOT NULL,
                agent_name  TEXT    NOT NULL,
                event_type  TEXT    NOT NULL,
                tool        TEXT,
                input       TEXT,
                output      TEXT,
                duration_ms REAL,
                flagged     INTEGER NOT NULL DEFAULT 0,
                flag_reason TEXT,
                timestamp   TEXT    NOT NULL
            )
        """)


def insert_event(event: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (trace_id, agent_name, event_type, tool, input, output,
                 duration_ms, flagged, flag_reason, timestamp)
            VALUES
                (:trace_id, :agent_name, :event_type, :tool, :input, :output,
                 :duration_ms, :flagged, :flag_reason, :timestamp)
            """,
            {
                "trace_id":    event["trace_id"],
                "agent_name":  event["agent_name"],
                "event_type":  event["event_type"],
                "tool":        event.get("tool"),
                "input":       json.dumps(event["input"]) if event.get("input") is not None else None,
                "output":      json.dumps(event["output"]) if event.get("output") is not None else None,
                "duration_ms": event.get("duration_ms"),
                "flagged":     int(event.get("flagged", False)),
                "flag_reason": event.get("flag_reason"),
                "timestamp":   event["timestamp"],
            },
        )


def get_events(limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_trace(trace_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE trace_id = ? ORDER BY id ASC", (trace_id,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["flagged"] = bool(d["flagged"])
    for field in ("input", "output"):
        if d[field] is not None:
            d[field] = json.loads(d[field])
    return d
