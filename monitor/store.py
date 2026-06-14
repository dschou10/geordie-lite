import sqlite3
import json
from pathlib import Path
from typing import Optional

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
                severity    TEXT,
                action      TEXT,
                standards   TEXT,
                timestamp   TEXT    NOT NULL
            )
        """)
        # migrate existing DBs that predate the standards column
        cols = {r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
        if "standards" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN standards TEXT")
        if "severity" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN severity TEXT")
        if "action" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN action TEXT")


def insert_event(event: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO events
                (trace_id, agent_name, event_type, tool, input, output,
                 duration_ms, flagged, flag_reason, severity, action, standards, timestamp)
            VALUES
                (:trace_id, :agent_name, :event_type, :tool, :input, :output,
                 :duration_ms, :flagged, :flag_reason, :severity, :action, :standards, :timestamp)
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
                "severity":    event.get("severity"),
                "action":      event.get("action", "log"),
                "standards":   json.dumps(event.get("standards") or []),
                "timestamp":   event["timestamp"],
            },
        )


def get_events(limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_stats() -> dict:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        flagged = conn.execute("SELECT COUNT(*) FROM events WHERE flagged = 1").fetchone()[0]
        by_severity = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT severity, COUNT(*) FROM events WHERE flagged=1 AND severity IS NOT NULL GROUP BY severity"
            ).fetchall()
        }
        by_agent = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT agent_name, COUNT(*) FROM events WHERE flagged=1 GROUP BY agent_name"
            ).fetchall()
        }
        blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action='block'").fetchone()[0]
    return {
        "total_events": total,
        "flagged_events": flagged,
        "blocked_events": blocked,
        "by_severity": by_severity,
        "by_agent": by_agent,
    }


def get_baseline(agent_name: str, event_type: str, exclude_trace_id: Optional[str] = None) -> Optional[float]:
    """Return the rolling average duration_ms for an agent+event_type over the last 50 events."""
    with get_conn() as conn:
        query = """
            SELECT AVG(duration_ms) FROM (
                SELECT duration_ms FROM events
                WHERE agent_name = ? AND event_type = ? AND duration_ms IS NOT NULL
                {}
                ORDER BY id DESC LIMIT 50
            )
        """.format("AND trace_id != ?" if exclude_trace_id else "")
        params = (agent_name, event_type, exclude_trace_id) if exclude_trace_id else (agent_name, event_type)
        row = conn.execute(query, params).fetchone()
    return row[0] if row and row[0] is not None else None


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
    d["standards"] = json.loads(d["standards"]) if d.get("standards") else []
    return d
