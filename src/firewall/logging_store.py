"""
Request logging -- writes every request through the firewall to a local
SQLite database. This is the data source for the dashboard, and for
flagged requests specifically, the foundation of the honeypot's attack
metrics.

SQLite (not Postgres) is intentional here: zero setup, a single file,
plenty for a portfolio-scale project. The schema is deliberately flat
(one row per request, JSON-encoded list fields) rather than normalized
across multiple tables -- simpler to query for a dashboard than it is
correct for a production system with real write concurrency.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/firewall_log.sqlite3")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    input_text TEXT NOT NULL,
    flagged INTEGER NOT NULL,
    sanitizer_categories TEXT NOT NULL,
    vector_similarity REAL NOT NULL,
    qllm_contains_embedded_instruction INTEGER NOT NULL,
    qllm_topic TEXT NOT NULL,
    response_text TEXT NOT NULL,
    output_safe INTEGER NOT NULL,
    output_validator_reasons TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS honeypot_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    input_text TEXT NOT NULL,
    decoy_response TEXT NOT NULL,
    honeytoken_leaked INTEGER NOT NULL
);
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        # executescript (not execute!) is required here -- _SCHEMA contains
        # two CREATE TABLE statements. execute() only runs a single
        # statement and silently drops anything after the first semicolon,
        # with no error -- which is exactly the bug that caused
        # honeypot_events to never actually get created.
        conn.executescript(_SCHEMA)


def log_request(
    input_text: str,
    flagged: bool,
    sanitizer_categories: list[str],
    vector_similarity: float,
    qllm_contains_embedded_instruction: bool,
    qllm_topic: str,
    response_text: str,
    output_safe: bool,
    output_validator_reasons: list[str],
) -> None:
    init_db()  # idempotent -- safe to call on every write, see log_honeypot_event
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO requests (
                timestamp, input_text, flagged, sanitizer_categories,
                vector_similarity, qllm_contains_embedded_instruction,
                qllm_topic, response_text, output_safe, output_validator_reasons
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                input_text,
                int(flagged),
                json.dumps(sanitizer_categories),
                vector_similarity,
                int(qllm_contains_embedded_instruction),
                qllm_topic,
                response_text,
                int(output_safe),
                json.dumps(output_validator_reasons),
            ),
        )


def get_summary_metrics() -> dict:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        total_requests = conn.execute(
            "SELECT COUNT(*) AS n FROM requests").fetchone()["n"]
        flagged_requests = conn.execute(
            "SELECT COUNT(*) AS n FROM requests WHERE flagged = 1"
        ).fetchone()["n"]
        embedded_instruction_count = conn.execute(
            "SELECT COUNT(*) AS n FROM requests WHERE qllm_contains_embedded_instruction = 1"
        ).fetchone()["n"]
        unsafe_output_count = conn.execute(
            "SELECT COUNT(*) AS n FROM requests WHERE output_safe = 0"
        ).fetchone()["n"]
        honeypot_events = conn.execute(
            "SELECT COUNT(*) AS n FROM honeypot_events").fetchone()["n"]
        honeytoken_leaks = conn.execute(
            "SELECT COUNT(*) AS n FROM honeypot_events WHERE honeytoken_leaked = 1"
        ).fetchone()["n"]

    return {
        "total_requests": total_requests,
        "flagged_requests": flagged_requests,
        "flagged_rate": (flagged_requests / total_requests) if total_requests else 0,
        "embedded_instruction_count": embedded_instruction_count,
        "unsafe_output_count": unsafe_output_count,
        "honeypot_events": honeypot_events,
        "honeytoken_leaks": honeytoken_leaks,
    }


def get_recent_requests(limit: int = 20) -> list[dict]:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def get_recent_honeypot_events(limit: int = 20) -> list[dict]:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM honeypot_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def log_honeypot_event(input_text: str, decoy_response: str, honeytoken_leaked: bool) -> None:
    init_db()  # idempotent (CREATE TABLE IF NOT EXISTS) -- safe to call every time,
    # ensures this works whether called from the FastAPI app's startup
    # or a standalone script that never triggered app startup at all.
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO honeypot_events (
                timestamp, input_text, decoy_response, honeytoken_leaked
            ) VALUES (?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                input_text,
                decoy_response,
                int(honeytoken_leaked),
            ),
        )
