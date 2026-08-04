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
"""


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(_SCHEMA)


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
