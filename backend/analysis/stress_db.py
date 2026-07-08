"""
Stress test result database module.

Provides a SQLite-backed store for collecting stress test run results,
with schema for test runs and individual ingestion results.
"""

import json
import sqlite3
from datetime import datetime, timezone


def create_db(path: str) -> None:
    """Create SQLite database at path with the stress test schema."""
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS test_runs (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            config TEXT NOT NULL,  -- JSON
            total_requests INTEGER DEFAULT 0,
            successful INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_run_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            ts TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            status TEXT NOT NULL,
            priority_score INTEGER,
            risk_band TEXT,
            tier_0_routing TEXT,
            tier_1_routing TEXT,
            tier_2_called INTEGER DEFAULT 0,
            total_latency_ms REAL,
            llm_cost_usd REAL DEFAULT 0.0,
            trace TEXT NOT NULL  -- JSON
        );

        CREATE INDEX IF NOT EXISTS idx_results_run ON results(test_run_id);
        CREATE INDEX IF NOT EXISTS idx_results_status ON results(status);
        CREATE INDEX IF NOT EXISTS idx_results_t0 ON results(tier_0_routing);
        CREATE INDEX IF NOT EXISTS idx_results_t1 ON results(tier_1_routing);
    """)
    conn.commit()
    conn.close()


def insert_run(db_path: str, run_id: str, config: dict) -> None:
    """Insert a test run record."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO test_runs (id, started_at, config)
        VALUES (?, ?, ?)
        """,
        (run_id, datetime.now(timezone.utc).isoformat(), json.dumps(config)),
    )
    conn.commit()
    conn.close()


def update_run_end(db_path: str, run_id: str, totals: dict) -> None:
    """Update ended_at and counts for a test run."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        UPDATE test_runs
        SET ended_at = ?,
            total_requests = ?,
            successful = ?,
            failed = ?
        WHERE id = ?
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            totals.get("total_requests", 0),
            totals.get("successful", 0),
            totals.get("failed", 0),
            run_id,
        ),
    )
    conn.commit()
    conn.close()


def insert_result(
    db_path: str,
    run_id: str,
    seq: int,
    cve_id: str,
    hostname: str,
    status: str,
    priority_score: int,
    risk_band: str,
    tier_0_routing: str,
    tier_1_routing: str,
    tier_2_called: bool,
    total_latency_ms: float,
    llm_cost_usd: float,
    trace: dict,
) -> None:
    """Insert one result row."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO results (
            test_run_id, seq, ts, cve_id, hostname, status,
            priority_score, risk_band,
            tier_0_routing, tier_1_routing, tier_2_called,
            total_latency_ms, llm_cost_usd, trace
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            seq,
            datetime.now(timezone.utc).isoformat(),
            cve_id,
            hostname,
            status,
            priority_score,
            risk_band,
            tier_0_routing,
            tier_1_routing,
            1 if tier_2_called else 0,
            total_latency_ms,
            llm_cost_usd,
            json.dumps(trace),
        ),
    )
    conn.commit()
    conn.close()
