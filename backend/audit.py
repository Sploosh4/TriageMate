"""
Background statistical audit for auto-resolved cases.

Randomly samples 7.5% of auto-resolved Tier 0/1 cases for
independent review to detect model drift.
"""

import random
from database import get_db

AUDIT_SAMPLE_RATE = 0.075


def should_audit(tier: str, routing: str) -> bool:
    """Determine if a case should enter the audit pool."""
    if routing == "auto_resolved" and tier in ("Deterministic", "ML Tier", "SLM Tier"):
        return random.random() < AUDIT_SAMPLE_RATE
    return False


def select_for_audit(row_id: int):
    """Mark a database row for background audit."""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE vulnerabilities SET audit_selected = TRUE WHERE id = ?", (row_id,)
        )
        conn.commit()
    finally:
        conn.close()


def get_audit_queue(limit: int = 20) -> list:
    """Get cases pending audit review."""
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT id, vulnerability_id, hostname, priority_score, risk_band,
                   detection_tier, tier_0_resolution, tier_1_confidence
            FROM vulnerabilities
            WHERE audit_selected = TRUE AND audit_result IS NULL
            LIMIT ?
        """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def record_audit_result(row_id: int, result: str):
    """Record audit outcome: 'PASS', 'FAIL_LOW', 'FAIL_HIGH'."""
    conn = get_db()
    try:
        conn.execute(
            """
            UPDATE vulnerabilities
            SET audit_result = ?, audit_date = CURRENT_TIMESTAMP WHERE id = ?
        """,
            (result, row_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_audit_statistics() -> dict:
    """Return aggregate audit statistics for drift detection."""
    conn = get_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE audit_selected = TRUE"
        ).fetchone()[0]
        reviewed = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE audit_result IS NOT NULL"
        ).fetchone()[0]
        failures = conn.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE audit_result LIKE 'FAIL%'"
        ).fetchone()[0]
    finally:
        conn.close()

    return {
        "total_audited": reviewed,
        "total_selected": total,
        "failures": failures,
        "failure_rate": failures / reviewed if reviewed > 0 else 0.0,
    }
