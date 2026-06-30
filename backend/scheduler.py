"""
Background scheduler for TriageMate operational cadence.

Handles: daily EPSS refresh, daily KEV poll, low-severity re-checks,
quarterly retraining triggers.
"""

import asyncio


async def recheck_low_severity():
    """
    Re-evaluate vulnerabilities classified as 'low' more than 7 days ago.
    Re-runs Tier 0 with current EPSS/KEV values and updates if changed.
    """
    from database import get_db
    from pipeline import tier_0

    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT * FROM vulnerabilities
            WHERE tier_0_resolution = 'low'
              AND julianday('now') - julianday(created_at) >= 7
              AND (last_recheck_date IS NULL
                   OR julianday('now') - julianday(last_recheck_date) >= 7)
        """).fetchall()
    finally:
        conn.close()

    for row in rows:
        new_t0 = tier_0.evaluate_tier_0(
            cvss_score=row["cvss_score"],
            cisa_kev=bool(row["cisa_kev"]),
            epss_score=row["epss_score"] or 0.0,
            data_classification=row["data_classification"] or "Category 2",
            internet_facing=("internet" in (row["interface_type"] or "").lower()),
        )

        conn = get_db()
        try:
            if new_t0["resolution"] != "low":
                conn.execute("""
                    UPDATE vulnerabilities
                    SET tier_0_resolution = ?, tier_0_routing = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_t0["resolution"], new_t0["routing"], row["id"]))
                conn.commit()

            conn.execute("""
                UPDATE vulnerabilities
                SET last_recheck_date = CURRENT_TIMESTAMP WHERE id = ?
            """, (row["id"],))
            conn.commit()
        finally:
            conn.close()
