from datetime import datetime, timedelta, timezone
from fastapi import APIRouter
from database import get_db
from models import QueueRow, QueueResponse, MetricsResponse, DriftMetricsResponse

router = APIRouter(tags=["Queue"])


def _relative_time(ts_str: str | None) -> str:
    if not ts_str:
        return ""
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - ts
        mins = int(delta.total_seconds() / 60)
        if mins < 1:
            return "now"
        if mins < 60:
            return f"{mins}m ago"
        hours = mins // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        return f"{days}d ago"
    except Exception:
        return ts_str


@router.get("/api/queue", response_model=QueueResponse)
def get_queue():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, vulnerability_id, hostname, priority_score, risk_band,
               detection_reason, detection_tier, data_classification,
               interface_type, created_at
        FROM vulnerabilities
        ORDER BY priority_score DESC, id ASC
    """)
    rows = []
    for r in cursor.fetchall():
        compliance_str = r["data_classification"] or "Category 1"
        cat = int(compliance_str.split()[-1]) if "Category" in compliance_str else 1
        rows.append(
            QueueRow(
                id=r["id"],
                vulnerability_id=r["vulnerability_id"],
                hostname=r["hostname"],
                priority_score=r["priority_score"],
                risk_band=r["risk_band"],
                detection_reason=r["detection_reason"],
                tier=r["detection_tier"],
                compliance=compliance_str,
                compliance_category=cat,
                interface_type=r["interface_type"] or "",
                created_at=_relative_time(r["created_at"]) if r["created_at"] else "",
            )
        )
    conn.close()
    return QueueResponse(rows=rows)


@router.get("/api/metrics", response_model=MetricsResponse)
def get_metrics():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            COUNT(CASE WHEN risk_band = 'Very Critical' THEN 1 END) as critical_actions,
            COUNT(CASE WHEN detection_tier = 'SLM Tier'
                        OR (detection_tier = 'ML Tier' AND tier_1_confidence < 0.85)
                   THEN 1 END) as low_confidence,
            COUNT(CASE WHEN interface_type LIKE '%internet-facing%' THEN 1 END) as exposed,
            COUNT(CASE WHEN detection_tier = 'SLM Tier' THEN 1 END) as needs_human_validation
        FROM vulnerabilities
    """)
    r = cursor.fetchone()
    conn.close()
    return MetricsResponse(
        critical_actions=r["critical_actions"],
        low_confidence=r["low_confidence"],
        exposed=r["exposed"],
        needs_human_validation=r["needs_human_validation"],
    )


@router.get("/api/drift", response_model=DriftMetricsResponse)
def get_drift_metrics():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS cnt FROM resolved_vulnerabilities")
    total_audited = cursor.fetchone()["cnt"]

    if total_audited == 0:
        conn.close()
        return DriftMetricsResponse(
            score_trend=[],
            tier_routing={"auto": 0, "escalated": 0},
            risk_band_distribution={},
            detection_tier_trend=[],
            feature_drift={},
            total_audited=0,
        )

    thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    cursor.execute(
        """
        SELECT DATE(resolved_at) AS day, AVG(priority_score) AS avg_score
        FROM resolved_vulnerabilities
        WHERE resolved_at >= ?
        GROUP BY DATE(resolved_at)
        ORDER BY day ASC
    """,
        (thirty_days_ago,),
    )
    score_trend = [
        {"date": r["day"], "avg_score": round(r["avg_score"], 1)}
        for r in cursor.fetchall()
    ]

    cursor.execute("""
        SELECT
            COUNT(CASE WHEN detection_tier IN ('Deterministic', 'ML Tier') THEN 1 END) AS auto,
            COUNT(CASE WHEN detection_tier = 'SLM Tier' THEN 1 END) AS escalated
        FROM resolved_vulnerabilities
    """)
    r = cursor.fetchone()
    tier_routing = {"auto": r["auto"], "escalated": r["escalated"]}

    cursor.execute("""
        SELECT risk_band, COUNT(*) AS cnt
        FROM resolved_vulnerabilities
        GROUP BY risk_band
    """)
    risk_band_distribution = {r["risk_band"]: r["cnt"] for r in cursor.fetchall()}

    cursor.execute(
        """
        SELECT DATE(resolved_at) AS day,
               COUNT(CASE WHEN detection_tier = 'Deterministic' THEN 1 END) AS det,
               COUNT(CASE WHEN detection_tier = 'ML Tier' THEN 1 END) AS ml,
               COUNT(CASE WHEN detection_tier = 'SLM Tier' THEN 1 END) AS slm
        FROM resolved_vulnerabilities
        WHERE resolved_at >= ?
        GROUP BY DATE(resolved_at)
        ORDER BY day ASC
    """,
        (thirty_days_ago,),
    )
    detection_tier_trend = [
        {"date": r["day"], "deterministic": r["det"], "ml": r["ml"], "slm": r["slm"]}
        for r in cursor.fetchall()
    ]

    cursor.execute(
        """
        SELECT
            COALESCE(AVG(cvss_score), 0) AS avg_cvss,
            COALESCE(AVG(epss_score), 0) AS avg_epss,
            COALESCE(AVG(priority_score), 0) AS avg_priority
        FROM resolved_vulnerabilities
        WHERE resolved_at >= ?
    """,
        (thirty_days_ago,),
    )
    r = cursor.fetchone()
    feature_drift = {
        "avg_cvss": round(r["avg_cvss"], 2),
        "avg_epss": round(r["avg_epss"], 2),
        "avg_priority": round(r["avg_priority"], 1),
    }

    conn.close()
    return DriftMetricsResponse(
        score_trend=score_trend,
        tier_routing=tier_routing,
        risk_band_distribution=risk_band_distribution,
        detection_tier_trend=detection_tier_trend,
        feature_drift=feature_drift,
        total_audited=total_audited,
    )
