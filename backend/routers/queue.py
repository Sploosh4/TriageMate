from datetime import datetime, timezone
from fastapi import APIRouter
from database import get_db
from models import QueueRow, QueueResponse, MetricsResponse

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
