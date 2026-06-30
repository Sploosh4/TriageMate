from fastapi import APIRouter, Depends
from database import get_db
from models import QueueRow, QueueResponse, MetricsResponse

router = APIRouter(tags=["Queue"])


@router.get("/api/queue", response_model=QueueResponse)
def get_queue():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, vulnerability_id, hostname, priority_score, risk_band,
               detection_reason, detection_tier, data_classification,
               interface_type
        FROM vulnerabilities
        ORDER BY priority_score DESC, id ASC
    """)
    rows = []
    for r in cursor.fetchall():
        compliance_str = r["data_classification"] or "Category 1"
        cat = int(compliance_str.split()[-1]) if "Category" in compliance_str else 1
        rows.append(QueueRow(
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
        ))
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
