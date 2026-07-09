import html
import json
from datetime import datetime, timezone
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException
from database import get_db
from ingest_helpers import compliance_category as _compliance_category
from models import (
    QueueRow,
    CaseResponse,
    CaseViewData,
    MitreTechnique,
    ScoringWeight,
    AssetRegistryEntry,
    SubstitutionBlock,
    NetworkContextData,
    ReviewRequest,
    ReviewQueueItem,
    ReviewQueueResponse,
)


class NotesUpdate(BaseModel):
    notes: str


router = APIRouter(tags=["Cases"])


def _row_to_queue_row(r) -> QueueRow:
    compliance_str = (
        r["data_classification"] or "Category 1"
    )  # WAICP: OFFICIAL (was PRIS Act Category 1)
    cat = _compliance_category(compliance_str)
    return QueueRow(
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
    )


def _parse_json_column(val, default=None):
    if val is None:
        return default if default is not None else []
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else []


def _row_to_case_view(r) -> CaseViewData:
    substitution_block = SubstitutionBlock(
        original_epss="0",
        substituted_epss="0",
        model_confidence="0",
        reason="No EPSS substitution performed",
    )
    if r["epss_substituted"]:
        substitution_block = SubstitutionBlock(
            original_epss=str(r["epss_score"]) if r["epss_score"] is not None else "0",
            substituted_epss=str(r["epss_substituted_value"])
            if r["epss_substituted_value"] is not None
            else "0",
            model_confidence=str(r["epss_substitution_confidence"])
            if r["epss_substitution_confidence"] is not None
            else "0",
            reason=r["epss_substitution_reason"] or "",
        )

    mitre_data = _parse_json_column(r["mitre_techniques_json"])
    scoring_data = _parse_json_column(r["scoring_weights_json"])
    asset_data = _parse_json_column(r["asset_registry_json"])
    summary_data = _parse_json_column(r["summary_paragraphs_json"])
    telemetry = _parse_json_column(r["telemetry_json"], default=None)
    network_context = _parse_json_column(r["network_context_json"], default=None)

    mitre_techniques = [MitreTechnique(**m) for m in mitre_data if isinstance(m, dict)]
    scoring_weights = [ScoringWeight(**s) for s in scoring_data if isinstance(s, dict)]
    asset_registry = [
        AssetRegistryEntry(**a) for a in asset_data if isinstance(a, dict)
    ]
    summary_paragraphs = [str(s) for s in summary_data]

    from integrations.nvd import get_cve_freshness

    nvd_freshness = get_cve_freshness(r["vulnerability_id"])

    return CaseViewData(
        summary_paragraphs=summary_paragraphs,
        mission_prevalence=[
            f"Mission Prevalence: {r['mission_prevalence']}",
            f"Public Well-Being Impact: {r['public_wellbeing_impact']}",
        ],
        mitre_techniques=mitre_techniques,
        text_conflict=bool(r["tier_2_text_conflict"]),
        text_conflict_note=r["tier_2_conflict_note"] or "",
        scanner_output=html.escape(r["scanner_output_raw"] or ""),
        weakness_template=html.escape(r["weakness_template_raw"] or ""),
        advisory_ref_id=r["advisory_ref_id"] or "",
        advisory_quote=r["advisory_quote"] or "",
        investigation_notes=r["investigation_notes"] or "",
        has_substitution=bool(r["epss_substituted"]),
        substitution_block=substitution_block,
        score_gauge_value=r["priority_score"],
        score_gauge_band=r["risk_band"],
        gauge_band_colour=_band_colour(r["risk_band"]),
        scoring_weights=scoring_weights,
        asset_registry=asset_registry,
        nvd_freshness=nvd_freshness,
        telemetry=telemetry if telemetry else None,
        network_context=NetworkContextData(**network_context)
        if network_context
        else None,
    )


def _band_colour(band: str) -> str:
    return {
        "Low": "#22C55E",
        "Medium": "#F59E0B",
        "Critical": "#F97316",
        "Very Critical": "#EF4444",
    }.get(band, "#64748B")


@router.get("/api/case/{case_id}", response_model=CaseResponse)
def get_case(case_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (case_id,))
    r = cursor.fetchone()
    conn.close()

    if r is None:
        raise HTTPException(status_code=404, detail="Case not found")

    queue_row = _row_to_queue_row(r)
    case_view = _row_to_case_view(r)

    return CaseResponse(queue_row=queue_row, case_view=case_view)


@router.patch("/api/case/{case_id}/notes")
def update_notes(case_id: int, body: NotesUpdate):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE vulnerabilities SET investigation_notes = ? WHERE id = ?",
        (body.notes, case_id),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Case not found")
    conn.commit()
    conn.close()
    return {"status": "ok"}


@router.get("/api/review/queue", response_model=ReviewQueueResponse)
def get_review_queue(flag_filter: str = "all"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, vulnerability_id, hostname, priority_score, risk_band,
               detection_tier, review_status, flagged_for_review,
               tier_2_text_conflict, created_at
        FROM vulnerabilities
        WHERE (flagged_for_review = 1 OR tier_2_text_conflict = 1)
          AND (review_status IS NULL OR review_status = '')
        ORDER BY priority_score DESC, id ASC
    """)
    rows = []
    for r in cursor.fetchall():
        rows.append(
            ReviewQueueItem(
                id=r["id"],
                vulnerability_id=r["vulnerability_id"],
                hostname=r["hostname"],
                priority_score=r["priority_score"],
                risk_band=r["risk_band"],
                detection_tier=r["detection_tier"],
                review_status=r["review_status"],
                flagged_for_review=bool(r["flagged_for_review"]),
                tier_2_text_conflict=bool(r["tier_2_text_conflict"]),
                created_at=r["created_at"] or "",
            )
        )
    conn.close()
    return ReviewQueueResponse(rows=rows, total=len(rows))


@router.post("/api/review/flag/{case_id}")
def flag_for_review(case_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE vulnerabilities SET flagged_for_review = 1 WHERE id = ?",
        (case_id,),
    )
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Case not found")
    conn.commit()
    conn.close()
    return {"status": "ok", "flagged": True}


@router.post("/api/case/{case_id}/review")
def submit_review(case_id: int, body: ReviewRequest):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT vulnerability_id FROM vulnerabilities WHERE id = ?", (case_id,)
    )
    r = cursor.fetchone()
    if r is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Case not found")
    vuln_id = r["vulnerability_id"]

    now = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """INSERT INTO reviews
           (vulnerability_id, case_id, analyst_decision, override_score,
            override_band, notes, analyst_name, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            vuln_id,
            case_id,
            body.analyst_decision,
            body.override_score,
            body.override_band,
            body.notes,
            body.analyst_name,
            now,
        ),
    )

    override_score = (
        body.override_score if body.analyst_decision == "override" else None
    )
    override_band = body.override_band if body.analyst_decision == "override" else None

    cursor.execute(
        """UPDATE vulnerabilities SET
           review_status = 'reviewed',
           review_decision = ?,
           reviewed_by = ?,
           reviewed_at = ?,
           override_score = ?,
           override_band = ?
           WHERE id = ?""",
        (
            body.analyst_decision,
            body.analyst_name,
            now,
            override_score,
            override_band,
            case_id,
        ),
    )

    conn.commit()
    conn.close()
    return {"status": "ok"}


@router.get("/api/case/{case_id}/history")
def get_case_history(case_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT id, vulnerability_id, case_id, analyst_decision,
                  override_score, override_band, notes, analyst_name, created_at
           FROM reviews
           WHERE case_id = ?
           ORDER BY created_at DESC""",
        (case_id,),
    )
    rows = []
    for r in cursor.fetchall():
        rows.append(
            {
                "id": r["id"],
                "vulnerability_id": r["vulnerability_id"],
                "case_id": r["case_id"],
                "analyst_decision": r["analyst_decision"],
                "override_score": r["override_score"],
                "override_band": r["override_band"],
                "notes": r["notes"],
                "analyst_name": r["analyst_name"],
                "created_at": str(r["created_at"]) if r["created_at"] else "",
            }
        )
    conn.close()
    return rows
