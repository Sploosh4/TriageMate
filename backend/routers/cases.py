import json
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException
from database import get_db
from models import (
    QueueRow,
    CaseResponse,
    CaseViewData,
    MitreTechnique,
    ScoringWeight,
    AssetRegistryEntry,
    SubstitutionBlock,
)


class NotesUpdate(BaseModel):
    notes: str


router = APIRouter(tags=["Cases"])


def _row_to_queue_row(r) -> QueueRow:
    compliance_str = r["data_classification"] or "Category 1"
    cat = int(compliance_str.split()[-1]) if "Category" in compliance_str else 1
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
    substitution_block = None
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

    mitre_techniques = [MitreTechnique(**m) for m in mitre_data if isinstance(m, dict)]
    scoring_weights = [ScoringWeight(**s) for s in scoring_data if isinstance(s, dict)]
    asset_registry = [
        AssetRegistryEntry(**a) for a in asset_data if isinstance(a, dict)
    ]
    summary_paragraphs = [str(s) for s in summary_data]

    return CaseViewData(
        summary_paragraphs=summary_paragraphs,
        mission_prevalence=[
            f"Mission Prevalence: {r['mission_prevalence']}",
            f"Public Well-Being Impact: {r['public_wellbeing_impact']}",
        ],
        mitre_techniques=mitre_techniques,
        text_conflict=bool(r["tier_2_text_conflict"]),
        text_conflict_note=r["tier_2_conflict_note"] or "",
        scanner_output=r["scanner_output_raw"] or "",
        weakness_template=r["weakness_template_raw"] or "",
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
