import json
import asyncio
from fastapi import APIRouter, HTTPException
from database import get_db
from models import IngestRequest, CaseResponse, QueueRow, CaseViewData, SubstitutionBlock
from pipeline import pre_tier, tier_0, tier_1, tier_2
from scoring import calculate_final_score
from ingest_helpers import (
    lookup_data_classification,
    is_internet_facing,
    build_feature_vector,
    query_rag,
    get_asset_context,
)

router = APIRouter(tags=["Ingest"])


def _band_colour(band: str) -> str:
    return {
        "Low": "#22C55E",
        "Medium": "#F59E0B",
        "Critical": "#F97316",
        "Very Critical": "#EF4444",
    }.get(band, "#64748B")


def _compliance_category(data_classification: str) -> int:
    try:
        return int(data_classification.split()[-1])
    except (ValueError, IndexError):
        return 1


@router.post("/api/ingest", response_model=CaseResponse)
async def ingest_vulnerability(payload: IngestRequest):
    # 1. Pre-Tier: mission tags
    mission_tags = pre_tier.predict_mission_tags(payload.hostname, payload.target_ip)

    # 2. Asset context
    data_classification = lookup_data_classification(payload.hostname)
    internet_facing = is_internet_facing(payload.hostname)
    asset_ctx = get_asset_context(payload.hostname)

    # 3. Tier 0: deterministic routing
    t0_result = tier_0.evaluate_tier_0(
        cvss_score=payload.cvss_score,
        cisa_kev=payload.cisa_kev,
        epss_score=payload.epss_score,
        data_classification=data_classification,
        internet_facing=internet_facing,
    )

    t1_result = None
    t2_result = None

    # 4. If ambiguous, run Tier 1
    if t0_result["routing"] == "escalated":
        features = build_feature_vector(payload, mission_tags, t0_result)
        t1_result = tier_1.evaluate_tier_1(features)

        # 5. If still ambiguous, run Tier 2
        if t1_result["routing"] == "escalated":
            config_context = query_rag(payload.hostname, payload.vulnerability_id)
            t2_result = await tier_2.evaluate_tier_2(
                cve_id=payload.vulnerability_id,
                cvss_score=payload.cvss_score,
                description=payload.raw_description,
                config_context=config_context,
                upstream_scores=t1_result,
                mission_tags=mission_tags,
            )

    # 6. Calculate final score
    t2_score_adjustment = t2_result.get("score_adjustment") if t2_result else None
    scoring = calculate_final_score(
        cvss_score=payload.cvss_score,
        epss_score=payload.epss_score,
        mission_prevalence=mission_tags["mission_prevalence"],
        public_wellbeing=mission_tags["public_wellbeing_impact"],
        data_classification=data_classification,
        internet_facing=internet_facing,
        patch_available=True,
        patch_applied=False,
        tier_1_result=t1_result,
        tier_2_result=t2_result,
    )

    # 7. Determine tier routing text
    detection_tier = "Deterministic"
    if t1_result and t2_result:
        detection_tier = "SLM Tier"
    elif t1_result and not t2_result:
        detection_tier = "ML Tier"

    # Build detection reason
    reason_parts = [f"{detection_tier}: CVSS {payload.cvss_score}"]
    if payload.cisa_kev:
        reason_parts.append("CISA KEV")
    if t0_result["routing"] == "auto_resolved":
        reason_parts.append(f"auto-resolved ({t0_result['resolution']})")
    else:
        reason_parts.append("escalated to Tier 1")
        if t1_result:
            if t1_result["routing"] == "auto_resolved":
                reason_parts.append(f"Tier 1 confidence {t1_result['confidence']}")
            else:
                reason_parts.append("escalated to Tier 2")
                if t2_result:
                    reason_parts.append(f"text conflict: {t2_result['rag_result']}")
    detection_reason = ". ".join(reason_parts) + "."

    # 8. Prepare scoring weights for storage
    weights = [
        {"name": "CVSS Base Score Contribution", "awarded": scoring["dimensions"]["cvss"], "max": 40, "justification": "Calculated from CVSS base score."},
        {"name": "EPSS Exploitability Contribution", "awarded": scoring["dimensions"]["epss"], "max": 20, "justification": "Calculated from EPSS score."},
        {"name": "Asset Criticality Contribution", "awarded": scoring["dimensions"]["criticality"], "max": 20, "justification": "Based on data classification and mission tags."},
        {"name": "Exposure and Network Position", "awarded": scoring["dimensions"]["exposure"], "max": 15, "justification": "Based on network position and exposure analysis."},
        {"name": "Patch Availability and Remediation Complexity", "awarded": scoring["dimensions"]["patch"], "max": 5, "justification": "Based on patch availability and application status."},
    ]

    # 9. Build investigation notes
    notes = f"Auto-generated investigation notes for {payload.vulnerability_id} on {payload.hostname}.\n\n"
    notes += f"Pipeline routing: {detection_tier}.\n"
    notes += f"Tier 0 result: {t0_result['routing']} ({t0_result['resolution']}).\n"
    if t1_result:
        notes += f"Tier 1 confidence: {t1_result['confidence']}, routing: {t1_result['routing']}.\n"
    if t2_result:
        notes += f"Tier 2 text conflict: {t2_result['text_conflict']}, confidence: {t2_result['confidence']}.\n"
    notes += f"\nFinal score: {scoring['total']} ({scoring['band']})."

    # 9b. Audit selection for auto-resolved cases
    from audit import should_audit, select_for_audit
    audit_selected = should_audit(detection_tier, t0_result["routing"])

    # 10. Insert into database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilities (
            vulnerability_id, hostname, cvss_score, cvss_vector, cisa_kev, epss_score,
            mission_prevalence, mission_prevalence_conf, public_wellbeing_impact, public_wellbeing_conf,
            tier_0_routing, tier_0_resolution,
            tier_1_confidence, tier_1_exploitation_prob, tier_1_routing,
            tier_2_text_conflict, tier_2_conflict_note, tier_2_rag_result, tier_2_confidence, tier_2_resolution_summary,
            priority_score, risk_band,
            cvss_contribution, epss_contribution, asset_criticality_contribution, exposure_contribution,
            patch_remediation_contribution,
            epss_substituted,
            data_classification, network_zone, interface_type, patch_cycle, last_patch_date, last_scan_date,
            operating_system, role, business_owner, technical_owner, registered_applications, dependent_assets,
            service_account, detection_tier, detection_reason,
            scanner_output_raw, weakness_template_raw, advisory_ref_id, advisory_quote, investigation_notes,
            mitre_techniques_json, scoring_weights_json, asset_registry_json, summary_paragraphs_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?,
            ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?
        )
    """, (
        payload.vulnerability_id, payload.hostname,
        payload.cvss_score, payload.cvss_vector, payload.cisa_kev, payload.epss_score,
        mission_tags["mission_prevalence"], mission_tags["mission_prevalence_confidence"],
        mission_tags["public_wellbeing_impact"], mission_tags["public_wellbeing_confidence"],
        t0_result["routing"], t0_result["resolution"],
        t1_result["confidence"] if t1_result else None,
        t1_result["exploitation_probability"] if t1_result else None,
        t1_result["routing"] if t1_result else None,
        t2_result["text_conflict"] if t2_result else False,
        t2_result["conflict_note"] if t2_result else None,
        t2_result["rag_result"] if t2_result else None,
        t2_result["confidence"] if t2_result else None,
        t2_result["resolution"] if t2_result else None,
        scoring["total"], scoring["band"],
        scoring["dimensions"]["cvss"], scoring["dimensions"]["epss"],
        scoring["dimensions"]["criticality"], scoring["dimensions"]["exposure"],
        scoring["dimensions"]["patch"],
        False,
        data_classification,
        asset_ctx.get("network_zone", ""),
        asset_ctx.get("interface_type", ""),
        asset_ctx.get("patch_cycle", ""),
        asset_ctx.get("last_patch_date", ""),
        asset_ctx.get("last_scan_date", ""),
        asset_ctx.get("operating_system", ""),
        asset_ctx.get("role", ""),
        asset_ctx.get("business_owner", ""),
        asset_ctx.get("technical_owner", ""),
        asset_ctx.get("registered_applications", ""),
        asset_ctx.get("dependent_assets", ""),
        asset_ctx.get("service_account", ""),
        detection_tier, payload.raw_description or f"{payload.vulnerability_id} ingested via API",
        payload.raw_description or "", "", "", "", notes,
        json.dumps([]), json.dumps(weights), json.dumps([]), json.dumps([]),
    ))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # 10b. Record audit selection for auto-resolved cases
    if audit_selected:
        select_for_audit(new_id)

    # 11. Build response
    queue_row = QueueRow(
        id=new_id,
        vulnerability_id=payload.vulnerability_id,
        hostname=payload.hostname,
        priority_score=scoring["total"],
        risk_band=scoring["band"],
        detection_reason=detection_reason,
        tier=detection_tier,
        compliance=data_classification,
        compliance_category=_compliance_category(data_classification),
    )

    case_view = CaseViewData(
        summary_paragraphs=[payload.raw_description] if payload.raw_description else [],
        mission_prevalence=[
            f"Mission Prevalence: {mission_tags['mission_prevalence']}",
            f"Public Well-Being Impact: {mission_tags['public_wellbeing_impact']}",
        ],
        mitre_techniques=[],
        text_conflict=t2_result["text_conflict"] if t2_result else False,
        text_conflict_note=t2_result["conflict_note"] if t2_result else "",
        scanner_output=payload.raw_description or "",
        weakness_template="",
        advisory_ref_id="",
        advisory_quote="",
        investigation_notes=notes,
        has_substitution=False,
        substitution_block=None,
        score_gauge_value=scoring["total"],
        score_gauge_band=scoring["band"],
        gauge_band_colour=_band_colour(scoring["band"]),
        scoring_weights=[],
        asset_registry=[
            {"label": "Hostname", "value": payload.hostname},
            {"label": "CVSS Score", "value": str(payload.cvss_score)},
            {"label": "EPSS Score", "value": str(payload.epss_score)},
            {"label": "Data Classification", "value": data_classification},
            {"label": "Internet-Facing", "value": "Yes" if internet_facing else "No"},
            {"label": "Tier", "value": detection_tier},
        ],
    )

    return CaseResponse(queue_row=queue_row, case_view=case_view)
