import html
import json
import logging
import os as _os
import time
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from auth import get_current_user_if_enabled
from database import get_db
from models import (
    IngestRequest,
    CaseResponse,
    QueueRow,
    CaseViewData,
    SubstitutionBlock,
)
from pipeline import pre_tier, tier_0, tier_1, tier_2
from pipeline.pre_tier import extract_pre_tier_features
from scoring import calculate_final_score
from ingest_helpers import (
    lookup_data_classification,
    is_internet_facing,
    build_feature_vector,
    query_rag,
    get_asset_context,
    compliance_category as _compliance_category,
)
from ml.epss_substitutor import calculate_substitution
from routers.cases import _band_colour
from ingest_cwe import get_cwe
from integrations.mitre_mapping import lookup_mitre
from integrations.advisories import get_advisory
from integrations.tenable import parse_tenable_webhook, parse_tenable_batch
from integrations.nvd import get_nvd_data

logger = logging.getLogger("triagemate.ingest")
router = APIRouter(tags=["Ingest"])


def _build_summaries(
    cve_id: str,
    hostname: str,
    detection_tier: str,
    total_score: int,
    band: str,
    data_classification: str,
    mission: str,
    wellbeing: str,
    internet_facing: bool,
    role: str,
    network_zone: str,
    description: str,
) -> list[str]:
    """Build template-based summary paragraphs matching demo row style."""
    paras = []
    lead = (
        f"This case concerns {description or cve_id} identified on the host {hostname}."
    )
    paras.append(lead)

    ctx = f"The multi-label classifier assessed this asset as having a Mission Prevalence of {mission} and a Public Well-Being Impact of {wellbeing}."
    if role:
        ctx += f" The asset operates as {role.lower()}."
    paras.append(ctx)

    signal = f"Pipeline routing: {detection_tier}. The priority score is {total_score} ({band})."
    if internet_facing:
        signal += " The asset is internet-facing."
    else:
        signal += " The asset is not directly internet-facing."
    paras.append(signal)

    return paras


def _demo_only():
    """Return 404 JSONResponse if DEMO_MODE is not enabled."""
    if _os.getenv("DEMO_MODE", "").lower() != "true":
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return None


@router.post(
    "/api/ingest", response_model=CaseResponse, response_model_exclude_none=True
)
async def ingest_vulnerability(
    payload: IngestRequest,
    request: Request = None,
    user: dict = Depends(get_current_user_if_enabled),
):
    _t_start = time.monotonic()
    _verbose = False
    if request is not None:
        _verbose = request.headers.get("X-TriageMate-Verbose", "").lower() == "true"
    trace = {}  # built locally, returned if verbose header present

    # 1. Pre-Tier: mission tags
    _t0 = time.monotonic()
    mission_tags = pre_tier.predict_mission_tags(payload.hostname)
    _t_pre_tier = time.monotonic() - _t0

    # Extract Pre-Tier features for drift monitoring
    pre_tier_features_json = None
    try:
        pre_tier_features = extract_pre_tier_features(payload.hostname)
        if pre_tier_features:
            pre_tier_features_json = json.dumps(pre_tier_features)
    except Exception:
        logger.warning("Failed to extract Pre-Tier features for %s", payload.hostname)

    # 2. Asset context
    data_classification = lookup_data_classification(payload.hostname)
    internet_facing = is_internet_facing(payload.hostname)
    asset_ctx = get_asset_context(payload.hostname)

    # WA government hostname validation
    from integrations.cmdb import validate_wa_gov_hostname

    if not validate_wa_gov_hostname(payload.hostname):
        logger.warning(
            "Hostname %s does not match WA government convention", payload.hostname
        )

    # 3. CWE classification (needed for EPSS substitution)
    cwe_result = get_cwe(payload.vulnerability_id, payload.raw_description or "")
    cwe_class = cwe_result.get("cwe_class", "")

    # 4. EPSS substitution (sector-adjusted exploitation probability)
    epss_available = payload.epss_score is not None
    raw_epss = payload.epss_score if epss_available else 0.0
    epss_sub = calculate_substitution(
        cve_id=payload.vulnerability_id,
        raw_epss=raw_epss if epss_available else None,
        hostname=payload.hostname,
        cisa_kev=payload.cisa_kev,
        cvss_score=payload.cvss_score,
        cwe_class=cwe_class,
        exploit_maturity=payload.exploit_maturity,
        has_public_poc=payload.has_public_poc,
        vendor_patch_status=payload.vendor_patch_status,
    )
    effective_epss = (
        epss_sub["substituted_epss"] if epss_sub["substituted"] else raw_epss
    )

    # Extract EPSS feature vector for drift monitoring
    epss_features_json = None
    try:
        from ml.epss_substitutor import get_last_feature_vector

        epss_fv = get_last_feature_vector()
        if epss_fv:
            epss_features_json = json.dumps(epss_fv)
    except Exception:
        logger.warning(
            "Failed to extract EPSS features for %s", payload.vulnerability_id
        )

    # ── Security context enrichment (Sprint 17) ─────────────────────
    telemetry = None
    network_ctx = None
    try:
        from integrations.synthetic_telemetry import get_telemetry_context

        telemetry = get_telemetry_context(
            cve_id=payload.vulnerability_id,
            hostname=payload.hostname,
            cvss_score=payload.cvss_score or 0.0,
            cisa_kev=bool(payload.cisa_kev) if hasattr(payload, "cisa_kev") else False,
            epss_score=effective_epss,
            description=payload.raw_description or "",
        )
    except Exception as e:
        logger.warning("Security telemetry enrichment failed: %s", e)

    try:
        from integrations.network_context import get_network_context

        network_ctx = get_network_context(
            hostname=payload.hostname,
            asset_ctx=asset_ctx,
        )
    except Exception as e:
        logger.warning("Network context enrichment failed: %s", e)

    # 5. Tier 0: deterministic routing
    _t1 = time.monotonic()

    # Fetch NVD data for reference count (already cached from get_cwe() above)
    nvd_data = get_nvd_data(payload.vulnerability_id)
    nvd_ref_count = nvd_data.get("nvd_reference_count", 0)

    t0_result = tier_0.evaluate_tier_0(
        cvss_score=payload.cvss_score,
        cisa_kev=payload.cisa_kev,
        epss_score=raw_epss,
        data_classification=data_classification,
        internet_facing=internet_facing,
        nvd_reference_count=nvd_ref_count,
        cwe_class=cwe_class,  # CWE-stratified EPSS threshold for low-severity auto-resolve
    )
    _t_tier_0 = time.monotonic() - _t1

    t1_result = None
    t2_result = None

    # 6. If ambiguous, run Tier 1
    tier_1_features_json = None
    _t_tier_1 = 0.0
    _t_tier_2 = 0.0
    if t0_result["routing"] == "escalated":
        _t2 = time.monotonic()
        features = build_feature_vector(
            payload,
            mission_tags,
            t0_result,
            telemetry=telemetry,
            network_ctx=network_ctx,
        )
        t1_result = tier_1.evaluate_tier_1(features)
        _t_tier_1 = time.monotonic() - _t2

        # Store encoded tabular features for ML drift monitoring
        from ingest_helpers import serialize_tabular_features

        tier_1_features_json = serialize_tabular_features(features)

        # 7a. RAG query with CWE context (CWE already classified above)
        if cwe_result:
            rag_result = query_rag(
                payload.hostname,
                cwe_class=cwe_result.get("cwe_class", ""),
            )
        else:
            rag_result = query_rag(payload.hostname)
        rag_context = rag_result.get("rag_context", "")

        # 7b. If still ambiguous, run Tier 2
        if t1_result["routing"] == "escalated":
            _t3 = time.monotonic()
            t2_result = await tier_2.evaluate_tier_2(
                cve_id=payload.vulnerability_id,
                hostname=payload.hostname,
                cvss_score=payload.cvss_score,
                description=payload.raw_description or "",
                rag_context=rag_context,
                cisa_kev=payload.cisa_kev,
                epss_score=raw_epss,
                cvss_vector=payload.cvss_vector or "",
                upstream_scores=t1_result,
                mission_tags=mission_tags,
                cwe_result=cwe_result,
            )
            _t_tier_2 = time.monotonic() - _t3

    # 7. Calculate final score
    scoring = calculate_final_score(
        cvss_score=payload.cvss_score,
        epss_score=raw_epss,
        mission_prevalence=mission_tags["mission_prevalence"],
        public_wellbeing=mission_tags["public_wellbeing_impact"],
        data_classification=data_classification,
        internet_facing=internet_facing,
        patch_available=nvd_data.get("patch_available", True),
        patch_applied=nvd_data.get("patch_applied", False),
        tier_1_result=t1_result,
        tier_2_result=t2_result,
        substituted_epss=effective_epss if epss_sub["substituted"] else None,
        telemetry_threat_score=telemetry.get("threat_score", 0.0) if telemetry else 0.0,
        network_blast_radius=network_ctx.get("blast_radius_score", 0.0)
        if network_ctx
        else 0.0,
        vulnerable_code_loaded=telemetry.get("process_evidence", {}).get(
            "is_loaded", None
        )
        if telemetry
        else None,
        confirmed_mitigated=False,  # Can be set by Tier 2 or human review in future
        confirmed_false_positive=False,
    )

    # 8. Determine tier routing text
    detection_tier = "Deterministic"
    if t1_result and t2_result:
        detection_tier = "SLM Tier"
    elif t1_result and not t2_result:
        detection_tier = "ML Tier"

    # Build trace dict
    _total = time.monotonic() - _t_start
    trace = {
        "pre_tier": {
            "tags": mission_tags,
            "confidence": mission_tags.get("mission_prevalence_confidence", 0.0),
            "latency_ms": round(_t_pre_tier * 1000, 2),
        },
        "tier_0": {
            "routing": t0_result.get("routing", ""),
            "reason": t0_result.get("resolution", ""),
            "latency_ms": round(_t_tier_0 * 1000, 2),
        },
        "tier_1": (
            {
                "exploitation_prob": t1_result.get("exploitation_probability", 0.0),
                "confidence": t1_result.get("confidence", 0.0),
                "routing": t1_result.get("routing", ""),
                "latency_ms": round(_t_tier_1 * 1000, 2),
            }
            if t1_result
            else None
        ),
        "tier_2": (
            {
                "called": True,
                "provider": getattr(tier_2, "LLM_PROVIDER", ""),
                "model": getattr(tier_2, "LLM_MODEL", ""),
                "text_conflict": t2_result.get("text_conflict", False),
                "confidence": t2_result.get("confidence", 0.0),
                "score_adjustment": t2_result.get("score_adjustment", 0),
                "tokens_in": t2_result.get("_usage", {}).get("tokens_in", 0),
                "tokens_out": t2_result.get("_usage", {}).get("tokens_out", 0),
                "cost_usd": t2_result.get("_usage", {}).get("cost_usd", 0.0),
                "latency_ms": round(_t_tier_2 * 1000, 2),
            }
            if t2_result
            else {"called": False}
        ),
        "scoring": {
            "final_score": scoring["total"],
            "risk_band": scoring["band"],
        },
        "total_latency_ms": round(_total * 1000, 2),
    }

    # Strip transient _usage key from t2_result before it reaches the DB
    if t2_result:
        t2_result.pop("_usage", None)

    # Build detection reason
    reason_parts = [f"{detection_tier}: CVSS {payload.cvss_score}"]
    if payload.cisa_kev:
        reason_parts.append("CISA KEV")
    if epss_sub["substituted"]:
        reason_parts.append(f"EPSS substituted ({raw_epss}->{effective_epss})")
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

    # 8b. MITRE ATT&CK techniques from CWE class
    mitre_techniques = lookup_mitre(cwe_class)

    # 8c. Advisory reference
    advisory = get_advisory(payload.vulnerability_id)
    advisory_ref_id = advisory.get("ref_id", "")
    advisory_quote = advisory.get("quote", "")

    # 8d. Summary paragraphs
    summary_paragraphs = _build_summaries(
        cve_id=payload.vulnerability_id,
        hostname=payload.hostname,
        detection_tier=detection_tier,
        total_score=scoring["total"],
        band=scoring["band"],
        data_classification=data_classification,
        mission=mission_tags["mission_prevalence"],
        wellbeing=mission_tags["public_wellbeing_impact"],
        internet_facing=internet_facing,
        role=asset_ctx.get("role", ""),
        network_zone=asset_ctx.get("network_zone", ""),
        description=payload.raw_description or "",
    )

    # 9. Prepare scoring weights for storage
    epss_weight_justification = (
        "Substituted from sector-adjusted score."
        if epss_sub["substituted"]
        else "Calculated from EPSS score."
    )
    weights = [
        {
            "name": "CVSS Base Score Contribution",
            "awarded": scoring["dimensions"]["cvss"],
            "max": 40,
            "justification": "Calculated from CVSS base score.",
            "is_substituted": False,
        },
        {
            "name": "EPSS Exploitability Contribution",
            "awarded": scoring["dimensions"]["epss"],
            "max": 20,
            "justification": epss_weight_justification,
            "is_substituted": epss_sub["substituted"],
        },
        {
            "name": "Asset Criticality Contribution",
            "awarded": scoring["dimensions"]["criticality"],
            "max": 20,
            "justification": "Based on data classification and mission tags.",
            "is_substituted": False,
        },
        {
            "name": "Exposure and Network Position",
            "awarded": scoring["dimensions"]["exposure"],
            "max": 12,
            "justification": "Based on network position and exposure analysis.",
            "is_substituted": False,
        },
        {
            "name": "Patch Availability and Remediation Complexity",
            "awarded": scoring["dimensions"]["patch"],
            "max": 5,
            "justification": "Based on patch availability and application status.",
            "is_substituted": False,
        },
        {
            "name": "ML Exploitation Probability Contribution",
            "awarded": scoring["dimensions"]["ml_exploitation"],
            "max": 10,
            "justification": "Calculated from XGBoost model exploitation probability prediction.",
            "is_substituted": False,
        },
        {
            "name": "Security Context",
            "awarded": scoring["dimensions"]["security_context"],
            "max": 5,
            "justification": "Based on telemetry threat score and network blast radius.",
            "is_substituted": False,
        },
    ]

    # 10. Build investigation notes
    notes = f"Auto-generated investigation notes for {payload.vulnerability_id} on {payload.hostname}.\n\n"
    notes += f"Pipeline routing: {detection_tier}.\n"
    notes += f"Tier 0 result: {t0_result['routing']} ({t0_result['resolution']}).\n"
    if epss_sub["substituted"]:
        notes += f"EPSS substitution: {raw_epss} -> {effective_epss} (confidence: {epss_sub['confidence']}).\n"
    if t1_result:
        notes += f"Tier 1 confidence: {t1_result['confidence']}, routing: {t1_result['routing']}.\n"
    if t2_result:
        notes += f"Tier 2 text conflict: {t2_result['text_conflict']}, confidence: {t2_result['confidence']}.\n"
    notes += f"\nFinal score: {scoring['total']} ({scoring['band']})."

    # 11. Audit selection for auto-resolved cases
    from audit import should_audit, select_for_audit

    # Determine effective routing for audit sampling:
    # If Tier 0 escalated and Tier 1 ran, use Tier 1's routing instead.
    effective_routing = t0_result["routing"]
    if t0_result["routing"] == "escalated" and t1_result:
        effective_routing = t1_result["routing"]
    audit_selected = should_audit(detection_tier, effective_routing)

    # 12. Insert into database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO vulnerabilities (
            vulnerability_id, hostname, cvss_score, cvss_vector, cisa_kev, epss_score,
            mission_prevalence, mission_prevalence_conf, public_wellbeing_impact, public_wellbeing_conf,
            tier_0_routing, tier_0_resolution,
            tier_1_confidence, tier_1_exploitation_prob, tier_1_routing,
            tier_2_text_conflict, tier_2_conflict_note, tier_2_rag_result, tier_2_confidence, tier_2_resolution_summary,
            priority_score, risk_band,
            cvss_contribution, epss_contribution, asset_criticality_contribution, exposure_contribution,
            patch_remediation_contribution, ml_exploitation_contribution, security_context_contribution,
            epss_substituted, epss_substituted_value, epss_substitution_confidence, epss_substitution_reason,
            data_classification, network_zone, interface_type, patch_cycle, last_patch_date, last_scan_date,
            operating_system, role, business_owner, technical_owner, registered_applications, dependent_assets,
            service_account, detection_tier, detection_reason,
            scanner_output_raw, weakness_template_raw, advisory_ref_id, advisory_quote, investigation_notes,
            mitre_techniques_json, scoring_weights_json, asset_registry_json, summary_paragraphs_json,
            tier_1_features,
            pre_tier_features,
            epss_features,
            telemetry_json, network_context_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?,
            ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?,
            ?, ?,
            ?
        )
    """,
        (
            payload.vulnerability_id,
            payload.hostname,
            payload.cvss_score,
            payload.cvss_vector,
            payload.cisa_kev,
            payload.epss_score,
            mission_tags["mission_prevalence"],
            mission_tags["mission_prevalence_confidence"],
            mission_tags["public_wellbeing_impact"],
            mission_tags["public_wellbeing_confidence"],
            t0_result["routing"],
            t0_result["resolution"],
            t1_result["confidence"] if t1_result else None,
            t1_result["exploitation_probability"] if t1_result else None,
            t1_result["routing"] if t1_result else None,
            t2_result["text_conflict"] if t2_result else False,
            t2_result["conflict_note"] if t2_result else None,
            t2_result["rag_result"] if t2_result else None,
            t2_result["confidence"] if t2_result else None,
            t2_result["resolution"] if t2_result else None,
            scoring["total"],
            scoring["band"],
            scoring["dimensions"]["cvss"],
            scoring["dimensions"]["epss"],
            scoring["dimensions"]["criticality"],
            scoring["dimensions"]["exposure"],
            scoring["dimensions"]["patch"],
            scoring["dimensions"]["ml_exploitation"],
            scoring["dimensions"]["security_context"],
            epss_sub["substituted"],
            effective_epss if epss_sub["substituted"] else None,
            epss_sub["confidence"] if epss_sub["substituted"] else None,
            epss_sub["reason"] if epss_sub["substituted"] else None,
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
            detection_tier,
            detection_reason,
            payload.scanner_output_raw or payload.raw_description or "",
            payload.weakness_template_raw or "",
            advisory_ref_id,
            advisory_quote,
            notes,
            json.dumps(mitre_techniques),
            json.dumps(weights),
            json.dumps(
                [
                    {"label": "Hostname", "value": payload.hostname},
                    {"label": "CVSS Score", "value": str(payload.cvss_score)},
                    {
                        "label": "EPSS Score",
                        "value": f"{raw_epss}"
                        + (" (not provided)" if not epss_available else "")
                        + (f" -> {effective_epss}" if epss_sub["substituted"] else ""),
                    },
                    {"label": "Data Classification", "value": data_classification},
                    {
                        "label": "Internet-Facing",
                        "value": "Yes" if internet_facing else "No",
                    },
                    {"label": "Tier", "value": detection_tier},
                    {
                        "label": "Network Zone",
                        "value": asset_ctx.get("network_zone", ""),
                    },
                    {"label": "Role", "value": asset_ctx.get("role", "")},
                    {
                        "label": "Operating System",
                        "value": asset_ctx.get("operating_system", ""),
                    },
                ]
            ),
            json.dumps(summary_paragraphs),
            tier_1_features_json,
            pre_tier_features_json,
            epss_features_json,
            json.dumps(telemetry) if telemetry else None,
            json.dumps(network_ctx) if network_ctx else None,
        ),
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # 13. Record audit selection for auto-resolved cases
    if audit_selected:
        select_for_audit(new_id)

    logger.info(
        "Ingest complete for %s on %s — score %d, band %s, tier %s",
        payload.vulnerability_id,
        payload.hostname,
        scoring["total"],
        scoring["band"],
        detection_tier,
        extra={"event": "ingest_complete"},
    )

    # 14. Build response
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

    from integrations.nvd import get_cve_freshness

    nvd_freshness = get_cve_freshness(payload.vulnerability_id)

    case_view = CaseViewData(
        summary_paragraphs=summary_paragraphs,
        mission_prevalence=[
            f"Mission Prevalence: {mission_tags['mission_prevalence']}",
            f"Public Well-Being Impact: {mission_tags['public_wellbeing_impact']}",
        ],
        mitre_techniques=mitre_techniques,
        text_conflict=t2_result["text_conflict"] if t2_result else False,
        text_conflict_note=t2_result["conflict_note"] if t2_result else "",
        scanner_output=html.escape(
            payload.scanner_output_raw or payload.raw_description or ""
        ),
        weakness_template=html.escape(payload.weakness_template_raw or ""),
        advisory_ref_id=advisory_ref_id,
        advisory_quote=advisory_quote,
        investigation_notes=notes,
        has_substitution=epss_sub["substituted"],
        substitution_block=SubstitutionBlock(
            original_epss=str(raw_epss)
            + (" (not provided)" if not epss_available else ""),
            substituted_epss=str(effective_epss),
            model_confidence=str(epss_sub["confidence"]),
            reason=epss_sub["reason"],
        ),
        score_gauge_value=scoring["total"],
        score_gauge_band=scoring["band"],
        gauge_band_colour=_band_colour(scoring["band"]),
        context_multiplier=scoring.get("context_multiplier", 1.0),
        scoring_weights=weights,
        nvd_freshness=nvd_freshness,
        asset_registry=[
            {"label": "Hostname", "value": payload.hostname},
            {"label": "CVSS Score", "value": str(payload.cvss_score)},
            {
                "label": "EPSS Score",
                "value": f"{raw_epss}"
                + (" (not provided)" if not epss_available else "")
                + (f" -> {effective_epss}" if epss_sub["substituted"] else ""),
            },
            {"label": "Data Classification", "value": data_classification},
            {"label": "Internet-Facing", "value": "Yes" if internet_facing else "No"},
            {"label": "Tier", "value": detection_tier},
        ],
    )

    if _verbose:
        return CaseResponse(
            queue_row=queue_row, case_view=case_view, trace_output=trace
        )
    return CaseResponse(queue_row=queue_row, case_view=case_view)


@router.post(
    "/api/ingest/batch",
    response_model=list[CaseResponse],
    response_model_exclude_none=True,
)
async def ingest_vulnerability_batch(
    payloads: list[IngestRequest],
    request: Request = None,
    user: dict = Depends(get_current_user_if_enabled),
):
    """Bulk ingest: accepts a list of IngestRequest, returns a list of CaseResponse.

    Each item is processed independently through the full pipeline.
    """
    _verbose = False
    if request is not None:
        _verbose = request.headers.get("X-TriageMate-Verbose", "").lower() == "true"
    results: list[CaseResponse] = []
    for item in payloads:
        result = await ingest_vulnerability(item, request=request)
        results.append(result)
    return results


@router.post("/api/ingest/tenable")
async def ingest_tenable(
    request: Request, user: dict = Depends(get_current_user_if_enabled)
):
    """Accept Tenable.io export JSON (single finding, webhook envelope, or batch list).

    Detection logic:
    - List → batch ingest via parse_tenable_batch
    - Dict with "type"+"finding" keys → webhook envelope, unwrapped via parse_tenable_webhook
    - Dict with "asset"+"plugin" keys → bare single finding via parse_tenable_webhook

    Returns a single CaseResponse for one finding or list[CaseResponse] for batch.
    """
    body_raw = await request.body()
    if len(body_raw) > 10_000_000:
        raise HTTPException(status_code=413, detail="Payload too large")
    body = json.loads(body_raw)

    if isinstance(body, list):
        requests = parse_tenable_batch(body)
        if not requests:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=400,
                content={
                    "detail": "No valid Tenable findings could be parsed from the batch"
                },
            )
        return await ingest_vulnerability_batch(requests)

    if isinstance(body, dict):
        parsed = parse_tenable_webhook(body)
        if parsed is None:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Unrecognized Tenable format. Expected an object with "
                    "'asset' and 'plugin' keys, or a webhook envelope with 'type' and 'finding'."
                },
            )
        return await ingest_vulnerability(parsed)

    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=400,
        content={"detail": "Expected a JSON object or array"},
    )


# ---------------------------------------------------------------------------
# Phase 3.3 — Demo API Endpoints (DEMO_MODE must be "true")
# ---------------------------------------------------------------------------


@router.get("/api/demo/scenarios")
async def list_demo_scenarios(user: dict = Depends(get_current_user_if_enabled)):
    """Return list of available demo scenarios (DEMO_MODE only)."""
    gate = _demo_only()
    if gate:
        return gate
    try:
        from integrations.demo_generator import get_scenarios_list

        return get_scenarios_list()
    except ImportError as e:
        return JSONResponse(
            status_code=500, content={"detail": f"Demo generator not available: {e}"}
        )


@router.post("/api/demo/generate")
async def generate_demo_findings(
    request: Request, user: dict = Depends(get_current_user_if_enabled)
):
    """Generate demo findings from a scenario or random wave (DEMO_MODE only)."""
    gate = _demo_only()
    if gate:
        return gate

    body = await request.json()
    mode = body.get("mode", "scenario")

    try:
        from integrations.demo_generator import (
            generate_scenario_findings,
            generate_random_wave,
            inject_enrichment,
        )
        from integrations.tenable import parse_tenable_batch
    except ImportError as e:
        return JSONResponse(
            status_code=500, content={"detail": f"Demo generator not available: {e}"}
        )

    if mode == "scenario":
        scenario_id = body.get("scenario_id")
        if not scenario_id:
            return JSONResponse(
                status_code=400, content={"detail": "scenario_id required"}
            )
        findings = generate_scenario_findings(scenario_id)
    elif mode == "random":
        size = body.get("size", "small")
        # Read current queue to avoid duplicates
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT vulnerability_id, hostname FROM vulnerabilities")
        existing = [
            {"vulnerability_id": r[0], "hostname": r[1]} for r in cursor.fetchall()
        ]
        conn.close()
        findings = generate_random_wave(size, existing_queue=existing)
    else:
        return JSONResponse(
            status_code=400, content={"detail": f"Unknown mode: {mode}"}
        )

    if not findings:
        return JSONResponse(
            status_code=400, content={"detail": "No findings generated"}
        )

    requests_list = parse_tenable_batch(findings)
    requests_list = inject_enrichment(requests_list)

    return await ingest_vulnerability_batch(requests_list)


@router.post("/api/ingest/clear")
async def clear_all_findings(user: dict = Depends(get_current_user_if_enabled)):
    """Archive all current findings and clear the queue (DEMO_MODE only).
    Destructive admin-only action.
    """
    gate = _demo_only()
    if gate:
        return gate

    conn = get_db()
    try:
        with conn:
            cursor = conn.cursor()
            # Archive: copy all from vulnerabilities to resolved_vulnerabilities
            cursor.execute("""
                INSERT INTO resolved_vulnerabilities (
                    original_id, vulnerability_id, hostname, cvss_score, cvss_vector,
                    cisa_kev, epss_score,
                    mission_prevalence, mission_prevalence_conf,
                    public_wellbeing_impact, public_wellbeing_conf,
                    tier_0_routing, tier_0_resolution,
                    tier_1_confidence, tier_1_exploitation_prob, tier_1_routing,
                    tier_2_text_conflict, tier_2_conflict_note, tier_2_rag_result,
                    tier_2_confidence, tier_2_resolution_summary,
                    priority_score, risk_band,
                    cvss_contribution, epss_contribution,
                    asset_criticality_contribution, exposure_contribution,
                    patch_remediation_contribution, ml_exploitation_contribution,
                    security_context_contribution,
                    tier_1_features,
                    pre_tier_features,
                    epss_features,
                    epss_substituted, epss_substituted_value,
                    epss_substitution_confidence, epss_substitution_reason,
                    data_classification, network_zone, interface_type,
                    patch_cycle, last_patch_date, last_scan_date,
                    operating_system, role, business_owner, technical_owner,
                    registered_applications, dependent_assets, service_account,
                    detection_tier, detection_reason,
                    scanner_output_raw, weakness_template_raw,
                    advisory_ref_id, advisory_quote, investigation_notes,
                    mitre_techniques_json, scoring_weights_json,
                    asset_registry_json, summary_paragraphs_json,
                    telemetry_json, network_context_json,
                    created_at, updated_at, last_recheck_date,
                    audit_selected, audit_result, audit_date,
                    resolved_at,
                    resolution_reason
                )
                SELECT id, vulnerability_id, hostname, cvss_score, cvss_vector,
                       cisa_kev, epss_score,
                       mission_prevalence, mission_prevalence_conf,
                       public_wellbeing_impact, public_wellbeing_conf,
                       tier_0_routing, tier_0_resolution,
                       tier_1_confidence, tier_1_exploitation_prob, tier_1_routing,
                       tier_2_text_conflict, tier_2_conflict_note, tier_2_rag_result,
                       tier_2_confidence, tier_2_resolution_summary,
                       priority_score, risk_band,
                       cvss_contribution, epss_contribution,
                       asset_criticality_contribution, exposure_contribution,
                       patch_remediation_contribution, ml_exploitation_contribution, security_context_contribution,
                       tier_1_features,
                       pre_tier_features,
                       epss_features,
                       epss_substituted, epss_substituted_value,
                       epss_substitution_confidence, epss_substitution_reason,
                       data_classification, network_zone, interface_type,
                       patch_cycle, last_patch_date, last_scan_date,
                       operating_system, role, business_owner, technical_owner,
                       registered_applications, dependent_assets, service_account,
                       detection_tier, detection_reason,
                       scanner_output_raw, weakness_template_raw,
                       advisory_ref_id, advisory_quote, investigation_notes,
                       mitre_techniques_json, scoring_weights_json,
                       asset_registry_json, summary_paragraphs_json,
                       telemetry_json, network_context_json,
                       created_at, updated_at, last_recheck_date,
                       audit_selected, audit_result, audit_date,
                       CURRENT_TIMESTAMP AS resolved_at,
                       'demo_clear'
                FROM vulnerabilities
            """)
            archived_count = cursor.rowcount
            cursor.execute("DELETE FROM vulnerabilities")
            deleted_count = cursor.rowcount

            if archived_count != deleted_count:
                raise RuntimeError(
                    f"Clear mismatch: archived {archived_count} but deleted {deleted_count}"
                )
    finally:
        conn.close()

    return {
        "status": "ok",
        "archived_count": archived_count,
        "message": f"{archived_count} findings archived. Queue cleared.",
    }
