import logging
import statistics
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Query
from database import get_db
import json
from pathlib import Path
from ingest_helpers import compliance_category as _compliance_category
from models import (
    QueueRow,
    QueueResponse,
    MetricsResponse,
    DriftMetricsResponse,
    MlDriftResponse,
    MlDriftFeature,
    ConceptDriftResponse,
    DistributionStats,
    RoutingCounts,
    TierRouting,
    PredictionDistribution,
    Window,
    TimeSeries,
    DailyTimeSeries,
    FeedbackSubmission,
    FeedbackResponse,
    AccuracyResponse,
)

logger = logging.getLogger("triagemate.queue")

router = APIRouter(tags=["Queue"])


@router.get("/api/system/retrain-status")
def get_retrain_status():
    """Return current retraining system status.

    Reports lock state, interval configuration, and drift threshold.
    """
    from scheduler import LOCK_FILE, RETRAIN_INTERVAL_HOURS, RETRAIN_DRIFT_THRESHOLD

    lock_held = LOCK_FILE.exists()
    lock_age_hours = None
    if lock_held:
        try:
            content = LOCK_FILE.read_text().strip()
            lock_time = datetime.fromisoformat(content)
            lock_age_hours = round(
                (datetime.now(timezone.utc) - lock_time).total_seconds() / 3600, 1
            )
        except Exception:
            pass

    return {
        "retrain_interval_hours": RETRAIN_INTERVAL_HOURS,
        "drift_threshold": RETRAIN_DRIFT_THRESHOLD,
        "lock_held": lock_held,
        "lock_age_hours": lock_age_hours,
    }


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
        compliance_str = (
            r["data_classification"] or "Category 1"
        )  # WAICP: OFFICIAL (was PRIS Act Category 1)
        cat = _compliance_category(compliance_str)
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


# ── ML Drift Monitoring ──────────────────────────────────────────────────────

# Load reference distributions once at module level for performance
_REFERENCE_DISTS_PATH = (
    Path(__file__).resolve().parent.parent / "ml" / "reference_distributions.json"
)
_REFERENCE_DISTS: dict | None = None


def _load_reference_dists() -> dict:
    """Lazy-load reference distributions from JSON file."""
    global _REFERENCE_DISTS
    if _REFERENCE_DISTS is not None:
        return _REFERENCE_DISTS
    if _REFERENCE_DISTS_PATH.exists():
        with open(_REFERENCE_DISTS_PATH) as f:
            _REFERENCE_DISTS = json.load(f)
        return _REFERENCE_DISTS
    return {"features": {}, "num_samples": 0}


@router.get("/api/drift/ml", response_model=MlDriftResponse)
def get_ml_drift():
    """Compute ML drift (PSI) for all ingested tier_1_features.

    Returns per-feature PSI values and a composite score comparing
    current inference data against the training reference distribution.
    """
    from analysis.drift import compute_drift
    import sqlite3 as _sqlite3

    reference_dists = _load_reference_dists()

    conn = get_db()
    cursor = conn.cursor()

    features_json_list = []
    try:
        cursor.execute(
            """
            SELECT tier_1_features FROM vulnerabilities
            WHERE tier_1_features IS NOT NULL
            UNION ALL
            SELECT tier_1_features FROM resolved_vulnerabilities
            WHERE tier_1_features IS NOT NULL
            """
        )
        for row in cursor.fetchall():
            try:
                feature_dict = json.loads(row["tier_1_features"])
                features_json_list.append(feature_dict)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
    except _sqlite3.OperationalError:
        # Column may not exist yet (early migration state) — return zero drift
        pass

    conn.close()

    result = compute_drift(features_json_list, reference_dists)

    return MlDriftResponse(
        features={
            name: MlDriftFeature(psi=f["psi"], status=f["status"])
            for name, f in result["features"].items()
        },
        composite_psi=result["composite_psi"],
        status=result["status"],
        total_samples=result["total_samples"],
    )


# ── EPSS Drift Monitoring ─────────────────────────────────────────────────────

_EPSS_REFERENCE_PATH = (
    Path(__file__).resolve().parent.parent / "ml" / "epss_reference_distributions.json"
)


@router.get("/api/drift/epss", response_model=MlDriftResponse)
def get_epss_drift():
    """Compute ML drift (PSI) for EPSS substitution model features.

    Returns per-feature PSI values and a composite score comparing
    current inference data against the training reference distribution.
    """
    from analysis.drift import compute_drift
    import sqlite3 as _sqlite3

    # Load EPSS reference distributions
    if _EPSS_REFERENCE_PATH.exists():
        with open(_EPSS_REFERENCE_PATH) as f:
            reference_dists = json.load(f)
    else:
        reference_dists = {"features": {}, "num_samples": 0}

    conn = get_db()
    cursor = conn.cursor()

    features_json_list = []
    try:
        cursor.execute("""
            SELECT epss_features FROM vulnerabilities
            WHERE epss_features IS NOT NULL
            UNION ALL
            SELECT epss_features FROM resolved_vulnerabilities
            WHERE epss_features IS NOT NULL
        """)
        for row in cursor.fetchall():
            try:
                feature_dict = json.loads(row["epss_features"])
                features_json_list.append(feature_dict)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
    except _sqlite3.OperationalError:
        # Column may not exist yet — return zero drift
        pass

    conn.close()

    result = compute_drift(features_json_list, reference_dists)

    return MlDriftResponse(
        features={
            name: MlDriftFeature(psi=f["psi"], status=f["status"])
            for name, f in result["features"].items()
        },
        composite_psi=result["composite_psi"],
        status=result["status"],
        total_samples=result["total_samples"],
    )


# ── Pre-Tier Drift Monitoring ────────────────────────────────────────────────

_PRETIER_REFERENCE_PATH = (
    Path(__file__).resolve().parent.parent
    / "ml"
    / "pre_tier_reference_distributions.json"
)


@router.get("/api/drift/pre-tier", response_model=MlDriftResponse)
def get_pretier_drift():
    """Compute ML drift (PSI) for Pre-Tier 60-dim features.

    Returns per-feature PSI values and a composite score comparing
    current inference data against the training reference distribution.
    """
    from analysis.drift import compute_drift
    import sqlite3 as _sqlite3

    # Load Pre-Tier reference distributions
    if _PRETIER_REFERENCE_PATH.exists():
        with open(_PRETIER_REFERENCE_PATH) as f:
            reference_dists = json.load(f)
    else:
        reference_dists = {"features": {}, "num_samples": 0}

    conn = get_db()
    cursor = conn.cursor()

    features_json_list = []
    try:
        cursor.execute("""
            SELECT pre_tier_features FROM vulnerabilities
            WHERE pre_tier_features IS NOT NULL
            UNION ALL
            SELECT pre_tier_features FROM resolved_vulnerabilities
            WHERE pre_tier_features IS NOT NULL
        """)
        for row in cursor.fetchall():
            try:
                feature_dict = json.loads(row["pre_tier_features"])
                features_json_list.append(feature_dict)
            except (json.JSONDecodeError, TypeError, KeyError):
                continue
    except _sqlite3.OperationalError:
        # Column may not exist yet — return zero drift
        pass

    conn.close()

    result = compute_drift(features_json_list, reference_dists)

    return MlDriftResponse(
        features={
            name: MlDriftFeature(psi=f["psi"], status=f["status"])
            for name, f in result["features"].items()
        },
        composite_psi=result["composite_psi"],
        status=result["status"],
        total_samples=result["total_samples"],
    )


# ── Concept Drift — Prediction Distribution ─────────────────────────────


@router.get("/api/drift/concept", response_model=ConceptDriftResponse)
def get_concept_drift(days: int = Query(30, ge=1, le=365)):
    """Return prediction distribution metrics over a rolling window.

    Queries resolved_vulnerabilities for records within the time window
    and computes statistics on tier_1_exploitation_prob, tier_1_confidence,
    routing decisions, and tier routing breakdown.
    """
    conn = get_db()
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        rows = conn.execute(
            """
            SELECT tier_1_exploitation_prob, tier_1_confidence, tier_1_routing,
                   detection_tier, tier_0_resolution, created_at
            FROM resolved_vulnerabilities
            WHERE created_at >= ?
              AND tier_1_exploitation_prob IS NOT NULL
            ORDER BY created_at
        """,
            (cutoff,),
        ).fetchall()

        if not rows:
            return ConceptDriftResponse(
                prediction_distribution=PredictionDistribution(
                    exploitation_probability=DistributionStats(
                        mean=0.0, std=0.0, p50=0.0, p95=0.0
                    ),
                    confidence=DistributionStats(mean=0.0, std=0.0, p50=0.0, p95=0.0),
                    routing=RoutingCounts(auto_resolved=0, escalated=0),
                    tier_routing=TierRouting(),
                ),
                window=Window(days=days, total_samples=0),
                time_series=TimeSeries(daily=[]),
            )

        probs: list[float] = []
        confs: list[float] = []
        auto_resolved = 0
        escalated = 0
        tier_counts: dict[str, int] = {
            "tier_0_kev": 0,
            "tier_0_epss": 0,
            "tier_1_xgboost": 0,
            "tier_2_llm": 0,
            "tier_3_review": 0,
        }
        daily_data: dict[str, dict] = {}

        for row in rows:
            prob = row["tier_1_exploitation_prob"]
            conf = row["tier_1_confidence"]
            routing = row["tier_1_routing"]
            det_tier = row["detection_tier"]
            t0_res = row["tier_0_resolution"]
            created = row["created_at"]

            if prob is not None:
                probs.append(prob)
            if conf is not None:
                confs.append(conf)

            # Routing classification
            if routing == "auto_resolved":
                auto_resolved += 1
            elif routing == "escalated":
                escalated += 1

            # Tier routing mapping
            if det_tier == "Deterministic":
                if t0_res and "kev" in str(t0_res).lower():
                    tier_counts["tier_0_kev"] += 1
                else:
                    tier_counts["tier_0_epss"] += 1
            elif det_tier == "ML Tier":
                tier_counts["tier_1_xgboost"] += 1
            elif det_tier == "SLM Tier":
                tier_counts["tier_2_llm"] += 1
            else:
                tier_counts["tier_3_review"] += 1

            # Daily aggregation
            date_str = created[:10] if created else "unknown"
            if date_str not in daily_data:
                daily_data[date_str] = {"probs": [], "n": 0}
            if prob is not None:
                daily_data[date_str]["probs"].append(prob)
            daily_data[date_str]["n"] += 1

        probs_sorted = sorted(probs)
        confs_sorted = sorted(confs)

        def _stats(arr: list[float]) -> DistributionStats:
            if not arr:
                return DistributionStats(mean=0.0, std=0.0, p50=0.0, p95=0.0)
            return DistributionStats(
                mean=round(statistics.mean(arr), 4),
                std=round(statistics.stdev(arr), 4) if len(arr) > 1 else 0.0,
                p50=round(arr[len(arr) // 2], 4),
                p95=round(arr[min(int(len(arr) * 0.95), len(arr) - 1)], 4),
            )

        return ConceptDriftResponse(
            prediction_distribution=PredictionDistribution(
                exploitation_probability=_stats(probs_sorted),
                confidence=_stats(confs_sorted),
                routing=RoutingCounts(auto_resolved=auto_resolved, escalated=escalated),
                tier_routing=TierRouting(**tier_counts),
            ),
            window=Window(days=days, total_samples=len(rows)),
            time_series=TimeSeries(
                daily=[
                    DailyTimeSeries(
                        date=date,
                        mean_prob=(
                            round(sum(d["probs"]) / len(d["probs"]), 4)
                            if d["probs"]
                            else 0.0
                        ),
                        n=d["n"],
                    )
                    for date, d in sorted(daily_data.items())
                ]
            ),
        )
    finally:
        conn.close()


# ── Ground-Truth Feedback (Stubs — Schema Deferred to Sprint 20) ────────


@router.post("/api/feedback/{vulnerability_id}")
def submit_feedback(vulnerability_id: str, feedback: FeedbackSubmission):
    """Submit ground-truth feedback for a prediction.

    NOTE: Schema migration for persistent storage is planned Sprint 20.
    For now, feedback is validated and logged.
    """
    logger.info(
        "Ground truth feedback received for %s: exploited=%s",
        vulnerability_id,
        feedback.exploited,
        extra={"event": "ground_truth_feedback"},
    )
    return FeedbackResponse(
        status="accepted",
        vulnerability_id=vulnerability_id,
        note="Feedback recorded. Schema migration pending Sprint 20.",
    )


@router.get("/api/drift/accuracy")
def get_accuracy():
    """Return accuracy metrics where ground truth is available.

    Stub — returns zero-data until ground truth schema migration in Sprint 20.
    """
    return AccuracyResponse(
        status="insufficient_data",
        samples_with_ground_truth=0,
        message="Ground truth collection requires database schema migration (planned Sprint 20)",
    )
