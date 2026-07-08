"""
Train EPSS substitution model v4 using sector-aware synthetic findings.

KEY IMPROVEMENT OVER V3:
  v3 trained on purely synthetic data generated from random real EPSS baselines
  with no sector grounding. v4 uses findings generated from actual research
  references — CVE-* patterns mapped to real WA government agencies with
  realistic context (CVSS, KEV, exploit maturity, PoC, patch status) and a
  ground-truth target (sector_exploitation_rate) that reflects how likely a
  CVE is to be exploited against a specific sector.

  The model learns sector-specific exploitation patterns: health and police
  CVEs get higher predicted scores than the same CVE on lower-risk sectors.

  v4 uses the same 37-feature layout as v2/v3 for drop-in compatibility:
    [0]   raw_epss
    [1]   cvss_score
    [2]   exploit_maturity
    [3]   cisa_kev
    [4]   has_public_poc
    [5]   vendor_patch_status
    [6..16]  agency one-hot (11 slots: 10 agencies + unknown)
    [17..36] CWE one-hot (20 classes)

Exports to backend/ml/epss_model_v4.pkl
"""

import logging
import os
import sys

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error
from xgboost import XGBRegressor
import joblib

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from database import get_db, init_db

logger = logging.getLogger(__name__)

# ── Constants (identical to v2/v3 for drop-in compatibility) ─────────────────
AGENCIES = [
    "health",
    "transport",
    "education",
    "sharedservices",
    "communities",
    "police",
    "finance",
    "watercorporation",
    "dpird",
    "justice",
]

CWES = [
    # Original 11
    "CWE-78",
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-434",
    "CWE-862",
    "CWE-787",
    "CWE-125",
    "CWE-20",
    "CWE-200",
    "CWE-287",
    # New additions (9 more = 20 total)
    "CWE-306",
    "CWE-269",
    "CWE-295",
    "CWE-611",
    "CWE-918",
    "CWE-190",
    "CWE-416",
    "CWE-476",
    "CWE-352",
]

RANDOM_SEED = 42


def _build_feature_vector_v4(sample: dict) -> list:
    """37-feature vector matching v2/v3 layout exactly.

    Layout (37 elements):
      [0]    raw_epss           (continuous)
      [1]    cvss_score         (continuous)
      [2]    exploit_maturity   (ordinal 0-3)
      [3]    cisa_kev           (binary)
      [4]    has_public_poc     (binary)
      [5]    vendor_patch_status (ordinal 0-2)
      [6..16]  agency OHE       (11 slots: 10 agencies + unknown)
      [17..36] CWE OHE          (20 slots)

    This matches epss_substitutor._build_feature_vector_v2 exactly so
    v4 can be a drop-in replacement at inference time.
    """
    features = []
    features.append(sample["raw_epss"])
    features.append(sample["cvss_score"])
    features.append(sample["exploit_maturity"])
    features.append(1.0 if sample["cisa_kev"] else 0.0)
    features.append(1.0 if sample.get("has_public_poc", False) else 0.0)
    features.append(sample["vendor_patch_status"])
    for agency in AGENCIES + ["unknown"]:
        features.append(1.0 if sample["agency"] == agency else 0.0)
    for cwe in CWES:
        features.append(1.0 if sample.get("cwe_class", "") == cwe else 0.0)
    return features


def get_feature_names_v4() -> list:
    """Ordered list of v4 feature names (same layout as v2/v3)."""
    names = [
        "raw_epss",
        "cvss_score",
        "exploit_maturity",
        "cisa_kev",
        "has_public_poc",
        "vendor_patch_status",
    ]
    for agency in AGENCIES + ["unknown"]:
        names.append(f"agency_{agency}")
    for cwe in CWES:
        names.append(f"cwe_{cwe}")
    return names


def load_training_data() -> tuple:
    """Load training data from synthetic_findings table.

    Returns:
        X: ndarray (n_samples, 37)
        y: ndarray (n_samples,) — sector_exploitation_rate
        samples: list of dict (for inspection)
    """
    init_db()
    db = get_db()
    try:
        rows = db.execute(
            "SELECT cve_id, hostname, cvss_score, epss_score, cisa_kev, "
            "cwe_class, sector, agency, exploit_maturity, has_public_poc, "
            "vendor_patch_status, source_research_ref "
            "FROM synthetic_findings"
        ).fetchall()
    finally:
        db.close()

    if not rows:
        raise ValueError(
            "No synthetic findings found. Run generate_synthetic_findings.py first."
        )

    logger.info("Loaded %d findings from synthetic_findings table", len(rows))

    # We need the sector_exploitation_rate. Since we recompute it here for
    # reproducibility, we replicate the formula from generate_synthetic_findings.
    # But the findings now have the target stored as a hidden field in the
    # insertion — actually, we stored it separately. Let's recompute consistently.
    # The target formula is deterministic given the inputs, so we recompute here.
    # (We use the same formula as the generator for consistency.)
    samples = []
    targets = []

    for row in rows:
        raw_epss = float(row["epss_score"])
        cvss_score = float(row["cvss_score"])
        cisa_kev = bool(row["cisa_kev"])
        agency = str(row["agency"])
        cwe_class = str(row["cwe_class"] or "")
        exploit_maturity = int(row["exploit_maturity"])
        has_public_poc = bool(row["has_public_poc"])
        vendor_patch_status = int(row["vendor_patch_status"])

        # Recompute sector_exploitation_rate (same formula as generator)
        target = _compute_exploitation_rate(
            raw_epss=raw_epss,
            cvss_score=cvss_score,
            cisa_kev=cisa_kev,
            agency=agency,
            exploit_maturity=exploit_maturity,
            has_public_poc=has_public_poc,
            vendor_patch_status=vendor_patch_status,
        )

        samples.append(
            {
                "raw_epss": raw_epss,
                "cvss_score": cvss_score,
                "cisa_kev": cisa_kev,
                "has_public_poc": has_public_poc,
                "vendor_patch_status": vendor_patch_status,
                "exploit_maturity": exploit_maturity,
                "agency": agency,
                "cwe_class": cwe_class,
            }
        )
        targets.append(target)

    X = np.array([_build_feature_vector_v4(s) for s in samples])
    y = np.array(targets)

    logger.info(
        "Feature matrix: %d samples x %d features. Target: [%.4f, %.4f], mean=%.4f",
        X.shape[0],
        X.shape[1],
        y.min(),
        y.max(),
        y.mean(),
    )

    return X, y, samples


def _compute_exploitation_rate(
    raw_epss: float,
    cvss_score: float,
    cisa_kev: bool,
    agency: str,
    exploit_maturity: int,
    has_public_poc: bool,
    vendor_patch_status: int,
) -> float:
    """Compute sector-specific exploitation rate (ground truth target).

    Matches the formula in generate_synthetic_findings.py exactly.
    """
    # Sector risk profiles
    sector_risk_map = {
        "health": 0.25,
        "police": 0.25,
        "justice": 0.25,
        "transport": 0.15,
        "finance": 0.15,
        "sharedservices": 0.15,
        "communities": 0.15,
        "education": 0.10,
        "dpird": 0.05,
        "watercorporation": 0.05,
    }

    # EPSS foundation
    base = raw_epss * 0.35

    # CVSS band
    if cvss_score >= 9.0:
        cvss_contrib = 0.25
    elif cvss_score >= 7.0:
        cvss_contrib = 0.15
    elif cvss_score >= 4.0:
        cvss_contrib = 0.08
    else:
        cvss_contrib = 0.02

    kev_boost = 0.20 if cisa_kev else 0.0
    sector_boost = sector_risk_map.get(agency, 0.05)
    maturity_boost = exploit_maturity * 0.04
    poc_boost = 0.04 if has_public_poc else 0.0

    if vendor_patch_status == 2:
        patch_penalty = 0.0
    elif vendor_patch_status == 1:
        patch_penalty = 0.03
    else:
        patch_penalty = 0.06

    target = (
        base
        + cvss_contrib
        + kev_boost
        + sector_boost
        + maturity_boost
        + poc_boost
        - patch_penalty
    )
    target += np.random.default_rng(RANDOM_SEED).normal(0, 0.02)
    return round(max(0.001, min(0.99, target)), 4)


def _compute_also_from_v3_model(cve_ids: list[str]) -> float:
    """Placeholder — not used for training, only for comparison."""
    return 0.0


def train():
    """Run the full training pipeline. Returns (r2, rmse)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    logger.info("=" * 60)
    logger.info("  EPSS Substitution Model v4 — Training")
    logger.info("  (sector-aware, grounded in research references)")
    logger.info("=" * 60)

    # 1. Load training data from DB
    X, y, samples = load_training_data()
    n_features = X.shape[1]

    # 2. Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED
    )
    logger.info("Train: %d, Test: %d samples", X_train.shape[0], X_test.shape[0])

    # 3. Train XGBoost regressor (same hyperparams as v3)
    model = XGBRegressor(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=RANDOM_SEED,
        verbosity=0,
    )
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    # 4. Evaluate
    y_pred = model.predict(X_test)
    r2 = r2_score(y_test, y_pred)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))

    y_train_pred = model.predict(X_train)
    train_r2 = r2_score(y_train, y_train_pred)
    train_rmse = np.sqrt(mean_squared_error(y_train, y_train_pred))

    logger.info("─" * 60)
    logger.info("Model Performance:")
    logger.info("  Train R²  = %.4f", train_r2)
    logger.info("  Test  R²  = %.4f", r2)
    logger.info("  Train RMSE = %.4f", train_rmse)
    logger.info("  Test  RMSE = %.4f", rmse)

    # 5. Feature importance
    names = get_feature_names_v4()
    importances = sorted(
        zip(names, model.feature_importances_),
        key=lambda x: -x[1],
    )
    logger.info("─" * 60)
    logger.info("Top 10 feature importances:")
    for name, imp in importances[:10]:
        logger.info("  %s: %.4f", name, imp)

    # 6. Export
    output_dir = os.path.dirname(__file__)
    artifact = {
        "model": model,
        "feature_names": names,
        "agencies": AGENCIES,
        "cwes": CWES,
        "metadata": {
            "version": "v4",
            "r2": float(r2),
            "r2_train": float(train_r2),
            "rmse": float(rmse),
            "rmse_train": float(train_rmse),
            "n_features": n_features,
            "n_agencies": len(AGENCIES),
            "n_cwes": len(CWES),
            "training_source": "synthetic_findings_v4",
            "n_training_samples": len(X),
            "training_date": __import__("datetime").datetime.now().isoformat(),
        },
    }
    out_path = os.path.join(output_dir, "epss_model_v4.pkl")
    joblib.dump(artifact, out_path)
    size_kb = os.path.getsize(out_path) / 1024
    logger.info("Exported v4 model to %s (%.1f KB)", out_path, size_kb)

    # 7. Smoke tests
    logger.info("─" * 60)
    logger.info("Smoke tests on known CVE patterns:")
    test_cases = [
        # (raw_epss, cvss, kev, cwe, agency, maturity, poc, patch)
        # KEV + high CVSS + OS command injection on health — high risk
        (0.95, 9.0, True, "CWE-78", "health", 3, True, 0),
        # No signals, unknown agency — should stay near baseline
        (0.02, 5.0, False, "CWE-79", "unknown", 0, False, 0),
        # High signals across the board
        (0.15, 9.5, True, "CWE-89", "transport", 3, True, 2),
        # CWE-434 (file upload) on police — high sector premium
        (0.01, 7.5, False, "CWE-434", "police", 0, False, 0),
        # Moderate signals — mild uplift expected
        (0.08, 6.5, False, "CWE-22", "education", 1, True, 1),
        # Very low EPSS + no signals — should remain low
        (0.001, 4.0, False, "CWE-200", "finance", 0, False, 0),
    ]
    for raw, cvss, kev, cwe, agency, maturity, poc, patch in test_cases:
        feat = _build_feature_vector_v4(
            {
                "raw_epss": raw,
                "cvss_score": cvss,
                "exploit_maturity": maturity,
                "cisa_kev": kev,
                "has_public_poc": poc,
                "vendor_patch_status": patch,
                "cwe_class": cwe,
                "agency": agency,
            }
        )
        vec = np.array([feat])
        pred = float(model.predict(vec)[0])
        diff = abs(pred - raw)
        substituted = diff >= 0.1
        logger.info(
            "  raw=%.4f cvss=%.1f kev=%d mat=%d poc=%d patch=%d "
            "cwe=%-8s agency=%-15s -> pred=%.4f (sub=%s)",
            raw,
            cvss,
            int(kev),
            maturity,
            int(poc),
            patch,
            cwe,
            agency,
            pred,
            substituted,
        )

    # 8. Compare with v3 performance (if v3 model exists)
    v3_path = os.path.join(output_dir, "epss_model_v3.pkl")
    if os.path.isfile(v3_path):
        try:
            v3_artifact = joblib.load(v3_path)
            v3_model = v3_artifact["model"]
            y_pred_v3 = v3_model.predict(X_test)
            v3_r2 = r2_score(y_test, y_pred_v3)
            v3_rmse = np.sqrt(mean_squared_error(y_test, y_pred_v3))
            v3_mae = np.mean(np.abs(y_test - y_pred_v3))
            v4_mae = np.mean(np.abs(y_test - y_pred))

            logger.info("─" * 60)
            logger.info("Comparison: v4 vs v3 on v4 test set:")
            logger.info("  Metric          v4        v3        Δ")
            logger.info(
                "  R²              %.4f     %.4f     %+.4f", r2, v3_r2, r2 - v3_r2
            )
            logger.info(
                "  RMSE            %.4f     %.4f     %+.4f",
                rmse,
                v3_rmse,
                rmse - v3_rmse,
            )
            logger.info(
                "  MAE             %.4f     %.4f     %+.4f",
                v4_mae,
                v3_mae,
                v4_mae - v3_mae,
            )
        except Exception as exc:
            logger.warning("Could not compare with v3: %s", exc)

    logger.info("=" * 60)
    return r2, rmse


if __name__ == "__main__":
    r2, rmse = train()
    print(f"\n  v4 model: R²={r2:.4f}, RMSE={rmse:.4f}")
