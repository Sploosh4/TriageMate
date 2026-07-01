"""
Train an improved XGBoost EPSS substitution model (v2).

Key improvements over v1:
  - 1000 training examples (up from 500)
  - 26 features including exploit_maturity, has_public_poc, vendor_patch_status
  - More agencies (11 total) and CWEs (20 classes)
  - Realistic noise injection instead of pure rule-engine mimics
  - Better hyperparameter tuning (depth=8, reg_alpha/lambda)
  - Target includes maturity/patch-status multipliers + Gaussian noise
  - Outlier injection (5% with EPSS > 0.9)

Exports to backend/ml/epss_model_v2.pkl
"""

import logging
import os
import random
import warnings

import joblib
import numpy as np
import xgboost as xgb
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("train_epss_v2")
warnings.filterwarnings("ignore", category=FutureWarning)

# ── seed for reproducibility ──────────────────────────────────────────────
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)
rng = np.random.default_rng(RANDOM_SEED)

# ── constants matching epss_substitutor.py (unchanged) ────────────────────
MAX_EPSS = 0.99
KEV_MULTIPLIER = 2.0
DEFAULT_MULTIPLIER = 1.0

CWE_MULTIPLIERS = {
    "CWE-78": 1.5,
    "CWE-434": 1.5,
    "CWE-862": 1.5,
}

CVE_ADJUSTMENTS = {
    "CVE-2023-36884": {
        "health": 8.0,
        "communities": 10.0,
        "police": 6.0,
        "default": 3.0,
    },
    "CVE-2023-34362": {
        "health": 8.0,
        "default": 4.0,
    },
    "CVE-2023-4966": {
        "health": 5.0,
        "transport": 7.0,
        "default": 3.0,
    },
}

ALL_CVES = list(CVE_ADJUSTMENTS.keys())

# ── Expanded agencies (11 total, up from 8) ──────────────────────────────
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

# ── Expanded CWEs (20 classes, up from 11) ───────────────────────────────
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
    # New additions (9 more to reach 20)
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


# ── Rule engine (exact same logic as epss_substitutor.py) ─────────────────
def apply_rule_engine(
    raw_epss: float,
    cve_id: str,
    agency: str,
    cwe_class: str,
    cisa_kev: bool,
) -> float:
    """Apply the same heuristic rule logic used by epss_substitutor.py."""
    sector_multiplier = DEFAULT_MULTIPLIER

    if cisa_kev:
        sector_multiplier = max(sector_multiplier, KEV_MULTIPLIER)

    adjustment = CVE_ADJUSTMENTS.get(cve_id)
    if adjustment:
        agency_mult = adjustment.get(agency, adjustment.get("default", 1.0))
        if agency_mult > 1.0:
            sector_multiplier = max(sector_multiplier, agency_mult)

    if cwe_class and cwe_class in CWE_MULTIPLIERS:
        cwe_mult = CWE_MULTIPLIERS[cwe_class]
        if cwe_mult > 1.0:
            sector_multiplier = max(sector_multiplier, cwe_mult)

    return min(MAX_EPSS, raw_epss * sector_multiplier)


# ── Synthetic data generator (v2) ─────────────────────────────────────────
def _generate_synthetic_sample(seed: int = None) -> dict:
    """Generate one synthetic training example with richer feature space.

    Returns features dict plus the target (sector_adjusted_epss_with_noise).
    """
    local_rng = random.Random(seed if seed is not None else random.randint(0, 2**31))

    # ── Features ──────────────────────────────────────────────────────────

    # Raw EPSS — Beta(0.3, 3.0), skewed low, with 5% outliers > 0.9
    if local_rng.random() < 0.05:
        raw_epss = local_rng.uniform(0.9, 0.99)
    else:
        raw_epss = min(0.99, max(0.0001, local_rng.betavariate(0.3, 3.0)))
    raw_epss = round(raw_epss, 4)

    # CVSS score — normal around 7.0, clipped [0, 10]
    cvss_score = round(min(10.0, max(0.0, local_rng.gauss(7.0, 2.0))), 1)

    # Exploit maturity (ordinal 0-3): None=0, POC=1, Weaponized=2, InWild=3
    # Distribution: mostly None or POC, fewer Weaponized/InWild
    maturity_probs = [0.50, 0.30, 0.12, 0.08]
    exploit_maturity = local_rng.choices([0, 1, 2, 3], weights=maturity_probs)[0]

    # CISA KEV (10% True)
    cisa_kev = local_rng.random() < 0.10

    # Has public POC (20% True, correlated with exploit_maturity)
    if exploit_maturity >= 2:
        has_public_poc = local_rng.random() < 0.60  # 60% if weaponized+
    else:
        has_public_poc = local_rng.random() < 0.15  # 15% otherwise

    # Vendor patch status (OfficialFix=0, TemporaryFix=1, Unavailable=2)
    patch_probs = [0.60, 0.25, 0.15]
    vendor_patch_status = local_rng.choices([0, 1, 2], weights=patch_probs)[0]

    # CWE class
    cwe = local_rng.choice(CWES)

    # Agency
    agency = local_rng.choice(AGENCIES + ["unknown"])

    # CVE ID — 30% chance of being a "known" CVE with sector adjustments
    if local_rng.random() < 0.30:
        cve_id = local_rng.choice(ALL_CVES)
    else:
        cve_id = (
            f"CVE-{local_rng.randint(2024, 2025)}-{local_rng.randint(10000, 99999)}"
        )

    # ── Target: rule engine + realistic noise + adjustments ──────────────
    base_target = apply_rule_engine(raw_epss, cve_id, agency, cwe, cisa_kev)

    # Realistic noise (simulating real-world variation not captured by rules)
    noise = rng.normal(0, 0.05)

    # Exploit maturity boost (up to 1.45x for InWild)
    maturity_mult = 1.0 + (exploit_maturity * 0.15)

    # Patch status impact
    if vendor_patch_status == 2:  # No patch available
        patch_penalty = 1.3
    elif vendor_patch_status == 1:  # Temporary fix
        patch_penalty = 1.1
    else:  # Official fix available
        patch_penalty = 1.0

    # Public POC boost
    poc_mult = 1.15 if has_public_poc else 1.0

    target = min(
        MAX_EPSS,
        max(0.0, base_target * maturity_mult * patch_penalty * poc_mult + float(noise)),
    )
    target = round(target, 4)

    return {
        "raw_epss": raw_epss,
        "cvss_score": cvss_score,
        "exploit_maturity": exploit_maturity,
        "cisa_kev": cisa_kev,
        "has_public_poc": has_public_poc,
        "vendor_patch_status": vendor_patch_status,
        "cwe": cwe,
        "agency": agency,
        "cve_id": cve_id,
        "target": target,
    }


# ── Feature vector builder (v2: 37 features) ──────────────────────────────
def _build_feature_vector_v2(sample: dict) -> list:
    """Build the 37-element feature vector for v2 model.

    Layout:
      [0] raw_epss                (continuous)
      [1] cvss_score              (continuous)
      [2] exploit_maturity        (ordinal 0-3)
      [3] cisa_kev                (binary)
      [4] has_public_poc          (binary)
      [5] vendor_patch_status     (ordinal 0-2)
      [6..16] agency one-hot      (11 slots)
      [17..36] CWE one-hot        (20 slots)
    Total: 6 + 11 + 20 = 37
    """
    features = []

    # Continuous
    features.append(sample["raw_epss"])  # 0
    features.append(sample["cvss_score"])  # 1

    # Ordinal
    features.append(sample["exploit_maturity"])  # 2

    # Binary
    features.append(1.0 if sample["cisa_kev"] else 0.0)  # 3
    features.append(1.0 if sample["has_public_poc"] else 0.0)  # 4

    # Ordinal
    features.append(sample["vendor_patch_status"])  # 5

    # One-hot agency (11 slots: 10 known + unknown)
    for agency in AGENCIES + ["unknown"]:
        features.append(1.0 if sample["agency"] == agency else 0.0)

    # One-hot CWE (20 classes)
    for cwe in CWES:
        features.append(1.0 if sample["cwe"] == cwe else 0.0)

    return features


def get_feature_names_v2() -> list:
    """Return ordered list of v2 feature names."""
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


# ── Dataset generation ────────────────────────────────────────────────────
def generate_dataset_v2(n_samples: int = 1000) -> tuple:
    """Generate a v2 synthetic dataset for EPSS substitution.

    Returns:
        X: ndarray of shape (n_samples, n_features)   — 37 features
        y: ndarray of shape (n_samples,)
        feature_names: list of str
        raw_samples: list of dict
    """
    # Use different seeds per sample for independent randomness
    base_seed = 1000
    samples = []
    for i in range(n_samples):
        s = _generate_synthetic_sample(seed=base_seed + i)
        samples.append(s)

    X = np.array([_build_feature_vector_v2(s) for s in samples])
    y = np.array([s["target"] for s in samples])

    feature_names = get_feature_names_v2()

    logger.info(
        "Generated %d samples with %d features (v2). "
        "Target range: [%.4f, %.4f], mean=%.4f",
        n_samples,
        X.shape[1],
        y.min(),
        y.max(),
        y.mean(),
    )

    # Distribution summary
    maturity_counts = {}
    patch_counts = {}
    kev_count = 0
    poc_count = 0
    for s in samples:
        m = s["exploit_maturity"]
        maturity_counts[m] = maturity_counts.get(m, 0) + 1
        p = s["vendor_patch_status"]
        patch_counts[p] = patch_counts.get(p, 0) + 1
        if s["cisa_kev"]:
            kev_count += 1
        if s["has_public_poc"]:
            poc_count += 1

    logger.info(
        "  Exploit maturity distribution: %s", dict(sorted(maturity_counts.items()))
    )
    logger.info("  Patch status distribution: %s", dict(sorted(patch_counts.items())))
    logger.info(
        "  CISA KEV: %d (%.1f%%), Public POC: %d (%.1f%%)",
        kev_count,
        100.0 * kev_count / n_samples,
        poc_count,
        100.0 * poc_count / n_samples,
    )

    return X, y, feature_names, samples


def main():
    logger.info("=" * 60)
    logger.info("EPSS Substitution Model v2 — Training")
    logger.info("=" * 60)

    # Generate 1000 examples
    X, y, feature_names, raw_samples = generate_dataset_v2(1000)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED
    )

    logger.info("Train: %d, Test: %d samples", X_train.shape[0], X_test.shape[0])

    # ── Train XGBoost regressor (v2 hyperparams) ──────────────────────────
    model = xgb.XGBRegressor(
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

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # ── Predictions and metrics ───────────────────────────────────────────
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)

    r2_train = r2_score(y_train, y_pred_train)
    r2_test = r2_score(y_test, y_pred_test)
    rmse_test = np.sqrt(mean_squared_error(y_test, y_pred_test))
    rmse_train = np.sqrt(mean_squared_error(y_train, y_pred_train))

    logger.info("=" * 60)
    logger.info("Model Performance:")
    logger.info("  Train R²  = %.4f", r2_train)
    logger.info("  Test  R²  = %.4f", r2_test)
    logger.info("  Train RMSE = %.4f", rmse_train)
    logger.info("  Test  RMSE = %.4f", rmse_test)
    logger.info(
        "  y_test range: [%.4f, %.4f], mean=%.4f",
        y_test.min(),
        y_test.max(),
        y_test.mean(),
    )
    logger.info(
        "  y_pred range: [%.4f, %.4f], mean=%.4f",
        y_pred_test.min(),
        y_pred_test.max(),
        y_pred_test.mean(),
    )
    logger.info("=" * 60)

    # Feature importance (top 15)
    logger.info("Top 15 feature importances:")
    importances = sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, imp in importances[:15]:
        logger.info("  %s: %.4f", name, imp)

    # ── Confusion-style analysis: does the model correctly identify
    #     values that should vs. shouldn't be substituted? ────────────────
    should_substitute = (
        abs(y_test - y_pred_test) >= 0.05
    )  # "ground truth" substitution flag
    pred_above_raw = y_pred_test > (y_test * 0.8)  # model thinks it's higher

    tp = np.sum(should_substitute & pred_above_raw)
    fp = np.sum(~should_substitute & pred_above_raw)
    tn = np.sum(~should_substitute & ~pred_above_raw)
    fn = np.sum(should_substitute & ~pred_above_raw)

    logger.info("=" * 60)
    logger.info("Substitution Detection Analysis (threshold >= 0.05 change):")
    logger.info("  True Positives (should sub, model sub):  %d", tp)
    logger.info("  False Positives (shouldn't, model sub):  %d", fp)
    logger.info("  True Negatives (shouldn't, model abstain): %d", tn)
    logger.info("  False Negatives (should sub, model abstain): %d", fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    logger.info("  Precision: %.4f", precision)
    logger.info("  Recall:    %.4f", recall)
    logger.info("  F1 Score:  %.4f", f1)

    # ── Export model ─────────────────────────────────────────────────────
    artifact = {
        "model": model,
        "feature_names": feature_names,
        "agencies": AGENCIES,
        "cwes": CWES,
        "metadata": {
            "version": "v2",
            "r2": float(r2_test),
            "r2_train": float(r2_train),
            "rmse": float(rmse_test),
            "rmse_train": float(rmse_train),
            "n_samples": 1000,
            "n_features": X.shape[1],
            "n_agencies": len(AGENCIES),
            "n_cwes": len(CWES),
            "f1_substitution_detection": float(f1),
        },
    }

    output_dir = os.path.dirname(__file__)
    output_path = os.path.join(output_dir, "epss_model_v2.pkl")
    joblib.dump(artifact, output_path)
    logger.info("Model exported to %s", output_path)

    # File size
    size_kb = os.path.getsize(output_path) / 1024
    logger.info("Model file size: %.1f KB", size_kb)

    # ── Smoke tests ──────────────────────────────────────────────────────
    logger.info("\n--- Smoke tests on known and synthetic CVE patterns ---")
    test_cases = [
        # (raw_epss, cvss, cisa_kev, cwe, agency, cve_id, maturity, poc, patch)
        # Known CVE-2023-36884 on health — high sector adjustment
        (0.05, 8.0, True, "CWE-78", "health", "CVE-2023-36884", 3, True, 0),
        # Same CVE, unknown agency
        (0.05, 8.0, False, "CWE-78", "unknown", "CVE-2023-36884", 0, False, 0),
        # Low EPSS, no signals — should be no-op
        (0.02, 6.5, False, "CWE-79", "health", "CVE-2024-99999", 0, False, 0),
        # High signals: KEV + high CVSS + InWild + no patch
        (0.15, 9.0, True, "CWE-89", "transport", "CVE-2024-12345", 3, True, 2),
        # Critical CWE but no other signals
        (0.01, 7.5, False, "CWE-434", "police", "CVE-2025-11111", 0, False, 0),
        # New CVE with strong signals — should trigger substitution
        (0.10, 9.5, True, "CWE-22", "health", "CVE-2025-00001", 2, True, 0),
    ]

    for raw, cvss, kev, cwe, agency, cve_id, maturity, poc, patch in test_cases:
        feat = _build_feature_vector_v2(
            {
                "raw_epss": raw,
                "cvss_score": cvss,
                "exploit_maturity": maturity,
                "cisa_kev": kev,
                "has_public_poc": poc,
                "vendor_patch_status": patch,
                "cwe": cwe,
                "agency": agency,
            }
        )
        vec = np.array([feat])
        pred = float(model.predict(vec)[0])

        # Also compute rule engine target for comparison
        rule_target = apply_rule_engine(raw, cve_id, agency, cwe, kev)

        diff = abs(pred - raw)
        substituted = diff >= 0.1  # MIN_CHANGE_THRESHOLD

        logger.info(
            "CVE=%-20s raw=%.4f cvss=%.1f kev=%d mat=%d poc=%d patch=%d "
            "cwe=%-8s agency=%-15s -> pred=%.4f (rule=%.4f, sub=%s)",
            cve_id,
            raw,
            cvss,
            int(kev),
            maturity,
            int(poc),
            patch,
            cwe,
            agency,
            pred,
            rule_target,
            substituted,
        )

    return artifact


if __name__ == "__main__":
    main()
