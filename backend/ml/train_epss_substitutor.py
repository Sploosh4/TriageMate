"""
Train an XGBoost EPSS substitution model using synthetic training data.

Generates ~500 examples where the "ground truth" target is computed from the
same heuristic rules in epss_substitutor.py. This demonstrates the ML pipeline
architecture without needing real sector-weighted incident data.

Exports to backend/ml/epss_model.pkl
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

# EPSS feature names available from config for drift monitoring alignment:
# from pipeline.config.feature_names import EPSS_V2_FEATURE_NAMES, EPSS_V1_FEATURE_NAMES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("train_epss_substitutor")
warnings.filterwarnings("ignore", category=FutureWarning)

# ── seed for reproducibility ──────────────────────────────────────────────
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ── constants matching epss_substitutor.py ─────────────────────────────────
MAX_EPSS = 0.99
KEV_MULTIPLIER = 2.0
DEFAULT_MULTIPLIER = 1.0

CWE_MULTIPLIERS = {
    "CWE-78": 1.5,
    "CWE-434": 1.5,
    "CWE-862": 1.5,
}

# The CVE-specific sector adjustments (same as in epss_substitutor.py)
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

AGENCIES = [
    "health",
    "transport",
    "education",
    "sharedservices",
    "communities",
    "police",
    "finance",
]

CWES = [
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
]


# ── synthetic data generator ───────────────────────────────────────────────
def _generate_synthetic_sample(rng: random.Random) -> dict:
    """Generate one synthetic training example.

    Returns features dict plus the target (sector_adjusted_epss).
    """
    # Random raw EPSS — skewed towards low values (realistic EPSS distribution)
    # Use a Beta(0.3, 3) shape to produce scores mostly < 0.2
    raw_epss = min(0.99, max(0.0001, rng.betavariate(0.3, 3.0)))
    raw_epss = round(raw_epss, 4)

    # Random CVSS score — normal around 7.0, clipped 0-10
    cvss_score = round(min(10.0, max(0.0, rng.gauss(7.0, 2.0))), 1)

    # CWE class
    cwe = rng.choice(CWES)

    # Agency
    agency = rng.choice(AGENCIES + ["unknown"])

    # CISA KEV (10% True)
    cisa_kev = rng.random() < 0.10

    # Randomly pick a CVE (or no known CVE)
    if rng.random() < 0.3:
        cve_id = rng.choice(ALL_CVES)
    else:
        cve_id = f"CVE-{rng.randint(2024, 2025)}-{rng.randint(10000, 99999)}"

    # ── Compute target using the same logic as the rule engine ──
    sector_multiplier = DEFAULT_MULTIPLIER

    if cisa_kev:
        sector_multiplier = max(sector_multiplier, KEV_MULTIPLIER)

    # CVE-specific adjustments
    adj = CVE_ADJUSTMENTS.get(cve_id)
    if adj:
        agency_mult = adj.get(agency, adj.get("default", 1.0))
        if agency_mult > 1.0:
            sector_multiplier = max(sector_multiplier, agency_mult)

    # CWE multiplier
    cwe_mult = CWE_MULTIPLIERS.get(cwe, 1.0)
    if cwe_mult > 1.0:
        sector_multiplier = max(sector_multiplier, cwe_mult)

    target = round(min(MAX_EPSS, raw_epss * sector_multiplier), 4)

    return {
        "raw_epss": raw_epss,
        "cvss_score": cvss_score,
        "cisa_kev": cisa_kev,
        "cwe": cwe,
        "agency": agency,
        "cve_id": cve_id,
        "target": target,
        "sector_multiplier": sector_multiplier,
    }


def _build_feature_vector(sample: dict, agencies: list, cwes: list) -> list:
    """Build the one-hot encoded feature vector from a sample dict."""
    features = []

    # Continuous features
    features.append(sample["raw_epss"])  # 1
    features.append(sample["cvss_score"])  # 2

    # Binary features
    features.append(1.0 if sample["cisa_kev"] else 0.0)  # 3

    # One-hot encode agency (len(agencies) + 1 for 'unknown')
    for agency in agencies + ["unknown"]:
        features.append(1.0 if sample["agency"] == agency else 0.0)

    # One-hot encode CWE
    for cwe in cwes:
        features.append(1.0 if sample["cwe"] == cwe else 0.0)

    return features


def get_feature_names(agencies: list, cwes: list) -> list:
    """Return the ordered list of feature names for documentation."""
    names = ["raw_epss", "cvss_score", "cisa_kev"]
    for agency in agencies + ["unknown"]:
        names.append(f"agency_{agency}")
    for cwe in cwes:
        names.append(f"cwe_{cwe}")
    return names


def generate_dataset(n_samples: int = 500, seed: int = RANDOM_SEED) -> tuple:
    """Generate a synthetic dataset for EPSS substitution.

    Returns:
        X: ndarray of shape (n_samples, n_features)
        y: ndarray of shape (n_samples,)
        feature_names: list of str
    """
    rng = random.Random(seed)
    samples = [_generate_synthetic_sample(rng) for _ in range(n_samples)]

    X = np.array([_build_feature_vector(s, AGENCIES, CWES) for s in samples])
    y = np.array([s["target"] for s in samples])

    feature_names = get_feature_names(AGENCIES, CWES)

    logger.info(
        "Generated %d samples with %d features. Target range: [%.4f, %.4f], mean=%.4f",
        n_samples,
        X.shape[1],
        y.min(),
        y.max(),
        y.mean(),
    )

    return X, y, feature_names, samples


def main():
    logger.info("Generating synthetic EPSS substitution training data...")

    # Generate 500 examples
    X, y, feature_names, raw_samples = generate_dataset(500)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED
    )

    logger.info("Train: %d, Test: %d samples", X_train.shape[0], X_test.shape[0])

    # ── Train XGBoost regressor ──────────────────────────────────────────
    model = xgb.XGBRegressor(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_SEED,
        verbosity=0,
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # Predictions
    y_pred = model.predict(X_test)

    # Metrics
    r2 = r2_score(y_test, y_pred)
    rmse = np.sqrt(mean_squared_error(y_test, y_pred))

    logger.info("=" * 50)
    logger.info("Model Performance (test set):")
    logger.info("  R²  = %.4f", r2)
    logger.info("  RMSE = %.4f", rmse)
    logger.info(
        "  y_test range: [%.4f, %.4f], mean=%.4f",
        y_test.min(),
        y_test.max(),
        y_test.mean(),
    )
    logger.info(
        "  y_pred range: [%.4f, %.4f], mean=%.4f",
        y_pred.min(),
        y_pred.max(),
        y_pred.mean(),
    )
    logger.info("=" * 50)

    # Feature importance
    logger.info("Top 10 feature importances:")
    importances = sorted(
        zip(feature_names, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, imp in importances[:10]:
        logger.info("  %s: %.4f", name, imp)

    # ── Export model ─────────────────────────────────────────────────────
    artifact = {
        "model": model,
        "feature_names": feature_names,
        "agencies": AGENCIES,
        "cwes": CWES,
        "metadata": {
            "r2": float(r2),
            "rmse": float(rmse),
            "n_samples": 500,
            "n_features": X.shape[1],
        },
    }

    output_dir = os.path.dirname(__file__)
    output_path = os.path.join(output_dir, "epss_model.pkl")
    joblib.dump(artifact, output_path)
    logger.info("Model exported to %s", output_path)

    # File size
    size_kb = os.path.getsize(output_path) / 1024
    logger.info("Model file size: %.1f KB", size_kb)

    # ── Quick smoke test ─────────────────────────────────────────────────
    logger.info("\n--- Quick smoke test on known CVE patterns ---")
    test_cases = [
        # (raw_epss, cvss_score, cisa_kev, cwe, agency, cve_id)
        (0.05, 8.0, True, "CWE-78", "health", "CVE-2023-36884"),
        (0.05, 8.0, False, "CWE-78", "unknown", "CVE-2023-36884"),
        (0.02, 6.5, False, "CWE-79", "health", "CVE-2024-99999"),
        (0.15, 9.0, True, "CWE-89", "transport", "CVE-2024-12345"),
        (0.01, 7.5, False, "CWE-434", "police", "CVE-2025-11111"),
    ]
    for raw, cvss, kev, cwe, agency, cve in test_cases:
        feat = _build_feature_vector(
            {
                "raw_epss": raw,
                "cvss_score": cvss,
                "cisa_kev": kev,
                "cwe": cwe,
                "agency": agency,
            },
            AGENCIES,
            CWES,
        )
        vec = np.array([feat])
        pred = float(model.predict(vec)[0])
        logger.info(
            "CVE=%-20s raw=%.4f cvss=%.1f kev=%d cwe=%-8s agency=%-15s -> pred=%.4f",
            cve,
            raw,
            cvss,
            int(kev),
            cwe,
            agency,
            pred,
        )

    return artifact


if __name__ == "__main__":
    main()
