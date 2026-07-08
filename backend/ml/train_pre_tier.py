"""
Offline training pipeline for the Pre-Tier multi-label classifier.

Trains a MultiOutputClassifier(RandomForestClassifier) on WA Government
hostname records to predict:
  - mission_prevalence:   Core / Support / Peripheral
  - public_wellbeing_impact:  Severe / Moderate / Minimal

Usage:
    cd backend
    python -m ml.train_pre_tier                   # JSON files (legacy)
    python -m ml.train_pre_tier --from-db         # SQLite synthetic_assets

When using --from-db:
  - Reads from synthetic_assets WHERE in_holdout = 0 for training
  - Evaluates blind holdout WHERE in_holdout = 1
  - Persists CV metrics to pre_tier_metrics.json

Output:
    backend/ml/pre_tier_model.pkl  — joblib dict with model, feature_names, classes
    backend/ml/pre_tier_metrics.json — CV and holdout metrics (when --from-db)
"""

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import StratifiedKFold
from sklearn.multioutput import MultiOutputClassifier

from ml.pretier_features import (
    extract_features,
    feature_vector_to_array,
    get_feature_count,
    get_feature_names,
    AGENCIES,
)

try:
    from database import get_db

    HAS_DB = True
except ImportError:
    HAS_DB = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── PATHS ──────────────────────────────────────────────────────────────────

HERE = Path(__file__).parent
ORIGINAL_DATA = HERE / "pretier_training_data.json"
SUPPLEMENTAL_DATA = HERE / "pretier_supplemental.json"
MODEL_OUTPUT = HERE / "pre_tier_model.pkl"
METRICS_OUTPUT = HERE / "pre_tier_metrics.json"

# ─── LABEL DEFINITIONS ─────────────────────────────────────────────────────

MISSION_CLASSES = ["Peripheral", "Support", "Core"]  # 0, 1, 2
WELLBEING_CLASSES = ["Minimal", "Moderate", "Severe"]  # 0, 1, 2

MISSION_ENCODE = {v: i for i, v in enumerate(MISSION_CLASSES)}
WELLBEING_ENCODE = {v: i for i, v in enumerate(WELLBEING_CLASSES)}

VALID_LABELS = set(MISSION_ENCODE.keys()) | set(WELLBEING_ENCODE.keys())

REQUIRED_FIELDS = {"hostname", "mission_prevalence", "public_wellbeing_impact"}


# ─── DATA LOADING ───────────────────────────────────────────────────────────


def load_json(path: Path) -> list[dict]:
    """Load a JSON array of records."""
    with open(path) as f:
        return json.load(f)


def validate_record(rec: dict) -> tuple[bool, str]:
    """Validate a single training record.

    Returns (is_valid, reason_if_invalid).
    """
    # Check required fields
    missing = REQUIRED_FIELDS - set(rec.keys())
    if missing:
        return False, f"Missing fields: {missing}"

    hostname = rec.get("hostname", "")
    if not isinstance(hostname, str) or not hostname.strip():
        return False, "Empty hostname"

    mp = rec.get("mission_prevalence", "")
    if mp not in MISSION_ENCODE:
        return False, f"Invalid mission_prevalence: {mp!r}"

    pwi = rec.get("public_wellbeing_impact", "")
    if pwi not in WELLBEING_ENCODE:
        return False, f"Invalid public_wellbeing_impact: {pwi!r}"

    return True, ""


def load_training_data() -> tuple[np.ndarray, np.ndarray]:
    """Load, merge, deduplicate, and featurise all training data.

    Returns:
        X: (n_samples, n_features) float64 feature matrix
        y: (n_samples, 2) int64 label matrix — column 0 = mission,
           column 1 = wellbeing
    """

    # ── Load all records ───────────────────────────────────────────────
    original_records = load_json(ORIGINAL_DATA)
    supp_records = load_json(SUPPLEMENTAL_DATA)

    logger.info("Original records:       %d", len(original_records))
    logger.info("Supplemental records:   %d", len(supp_records))

    # ── Validate ───────────────────────────────────────────────────────
    all_records = []
    skipped_validation = 0
    for rec in original_records + supp_records:
        valid, reason = validate_record(rec)
        if valid:
            all_records.append(rec)
        else:
            skipped_validation += 1
            if skipped_validation <= 5:
                logger.warning(
                    "  Skipping record: %s — %s", rec.get("hostname", "?"), reason
                )

    if skipped_validation:
        logger.warning("Skipped %d invalid records", skipped_validation)

    # ── Deduplicate by hostname ─────────────────────────────────────────
    seen_hostnames: dict[str, dict] = {}
    for rec in all_records:
        hn = rec["hostname"].strip().lower()
        if hn not in seen_hostnames:
            seen_hostnames[hn] = rec
        # else keep first occurrence (original takes priority)

    deduped_records = list(seen_hostnames.values())
    dupes_removed = len(all_records) - len(deduped_records)
    if dupes_removed:
        logger.info("Removed %d duplicate hostnames", dupes_removed)

    logger.info("Total unique records after dedup: %d", len(deduped_records))

    # ── Per-agency reporting ────────────────────────────────────────────
    agency_counts = Counter()
    for rec in deduped_records:
        hn = rec["hostname"].lower()
        for a in AGENCIES:
            if a in hn:
                agency_counts[a] += 1
                break
        else:
            agency_counts["other"] += 1

    logger.info("Per-agency dataset size:")
    for a in sorted(agency_counts):
        logger.info("  %-20s: %d", a, agency_counts[a])

    # ── Featurise ───────────────────────────────────────────────────────
    X_rows = []
    y_rows = []

    for rec in deduped_records:
        hostname = rec["hostname"]
        mission = rec["mission_prevalence"]
        wellbeing = rec["public_wellbeing_impact"]

        features = extract_features(hostname)
        X_rows.append(feature_vector_to_array(features))
        y_rows.append([MISSION_ENCODE[mission], WELLBEING_ENCODE[wellbeing]])

    X = np.array(X_rows, dtype=np.float64)
    y = np.array(y_rows, dtype=np.int64)

    logger.info("Feature matrix: %d samples × %d features", X.shape[0], X.shape[1])
    logger.info("Feature names: %s", get_feature_names())

    # ── Label distribution ─────────────────────────────────────────────
    logger.info("Label distribution:")
    for col_name, classes in [
        ("mission_prevalence", MISSION_CLASSES),
        ("public_wellbeing_impact", WELLBEING_CLASSES),
    ]:
        col = 0 if col_name == "mission_prevalence" else 1
        counts = {c: int(np.sum(y[:, col] == i)) for i, c in enumerate(classes)}
        logger.info("  %s: %s", col_name, counts)

    return X, y


def load_training_data_from_db() -> tuple[np.ndarray, np.ndarray]:
    """Load training data from synthetic_assets WHERE in_holdout = 0.

    Returns:
        X: (n_samples, n_features) float64 feature matrix
        y: (n_samples, 2) int64 label matrix — column 0 = mission,
           column 1 = wellbeing
    """
    if not HAS_DB:
        logger.error("database module not available. Cannot use --from-db.")
        sys.exit(1)

    db = get_db()
    rows = db.execute(
        "SELECT hostname, mission_prevalence, public_wellbeing_impact "
        "FROM synthetic_assets WHERE in_holdout = 0"
    ).fetchall()
    db.close()

    logger.info("Training records from DB: %d", len(rows))

    if len(rows) == 0:
        logger.error("No training records found in synthetic_assets. Aborting.")
        sys.exit(1)

    # ── Validate labels ────────────────────────────────────────────────
    valid_rows = []
    skipped = 0
    for row in rows:
        mp = row["mission_prevalence"]
        pwi = row["public_wellbeing_impact"]
        if mp in MISSION_ENCODE and pwi in WELLBEING_ENCODE:
            valid_rows.append(row)
        else:
            skipped += 1

    if skipped:
        logger.warning("Skipped %d rows with invalid labels", skipped)

    # ── Per-agency reporting ────────────────────────────────────────────
    agency_counts = Counter()
    for row in valid_rows:
        hn = row["hostname"].lower()
        for a in AGENCIES:
            if a in hn:
                agency_counts[a] += 1
                break
        else:
            agency_counts["other"] += 1

    logger.info("Per-agency dataset size:")
    for a in sorted(agency_counts):
        logger.info("  %-20s: %d", a, agency_counts[a])

    # ── Featurise ───────────────────────────────────────────────────────
    X_rows = []
    y_rows = []

    for row in valid_rows:
        hostname = row["hostname"]
        mission = row["mission_prevalence"]
        wellbeing = row["public_wellbeing_impact"]

        features = extract_features(hostname)
        X_rows.append(feature_vector_to_array(features))
        y_rows.append([MISSION_ENCODE[mission], WELLBEING_ENCODE[wellbeing]])

    X = np.array(X_rows, dtype=np.float64)
    y = np.array(y_rows, dtype=np.int64)

    logger.info("Feature matrix: %d samples × %d features", X.shape[0], X.shape[1])
    logger.info("Feature names: %s", get_feature_names())

    # ── Label distribution ─────────────────────────────────────────────
    logger.info("Label distribution:")
    for col_name, classes in [
        ("mission_prevalence", MISSION_CLASSES),
        ("public_wellbeing_impact", WELLBEING_CLASSES),
    ]:
        col = 0 if col_name == "mission_prevalence" else 1
        counts = {c: int(np.sum(y[:, col] == i)) for i, c in enumerate(classes)}
        logger.info("  %s: %s", col_name, counts)

    return X, y


def load_holdout_data() -> tuple[np.ndarray, np.ndarray]:
    """Load holdout data from synthetic_assets WHERE in_holdout = 1.

    Returns:
        X_hold: (n_samples, n_features) float64 feature matrix
        y_hold: (n_samples, 2) int64 label matrix
    """
    if not HAS_DB:
        logger.error("database module not available. Cannot use --from-db.")
        sys.exit(1)

    db = get_db()
    rows = db.execute(
        "SELECT hostname, mission_prevalence, public_wellbeing_impact "
        "FROM synthetic_assets WHERE in_holdout = 1"
    ).fetchall()
    db.close()

    logger.info("Holdout records from DB: %d", len(rows))

    if len(rows) == 0:
        logger.warning("No holdout records found. Skipping holdout evaluation.")
        return np.empty((0, get_feature_count()), dtype=np.float64), np.empty(
            (0, 2), dtype=np.int64
        )

    X_rows = []
    y_rows = []
    skipped = 0

    for row in rows:
        mp = row["mission_prevalence"]
        pwi = row["public_wellbeing_impact"]
        if mp not in MISSION_ENCODE or pwi not in WELLBEING_ENCODE:
            skipped += 1
            continue
        hostname = row["hostname"]
        features = extract_features(hostname)
        X_rows.append(feature_vector_to_array(features))
        y_rows.append([MISSION_ENCODE[mp], WELLBEING_ENCODE[pwi]])

    if skipped:
        logger.warning("Skipped %d holdout rows with invalid labels", skipped)

    X_hold = np.array(X_rows, dtype=np.float64)
    y_hold = np.array(y_rows, dtype=np.int64)

    logger.info(
        "Holdout feature matrix: %d samples × %d features",
        X_hold.shape[0],
        X_hold.shape[1],
    )

    return X_hold, y_hold


# ─── TRAINING ───────────────────────────────────────────────────────────────


def train_model(X: np.ndarray, y: np.ndarray) -> MultiOutputClassifier:
    """Train the MultiOutputClassifier on the full dataset.

    Returns:
        Trained model (fitted MultiOutputClassifier).
    """
    base = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model = MultiOutputClassifier(base, n_jobs=-1)
    model.fit(X, y)

    train_preds = model.predict(X)
    both_correct = np.all(train_preds == y, axis=1)
    overall_acc = float(np.mean(both_correct))
    mp_acc = accuracy_score(y[:, 0], train_preds[:, 0])
    pwi_acc = accuracy_score(y[:, 1], train_preds[:, 1])

    logger.info("Training set results (full fit):")
    logger.info("  Mission prevalence accuracy:  %.4f", mp_acc)
    logger.info("  Well-being impact accuracy:   %.4f", pwi_acc)
    logger.info("  Overall accuracy:             %.4f", overall_acc)

    return model


# ─── CROSS-VALIDATION ───────────────────────────────────────────────────────


def cross_validate(X: np.ndarray, y: np.ndarray, n_splits: int = 5) -> dict:
    """Stratified 5-fold cross-validation reporting per-label and overall accuracy.

    Returns:
        dict with keys: mean_mp_acc, mean_pwi_acc, mean_overall_acc,
                        std_mp_acc, std_pwi_acc, std_overall_acc,
                        fold_details (list of dicts)
    """
    combined = np.array(
        [
            f"{MISSION_CLASSES[mi]}_{WELLBEING_CLASSES[wi]}"
            for mi, wi in zip(y[:, 0], y[:, 1])
        ]
    )

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    fold_mp_acc = []
    fold_pwi_acc = []
    fold_overall_acc = []

    logger.info("")
    logger.info("=" * 60)
    logger.info("STRATIFIED %d-FOLD CROSS-VALIDATION", n_splits)
    logger.info("=" * 60)

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, combined)):
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        base = RandomForestClassifier(
            n_estimators=200,
            min_samples_leaf=2,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        fold_model = MultiOutputClassifier(base, n_jobs=-1)
        fold_model.fit(X_train, y_train)

        preds = fold_model.predict(X_val)

        mp_acc = accuracy_score(y_val[:, 0], preds[:, 0])
        pwi_acc = accuracy_score(y_val[:, 1], preds[:, 1])
        both_correct = np.all(preds == y_val, axis=1)
        overall_acc = float(np.mean(both_correct))

        fold_mp_acc.append(mp_acc)
        fold_pwi_acc.append(pwi_acc)
        fold_overall_acc.append(overall_acc)

        logger.info(
            "  Fold %d:  MP=%.4f  WI=%.4f  Overall=%.4f  (val size=%d)",
            fold_idx + 1,
            mp_acc,
            pwi_acc,
            overall_acc,
            len(X_val),
        )

    logger.info("  ─────────────────────────────────────────")
    logger.info(
        "  Mean:     MP=%.4f  WI=%.4f  Overall=%.4f",
        np.mean(fold_mp_acc),
        np.mean(fold_pwi_acc),
        np.mean(fold_overall_acc),
    )
    logger.info(
        "  Std:      MP=%.4f  WI=%.4f  Overall=%.4f",
        np.std(fold_mp_acc),
        np.std(fold_pwi_acc),
        np.std(fold_overall_acc),
    )
    logger.info("=" * 60)

    return {
        "mean_mp_acc": float(np.mean(fold_mp_acc)),
        "mean_pwi_acc": float(np.mean(fold_pwi_acc)),
        "mean_overall_acc": float(np.mean(fold_overall_acc)),
        "std_mp_acc": float(np.std(fold_mp_acc)),
        "std_pwi_acc": float(np.std(fold_pwi_acc)),
        "std_overall_acc": float(np.std(fold_overall_acc)),
        "fold_details": [
            {
                "fold": i + 1,
                "mp_acc": float(a),
                "pwi_acc": float(b),
                "overall_acc": float(c),
            }
            for i, (a, b, c) in enumerate(
                zip(fold_mp_acc, fold_pwi_acc, fold_overall_acc)
            )
        ],
    }


# ─── HOLDOUT EVALUATION ─────────────────────────────────────────────────────


def evaluate_holdout(
    model: MultiOutputClassifier, X_hold: np.ndarray, y_hold: np.ndarray
) -> dict:
    """Evaluate model on blind holdout set.

    Returns:
        dict with holdout_mp_acc, holdout_pwi_acc, holdout_overall_acc.
    """
    if X_hold.shape[0] == 0:
        logger.warning("No holdout data to evaluate.")
        return {}

    hold_preds = model.predict(X_hold)

    mp_acc = accuracy_score(y_hold[:, 0], hold_preds[:, 0])
    pwi_acc = accuracy_score(y_hold[:, 1], hold_preds[:, 1])
    both_correct = np.all(hold_preds == y_hold, axis=1)
    overall_acc = float(np.mean(both_correct))

    logger.info("")
    logger.info("=" * 60)
    logger.info("BLIND HOLDOUT EVALUATION (%d samples)", X_hold.shape[0])
    logger.info("=" * 60)
    logger.info("  Mission prevalence accuracy:  %.4f", mp_acc)
    logger.info("  Well-being impact accuracy:   %.4f", pwi_acc)
    logger.info("  Overall accuracy:             %.4f", overall_acc)
    logger.info("=" * 60)

    return {
        "holdout_samples": int(X_hold.shape[0]),
        "holdout_mp_acc": float(mp_acc),
        "holdout_pwi_acc": float(pwi_acc),
        "holdout_overall_acc": float(overall_acc),
    }


def save_metrics(metrics: dict):
    """Persist metrics dict to pre_tier_metrics.json."""
    METRICS_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(METRICS_OUTPUT, "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info("Metrics saved to %s", METRICS_OUTPUT)


# ─── EXPORT ─────────────────────────────────────────────────────────────────


def export_model(model: MultiOutputClassifier):
    """Save model + metadata to backend/ml/pre_tier_model.pkl."""
    artifact = {
        "model": model,
        "feature_names": get_feature_names(),
        "n_features": get_feature_count(),
        "classes": {
            "mission": MISSION_CLASSES,
            "wellbeing": WELLBEING_CLASSES,
        },
        "label_encodings": {
            "mission": MISSION_ENCODE,
            "wellbeing": WELLBEING_ENCODE,
        },
    }

    logger.info("Exporting model to %s ...", MODEL_OUTPUT.name)
    MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, MODEL_OUTPUT)

    size_mb = MODEL_OUTPUT.stat().st_size / (1024 * 1024)
    logger.info("Model saved (%.2f MB).", size_mb)


# ─── MAIN ───────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Pre-Tier Multi-Label Classifier — Training Pipeline"
    )
    parser.add_argument(
        "--from-db",
        action="store_true",
        help="Load training data from synthetic_assets (SQLite) instead of JSON files.",
    )
    args = parser.parse_args()

    logger.info("Pre-Tier Multi-Label Classifier — Training Pipeline")
    logger.info("=" * 60)

    from_db = args.from_db

    if from_db:
        logger.info("Data source: synthetic_assets (SQLite)")
        X, y = load_training_data_from_db()
        holdout_available = True
        X_hold, y_hold = load_holdout_data()
    else:
        logger.info("Data source: JSON files (legacy)")
        X, y = load_training_data()
        holdout_available = False
        X_hold = np.empty((0, get_feature_count()), dtype=np.float64)
        y_hold = np.empty((0, 2), dtype=np.int64)

    if X.shape[0] == 0:
        logger.error("No training data loaded. Aborting.")
        sys.exit(1)

    cv_metrics = cross_validate(X, y, n_splits=5)

    logger.info("")
    logger.info("Training final model on full dataset ...")
    model = train_model(X, y)

    export_model(model)

    # ── Build full metrics payload ────────────────────────────────────
    metrics = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data_source": "synthetic_assets (SQLite)"
        if from_db
        else "JSON files (legacy)",
        "training_samples": int(X.shape[0]),
        "n_features": int(X.shape[1]),
        "mission_classes": MISSION_CLASSES,
        "wellbeing_classes": WELLBEING_CLASSES,
        "cv": cv_metrics,
    }

    # Training set accuracy
    train_preds = model.predict(X)
    both_correct = np.all(train_preds == y, axis=1)
    metrics["train_accuracy"] = {
        "overall": float(np.mean(both_correct)),
        "mission_prevalence": float(accuracy_score(y[:, 0], train_preds[:, 0])),
        "public_wellbeing_impact": float(accuracy_score(y[:, 1], train_preds[:, 1])),
    }

    if holdout_available and X_hold.shape[0] > 0:
        hold_metrics = evaluate_holdout(model, X_hold, y_hold)
        metrics["holdout"] = hold_metrics

    save_metrics(metrics)

    logger.info("Done. Model ready at %s", MODEL_OUTPUT)
    logger.info("Metrics saved at %s", METRICS_OUTPUT)


if __name__ == "__main__":
    main()
