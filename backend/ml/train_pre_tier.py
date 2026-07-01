"""
Offline training pipeline for the Pre-Tier multi-label classifier.

Trains a MultiOutputClassifier(RandomForestClassifier) on combined original
(242) + supplemental (300+) WA Government hostname records (~550+ total)
to predict:
  - mission_prevalence:   Core / Support / Peripheral
  - public_wellbeing_impact:  Severe / Moderate / Minimal

Usage:
    cd backend
    python -m ml.train_pre_tier

Output:
    backend/ml/pre_tier_model.pkl  — joblib dict with model, feature_names, classes
"""

import json
import logging
import sys
from collections import Counter
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


def cross_validate(X: np.ndarray, y: np.ndarray, n_splits: int = 5):
    """Stratified 5-fold cross-validation reporting per-label and overall accuracy."""
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
    logger.info("Pre-Tier Multi-Label Classifier — Training Pipeline")
    logger.info("=" * 60)

    X, y = load_training_data()

    if X.shape[0] == 0:
        logger.error("No training data loaded. Aborting.")
        sys.exit(1)

    cross_validate(X, y, n_splits=5)

    logger.info("")
    logger.info("Training final model on full dataset ...")
    model = train_model(X, y)

    export_model(model)

    logger.info("Done. Model ready at %s", MODEL_OUTPUT)


if __name__ == "__main__":
    main()
