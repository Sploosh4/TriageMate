"""
Calibration audit for the Tier 1 XGBoost exploitation-probability model.

Loads enriched_cves.json (or training_data_v2.npz), rebuilds the full 419-dim
feature matrix, runs predict_proba, and compares against ground-truth CISA KEV
labels to produce Expected Calibration Error (ECE) and per-bin diagnostics.

Usage:
    python analysis/calibration_audit.py
    python analysis/calibration_audit.py --max-samples 30000
"""

import json
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np

warnings.filterwarnings("ignore", category=UserWarning)

BASE_DIR = Path(__file__).resolve().parent.parent
ML_DIR = BASE_DIR / "ml"

sys.path.insert(0, str(BASE_DIR))

ENRICHED_CVES_FILE = ML_DIR / "enriched_cves.json"
MODEL_FILE = ML_DIR / "xgboost_model.pkl"
CALIBRATOR_FILE = ML_DIR / "xgboost_calibrator.pkl"
TRAINING_DATA_FILE = ML_DIR / "training_data.npz"
TRAINING_DATA_V2_FILE = ML_DIR / "training_data_v2.npz"


def _ece(y_true, y_prob_arr, n_bins=10):
    """Expected Calibration Error — identical formula to train_xgboost.py."""
    bins = np.linspace(0, 1, n_bins + 1)
    total = len(y_true)
    if total == 0:
        return 0.0
    ece = 0.0
    for i in range(n_bins):
        mask = (y_prob_arr >= bins[i]) & (y_prob_arr < bins[i + 1])
        n_bin = int(np.sum(mask))
        if n_bin == 0:
            continue
        bin_acc = float(np.mean(y_true[mask] == 1))
        bin_conf = float(np.mean(y_prob_arr[mask]))
        ece += n_bin * abs(bin_acc - bin_conf)
    return ece / total


def _load_data(max_samples=None):
    """Load feature matrix X and ground-truth labels y from available source."""

    # Prefer enriched_cves.json (largest, most representative)
    if ENRICHED_CVES_FILE.exists():
        print(f"Loading {ENRICHED_CVES_FILE.name} ... ", end="", flush=True)
        with open(ENRICHED_CVES_FILE) as f:
            cves = json.load(f)
        print(f"{len(cves)} CVEs.")

        if max_samples and len(cves) > max_samples:
            rng = np.random.default_rng(42)
            idx = rng.choice(len(cves), max_samples, replace=False)
            cves = [cves[i] for i in sorted(idx)]
            print(f"  Random subsample: {len(cves)} CVEs.")

        # Ground-truth labels from KEV flag
        y = np.array([c.get("cisa_kev", False) for c in cves], dtype=np.int32)
        n_pos = int(y.sum())
        print(f"  Positives (KEV): {n_pos:,}  ({n_pos / len(y):.3%})")

        # ── Build tabular features ────────────────────────────────────────
        print("  Building tabular features (35 dim)...")
        from ml.train_xgboost import build_tabular_features

        X_tab = build_tabular_features(cves)

        # ── SBERT encode descriptions ─────────────────────────────────────
        print("  Encoding descriptions with SBERT (384 dim)...")
        from ml.encoder import encode_batch

        descriptions = [c["description"] for c in cves]
        X_text = encode_batch(descriptions)

        X = np.hstack([X_tab, X_text]).astype(np.float32)
        return X, y, len(cves), n_pos

    # Fall back to training_data_v2.npz (small but pre-computed)
    target = (
        TRAINING_DATA_V2_FILE if TRAINING_DATA_V2_FILE.exists() else TRAINING_DATA_FILE
    )
    if target.exists():
        print(f"Loading pre-computed features from {target.name} ...")
        data = np.load(target)
        X = data["X"]
        y_arr = data["y"]
        data.close()
        y = np.array(y_arr, dtype=np.int32)
        n_pos = int(y.sum())
        print(f"  {len(X)} records, {X.shape[1]} features, {n_pos} positives.")
        return X, y, len(X), n_pos

    print("ERROR: No data source found. Run ml.train_xgboost --gather first.")
    sys.exit(1)


def _format_bin_label(lo, hi):
    return f"[{lo:.2f}-{hi:.2f})"


def _audit_bins(y_true, y_prob, label, n_bins=10):
    """Print per-bin calibration diagnostics."""
    bins = np.linspace(0, 1, n_bins + 1)
    max_gap = 0.0
    overconfident_bins = 0

    print(f"\n--- {label} ---")
    for i in range(n_bins):
        mask = (y_prob >= bins[i]) & (y_prob < bins[i + 1])
        n_bin = int(np.sum(mask))
        if n_bin == 0:
            bl = _format_bin_label(bins[i], bins[i + 1])
            print(f"  {bl}: n=0")
            continue
        bin_conf = float(np.mean(y_prob[mask]))
        bin_acc = float(np.mean(y_true[mask] == 1))
        gap = bin_conf - bin_acc
        max_gap = max(max_gap, abs(gap))

        flag = ""
        if gap > 0.10:
            flag = " *** OVERCONFIDENT"
            overconfident_bins += 1
        elif abs(gap) <= 0.01:
            flag = " \u2713 calibrated"
        elif n_bin < 30:
            flag = " (low n)"

        bl = _format_bin_label(bins[i], bins[i + 1])
        print(
            f"  {bl}: n={n_bin:,} "
            f"pred_mean={bin_conf:.3f} "
            f"actual={bin_acc:.3f} "
            f"gap={gap:+.4f}{flag}"
        )
    return max_gap, overconfident_bins


def _verdict(
    ece_raw, ece_cal, impr_pct, calibrator_present, overconfident_bins, y_prob_raw=None
):
    """Print the verdict block."""
    print("\n" + "=" * 60)
    print("--- Verdict ---")
    if calibrator_present:
        raw_status = (
            "ACCEPTABLE"
            if ece_raw < 0.05
            else "WARNING"
            if ece_raw < 0.10
            else "UNRELIABLE"
        )
        cal_status = (
            "ACCEPTABLE"
            if ece_cal < 0.05
            else "WARNING"
            if ece_cal < 0.10
            else "UNRELIABLE"
        )
        print(f"  Raw ECE:        {ece_raw:.4f} \u2014 {raw_status}")
        print(f"  Calibrated ECE: {ece_cal:.4f} \u2014 {cal_status}")
        if impr_pct > 0:
            print(f"  Improvement: {impr_pct:+.1f}%")
            print(
                "  Recommendation: Keep Platt calibrator active. "
                "Scoring engine sees well-calibrated probabilities."
            )
        else:
            print(
                "  Calibrator did not improve ECE. Consider retraining or switching to isotonic regression."
            )
    else:
        if ece_raw < 0.05:
            print(f"  Raw ECE: {ece_raw:.4f} \u2014 ACCEPTABLE (<0.05)")
            if overconfident_bins > 2:
                print(
                    f"  CAUTION: {overconfident_bins}/10 bins show >10% overconfidence gap."
                )
                n_first = int(np.sum(y_prob_raw < 0.10))
                pct_first = n_first / len(y_prob_raw) * 100
                n_first = int(np.sum(y_prob_raw < 0.10))
                pct_first = n_first / len(y_prob_raw) * 100
                print(
                    f"  ECE is low because {pct_first:.1f}% of predictions fall in [0.00-0.10) "
                    f"where the model is well-calibrated at near-zero probability."
                )
                print(
                    "  Model is systematically overconfident at higher probability ranges "
                    "(\u22650.10). Platt scaling recommended."
                )
            else:
                print(
                    "  Recommendation: Model is reasonably calibrated without Platt scaling."
                )
        elif ece_raw < 0.10:
            print(f"  Raw ECE: {ece_raw:.4f} \u2014 WARNING (>0.05)")
            print(
                "  Recommendation: Consider retraining with --gather --train to regenerate Platt calibrator."
            )
        else:
            print(f"  Raw ECE: {ece_raw:.4f} \u2014 UNRELIABLE (>0.10)")
            print(
                f"  The model overestimates exploitation probability "
                f"by {ece_raw * 100:.1f}% on average."
            )
            print(
                "  Scoring engine is inflating priorities. "
                "Platt scaling or isotonic regression recommended."
            )
    print("=" * 60)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Calibration audit for XGBoost model")
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Limit number of CVEs (for faster testing)",
    )
    args = parser.parse_args()

    # ── 1. Check for calibrator ──────────────────────────────────────────
    calibrator_present = CALIBRATOR_FILE.exists()
    if calibrator_present:
        print(f"Calibrator found: {CALIBRATOR_FILE.name}")
    else:
        print(
            f"WARNING: {CALIBRATOR_FILE.name} not found. "
            "The model was trained without Platt scaling "
            "(or the file was deleted)."
        )
        print("Retrain with --gather --train to regenerate it.\n")

    # ── 2. Load data ────────────────────────────────────────────────────
    X, y, n_total, n_pos = _load_data(max_samples=args.max_samples)

    # ── 3. Load model ───────────────────────────────────────────────────
    print(f"\nLoading model from {MODEL_FILE.name} ... ", end="", flush=True)
    model = joblib.load(MODEL_FILE)
    print("done.")

    # ── 4. Raw probabilities ────────────────────────────────────────────
    print("  Predicting raw probabilities...")
    t0 = time.time()
    y_prob_raw = model.predict_proba(X)[:, 1]
    t1 = time.time()
    print(
        f"  {len(X):,} predictions in {t1 - t0:.1f}s "
        f"({(t1 - t0) / len(X) * 1000:.1f}ms per sample)."
    )

    # ── 5. Calibrated probabilities (if available) ──────────────────────
    calibrator = None
    if calibrator_present:
        calibrator = joblib.load(CALIBRATOR_FILE)
        raw_reshaped = y_prob_raw.reshape(-1, 1)
        print("  Applying Platt calibration...")
        y_prob_cal = calibrator.predict_proba(raw_reshaped)[:, 1]
    else:
        y_prob_cal = y_prob_raw

    # ── 6. ECE ──────────────────────────────────────────────────────────
    ece_raw = _ece(y, y_prob_raw)
    ece_cal = _ece(y, y_prob_cal) if calibrator_present else None

    # ── 8. Report ───────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("CALIBRATION AUDIT \u2014 XGBoost Model")
    print(
        f"Test samples: {n_total:,}  "
        f"Positives: {n_pos:,} ({n_pos / n_total:.1%})  "
        f"Platt calibrator: {'PRESENT' if calibrator_present else 'MISSING'}"
    )
    print("=" * 60)

    _, over_raw = _audit_bins(y, y_prob_raw, "Raw Probabilities")
    print(
        f"\n  ECE (raw): {ece_raw:.4f} "
        f"({'GOOD' if ece_raw < 0.05 else 'WARNING' if ece_raw < 0.10 else 'HIGH'})"
    )

    if calibrator_present:
        _, over_cal = _audit_bins(y, y_prob_cal, "Calibrated Probabilities (Platt)")
        impr_pct = ((ece_raw - ece_cal) / ece_raw * 100) if ece_raw > 0 else 0.0
        print(
            f"\n  ECE (calibrated): {ece_cal:.4f}  "
            f"({'GOOD' if ece_cal < 0.05 else 'WARNING' if ece_cal < 0.10 else 'HIGH'})"
        )
        print(f"  ECE improvement: {impr_pct:+.1f}%")
    else:
        impr_pct = 0.0
        over_cal = 0

    _verdict(
        ece_raw,
        ece_cal if calibrator_present else ece_raw,
        impr_pct,
        calibrator_present,
        over_raw,
        y_prob_raw,
    )

    # ── 9. Summary table ────────────────────────────────────────────────
    print(
        f"\n  OVERCONFIDENT bins (>10% gap): raw={over_raw} "
        f"{'calibrated=' + str(over_cal) if calibrator_present else 'N/A (no calibrator)'}"
    )


if __name__ == "__main__":
    main()
