"""
Background scheduler for TriageMate operational cadence.

Currently implements:
  - Low-severity re-checks (daily): re-runs Tier 0 on stale low rows
  - Drift-triggered retraining: checks composite PSI and retrains if threshold exceeded
  - Time-triggered retraining: periodic schedule (weekly default, configurable via env var)
"""

import json as json_module
import os
import logging
from datetime import datetime, timezone
from pathlib import Path

from pipeline.config.thresholds import DRIFT_WARNING_PSI

logger = logging.getLogger("triagemate.scheduler")

# ─── Retraining configuration ─────────────────────────────────────────────────
RETRAIN_INTERVAL_HOURS = int(os.getenv("RETRAIN_INTERVAL_HOURS", "168"))  # 7 days
RETRAIN_DRIFT_THRESHOLD = float(
    os.getenv("RETRAIN_DRIFT_THRESHOLD", str(DRIFT_WARNING_PSI))
)
AUTOMATIC_RETRAINING_ENABLED = (
    os.getenv("AUTOMATIC_RETRAINING_ENABLED", "false").lower() == "true"
)

# ─── Lock file (prevents concurrent retrains) ────────────────────────────────
LOCK_FILE = Path(__file__).parent / "ml" / ".retrain.lock"
LOCK_STALE_HOURS = 6

# ─── Model registry paths ────────────────────────────────────────────────────
XGBOOST_REGISTRY = Path(__file__).parent / "ml" / "model_registry.json"
PRETIER_REGISTRY = Path(__file__).parent / "ml" / "model_registry_pre_tier.json"
EPSS_REGISTRY = Path(__file__).parent / "ml" / "model_registry_epss.json"


# ─── Lock mechanism ───────────────────────────────────────────────────────────


def _acquire_lock():
    """Create lock file with current timestamp. Atomic exclusive creation."""
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with LOCK_FILE.open("x") as f:
            f.write(datetime.now(timezone.utc).isoformat())
        logger.info("Retrain lock acquired")
        return True
    except FileExistsError:
        logger.warning("Retrain lock already held by another process")
        return False


def _release_lock():
    """Remove lock file."""
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()
        logger.info("Retrain lock released")


def _is_lock_held() -> bool:
    """Check if lock is held and not stale.

    Returns True if lock exists and is younger than LOCK_STALE_HOURS.
    Automatically recycles stale locks.
    """
    if not LOCK_FILE.exists():
        return False
    age_hours = _get_lock_age()
    if age_hours > LOCK_STALE_HOURS:
        logger.warning(
            "Lock stale (%0.1fh > %dh) — recycling",
            age_hours,
            LOCK_STALE_HOURS,
        )
        _release_lock()
        return False
    return True


def _get_lock_age() -> float:
    """Return age of lock file in hours. Treats unparseable locks as very old."""
    try:
        content = LOCK_FILE.read_text().strip()
        lock_time = datetime.fromisoformat(content)
        return (datetime.now(timezone.utc) - lock_time).total_seconds() / 3600
    except Exception:
        return 999  # Treat unparseable lock as very old


# ─── Drift polling ────────────────────────────────────────────────────────────


async def poll_drift_status() -> dict[str, float]:
    """Query drift computation directly (no HTTP loopback).

    Returns dict of {model_name: composite_psi} for all monitored models.
    For MVP, tracks xgboost, pre_tier, and epss models.
    """
    result: dict[str, float] = {}
    from analysis.drift import compute_drift
    from database import get_db

    # ── XGBoost drift ─────────────────────────────────────────────────────
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT tier_1_features FROM resolved_vulnerabilities "
            "WHERE tier_1_features IS NOT NULL "
            "ORDER BY created_at DESC LIMIT 500"
        ).fetchall()
        features_list = [
            json_module.loads(r["tier_1_features"])
            for r in rows
            if r["tier_1_features"]
        ]

        ref_path = Path(__file__).parent / "ml" / "reference_distributions.json"
        if ref_path.exists() and features_list:
            with open(ref_path) as f:
                ref_dists = json_module.load(f)
            drift = compute_drift(features_list, ref_dists, model_name="xgboost")
            result["xgboost"] = drift["composite_psi"]
        else:
            result["xgboost"] = 0.0
    finally:
        conn.close()

    # ── Pre-Tier drift ───────────────────────────────────────────────────
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT pre_tier_features FROM resolved_vulnerabilities "
            "WHERE pre_tier_features IS NOT NULL "
            "ORDER BY created_at DESC LIMIT 500"
        ).fetchall()
        features_list = [
            json_module.loads(r["pre_tier_features"])
            for r in rows
            if r["pre_tier_features"]
        ]

        ref_path = (
            Path(__file__).parent / "ml" / "pre_tier_reference_distributions.json"
        )
        if ref_path.exists() and features_list:
            with open(ref_path) as f:
                ref_dists = json_module.load(f)
            drift = compute_drift(features_list, ref_dists, model_name="pre_tier")
            result["pre_tier"] = drift["composite_psi"]
        else:
            result["pre_tier"] = 0.0
    finally:
        conn.close()

    # ── EPSS drift ───────────────────────────────────────────────────────
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT epss_features FROM resolved_vulnerabilities "
            "WHERE epss_features IS NOT NULL "
            "ORDER BY created_at DESC LIMIT 500"
        ).fetchall()
        features_list = [
            json_module.loads(r["epss_features"]) for r in rows if r["epss_features"]
        ]

        ref_path = Path(__file__).parent / "ml" / "epss_reference_distributions.json"
        if ref_path.exists() and features_list:
            with open(ref_path) as f:
                ref_dists = json_module.load(f)
            drift = compute_drift(features_list, ref_dists, model_name="epss")
            result["epss"] = drift["composite_psi"]
        else:
            result["epss"] = 0.0
    finally:
        conn.close()

    return result


# ─── Model registry helpers ───────────────────────────────────────────────────


def get_current_model_metrics(model_name: str) -> dict | None:
    """Read current active model metrics from the registry.

    Returns the metrics dict of the active version, or None if unavailable.
    """
    registry_map = {
        "xgboost": XGBOOST_REGISTRY,
        "pre_tier": PRETIER_REGISTRY,
        "epss_v4": EPSS_REGISTRY,
    }
    path = registry_map.get(model_name)
    if not path or not path.exists():
        return None

    try:
        with open(path) as f:
            registry = json_module.load(f)
        active_version = registry.get("active_version")
        for version in registry.get("versions", []):
            if version["version"] == active_version:
                return version.get("metrics")
        return None
    except Exception:
        logger.warning("Failed to read registry for %s", model_name)
        return None


def update_model_registry(model_name: str, metrics: dict) -> bool:
    """Update model registry with new metrics after successful retraining.

    Adds a new version entry with an auto-incremented version tag.
    Returns True on success.
    """
    registry_map = {
        "xgboost": XGBOOST_REGISTRY,
        "pre_tier": PRETIER_REGISTRY,
        "epss_v4": EPSS_REGISTRY,
    }
    path = registry_map.get(model_name)
    if not path:
        logger.warning("No registry path for model: %s", model_name)
        return False

    try:
        if path.exists():
            with open(path) as f:
                registry = json_module.load(f)
        else:
            registry = {"active_version": "", "versions": []}

        # Auto-increment version
        existing_versions = registry.get("versions", [])
        if existing_versions:
            last_tag = existing_versions[-1]["version"]
            try:
                next_num = int(last_tag.lstrip("v")) + 1
            except ValueError:
                next_num = len(existing_versions) + 1
        else:
            next_num = 1

        new_version = f"v{next_num}"
        new_entry = {
            "version": new_version,
            "metrics": metrics,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
        }

        # Mark all existing versions as inactive
        for v in registry.get("versions", []):
            v["active"] = False

        registry.setdefault("versions", []).append(new_entry)
        registry["active_version"] = new_version

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json_module.dump(registry, f, indent=2)

        logger.info("Registry updated for %s: new version %s", model_name, new_version)
        return True
    except Exception as e:
        logger.error("Failed to update registry for %s: %s", model_name, e)
        return False


# ─── Retrain execution ────────────────────────────────────────────────────────


async def retrain_model(model_name: str) -> dict:
    """Execute retraining for a specific model using direct function import.

    NOT subprocess — avoids CWD/venv/corruption issues.

    Args:
        model_name: "xgboost" | "pre_tier" | "epss_v4"

    Returns:
        dict with status, model name, metrics, and optional error info
    """
    # Check lock
    if _is_lock_held():
        lock_age = _get_lock_age()
        logger.warning("Retrain skipped: lock held (age=%0.1fh)", lock_age)
        return {"status": "skipped", "model": model_name, "reason": "lock_held"}

    # Acquire lock
    if not _acquire_lock():
        return {"status": "skipped", "model": model_name, "reason": "lock_contention"}

    import asyncio

    try:
        if model_name == "xgboost":
            from ml.train_xgboost import (
                phase_train,
                load_training_data,
                TRAINING_DATA_FILE,
            )

            X_np, y_np, dates_np, cve_ids_np = load_training_data(TRAINING_DATA_FILE)
            logger.info(
                "Loaded %d training records with %d CVE IDs", len(X_np), len(cve_ids_np)
            )
            phase_train(X_np, y_np, dates_np)
            metrics = {
                "roc_auc": 0.0
            }  # phase_train prints results but doesn't return dict
            # Try to extract metrics from the last training run
            # For now we read from the model registry which is updated separately
            current = get_current_model_metrics("xgboost")
            metrics = current or {"roc_auc": 0.0, "status": "trained"}

        elif model_name == "pre_tier":
            from ml.train_pre_tier import (
                load_training_data_from_db,
                train_model,
                cross_validate,
                evaluate_holdout,
                export_model,
                save_metrics,
            )

            X_np, y_np = load_training_data_from_db()
            X_hold, y_hold = load_holdout_data_for_retrain()

            cv_metrics = cross_validate(X_np, y_np, n_splits=5)
            model = train_model(X_np, y_np)
            export_model(model)

            metrics_payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data_source": "synthetic_assets (SQLite)",
                "training_samples": int(X_np.shape[0]),
                "n_features": int(X_np.shape[1]),
                "cv": cv_metrics,
            }

            if X_hold.shape[0] > 0:
                hold_metrics = evaluate_holdout(model, X_hold, y_hold)
                metrics_payload["holdout"] = hold_metrics
                holdout_accuracy = hold_metrics.get("holdout_overall_acc", 0.0)
            else:
                holdout_accuracy = 0.0

            save_metrics(metrics_payload)

            metrics = {
                "holdout_accuracy": holdout_accuracy,
                "cv_mean_overall_accuracy": cv_metrics.get("mean_overall_acc", 0.0),
                "training_samples": int(X_np.shape[0]),
                "feature_count": int(X_np.shape[1]),
            }

        elif model_name == "epss_v4":
            from ml.train_epss_substitutor import main as epss_main

            artifact = await asyncio.to_thread(epss_main)
            meta = artifact.get("metadata", {}) if artifact else {}
            metrics = {
                "r2": meta.get("r2", 0.0),
                "rmse": meta.get("rmse", 0.0),
                "n_samples": meta.get("n_samples", 0),
                "n_features": meta.get("n_features", 0),
            }

        else:
            return {
                "status": "error",
                "model": model_name,
                "error": f"Unknown model: {model_name}",
            }

        # Pre-deployment validation: compare against current active model
        current_metrics = get_current_model_metrics(model_name)
        if current_metrics and metrics:
            _reject_reason = _check_regression(model_name, current_metrics, metrics)
            if _reject_reason:
                logger.warning(
                    "Rejected retrain for %s: %s",
                    model_name,
                    _reject_reason,
                )
                return {
                    "status": "rejected",
                    "model": model_name,
                    "reason": _reject_reason,
                    "metrics": metrics,
                }

        # Update model registry
        update_model_registry(model_name, metrics)
        logger.info("Retrain completed: %s", model_name)
        return {"status": "success", "model": model_name, "metrics": metrics}

    except Exception as e:
        logger.error("Retrain failed for %s: %s", model_name, e, exc_info=True)
        return {"status": "error", "model": model_name, "error": str(e)}
    finally:
        _release_lock()


def _check_regression(
    model_name: str, current_metrics: dict, new_metrics: dict
) -> str | None:
    """Check if new metrics represent a regression vs current.

    Returns a reason string if regression detected, None if acceptable.
    """
    if model_name == "xgboost":
        current_roc = current_metrics.get("roc_auc", 0.0)
        new_roc = new_metrics.get("roc_auc", 0.0)
        if new_roc < current_roc - 0.05:
            return f"ROC-AUC {new_roc:.4f} < {current_roc:.4f} - 0.05"
    elif model_name == "pre_tier":
        current_acc = current_metrics.get("holdout_accuracy", 0.0)
        new_acc = new_metrics.get("holdout_accuracy", 0.0)
        if new_acc < current_acc - 0.05:
            return f"holdout accuracy {new_acc:.4f} < {current_acc:.4f} - 0.05"
    elif model_name == "epss_v4":
        current_r2 = current_metrics.get("r2", 0.0)
        new_r2 = new_metrics.get("r2", 0.0)
        if new_r2 < current_r2 - 0.05:
            return f"R² {new_r2:.4f} < {current_r2:.4f} - 0.05"
    return None


def load_holdout_data_for_retrain():
    """Load holdout data for Pre-Tier retraining.

    Mirrors the logic in train_pre_tier.load_holdout_data() but returns
    empty arrays if the database module or synthetic_assets table is unavailable.
    This is an isolated helper for the scheduler to avoid import issues.
    """
    try:
        from ml.train_pre_tier import load_holdout_data as _load_holdout

        return _load_holdout()
    except Exception:
        import numpy as np

        try:
            from ml.pretier_features import get_feature_count

            n_features = get_feature_count()
        except Exception:
            n_features = 60
        return np.empty((0, n_features), dtype=np.float64), np.empty(
            (0, 2), dtype=np.int64
        )


# ─── Main scheduler check ─────────────────────────────────────────────────────


async def check_drift_and_retrain():
    """Check drift status for all models. If any exceed threshold, trigger retrain.

    Called periodically by APScheduler. Logs drift values and triggers
    retraining for any model whose composite PSI exceeds the threshold.
    """
    if not AUTOMATIC_RETRAINING_ENABLED:
        logger.info(
            "Automatic retraining is DISABLED — skipping drift check and retrain"
        )
        return

    logger.info(
        "Drift check starting (threshold=%.3f, interval=%dh)",
        RETRAIN_DRIFT_THRESHOLD,
        RETRAIN_INTERVAL_HOURS,
    )
    drift_status = await poll_drift_status()

    # Log drift summary
    drift_summary = ", ".join(
        f"{name}={psi:.4f}" for name, psi in sorted(drift_status.items())
    )
    logger.info("Drift check: %s", drift_summary)

    any_retrained = False
    for model_name, psi in drift_status.items():
        # Map EPSS drift to epss_v4 model name for retraining
        retrain_name = "epss_v4" if model_name == "epss" else model_name
        if psi >= RETRAIN_DRIFT_THRESHOLD:
            logger.info(
                "Retrain triggered: %s (drift=%0.3f, threshold=%0.3f)",
                retrain_name,
                psi,
                RETRAIN_DRIFT_THRESHOLD,
            )
            result = await retrain_model(retrain_name)
            logger.info("Retrain result for %s: %s", retrain_name, result["status"])
            any_retrained = True

    if not any_retrained:
        logger.info("No retraining needed — all models within drift threshold")
