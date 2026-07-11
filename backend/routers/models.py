"""
Model version management router.

Provides read-write access to the model registry:
- GET  /api/model/versions  — list all registered model versions
- GET  /api/model/status   — active model info with cross-version comparison
- POST /api/model/activate — switch the active model version
- GET  /api/models/versions — list all versions (rollback router)
- POST /api/models/xgboost/rollback — rollback to a previous version
"""

import json
import logging
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger("triagemate.models")

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "ml" / "model_registry.json"
ROLLBACK_LOCK_FILE = Path(__file__).resolve().parent.parent / "ml" / ".rollback.lock"


class ActivateRequest(BaseModel):
    version: str


router = APIRouter(prefix="/api/model", tags=["Model Version Management"])
# Separate router for rollback endpoints (different path prefix)
rollback_router = APIRouter(tags=["Models"])


def _read_registry() -> dict:
    """Read the model registry JSON file."""
    if not REGISTRY_PATH.exists():
        return {"active_version": None, "versions": []}
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def _write_registry(registry: dict):
    """Atomically write the registry to disk (write temp, rename)."""
    tmp_path = REGISTRY_PATH.with_suffix(".json.tmp")
    with open(tmp_path, "w") as f:
        json.dump(registry, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp_path.replace(REGISTRY_PATH)


def _registry_to_response(registry: dict) -> dict:
    """Build the response shape with is_active flags."""
    active = registry.get("active_version")
    versions = []
    for v in registry.get("versions", []):
        versions.append(
            {
                "version": v["version"],
                "label": v["label"],
                "metrics": v.get("metrics", {}),
                "is_active": v["version"] == active,
                "created_at": v.get("created_at", ""),
            }
        )
    return {"active_version": active, "versions": versions}


@router.get("/versions")
async def list_versions():
    """Return all registered model versions with metadata.

    Does NOT include model binaries — only metadata and activation status.
    """
    registry = _read_registry()
    return _registry_to_response(registry)


@router.get("/status")
async def get_model_status():
    """Return active model info with comparison data across versions.

    Includes:
    - active_version: full metadata for the currently active model
    - available_versions: all registered versions with is_active flags
    - score_comparison: per-version score baselines for side-by-side view
    """
    registry = _read_registry()
    active_version_id = registry.get("active_version")
    versions = registry.get("versions", [])

    active_info = None
    available = []
    # Reference baseline — computed by verify_seed_scores.py (2026-07-10).
    # A snapshot of what calculate_final_score() produces for the 7 demo rows.
    score_comparison = {
        "baseline_scores": [94, 92, 76, 86, 78, 91, 77],
        "versions": {},
    }

    for v in versions:
        info = {
            "version": v["version"],
            "label": v["label"],
            "metrics": v.get("metrics", {}),
            "is_active": v["version"] == active_version_id,
            "created_at": v.get("created_at", ""),
        }
        if v["version"] == active_version_id:
            active_info = info

        available.append(info)

        # Score comparison — stored baselines or estimated
        scores = v.get("score_baseline")
        if scores:
            note = (
                "active"
                if v["version"] == active_version_id
                else "estimated — stored baseline not available"
            )
            score_comparison["versions"][v["version"]] = {
                "scores": scores,
                "note": note,
            }

    return {
        "active_version": active_info,
        "available_versions": available,
        "score_comparison": score_comparison,
    }


@router.post("/activate")
async def activate_version(req: ActivateRequest):
    """Switch the active model version.

    Validates the version exists in the registry, persists the change to
    model_registry.json, and invalidates the in-memory model cache in the
    XGBoost predictor so the next prediction uses the new model.
    """
    registry = _read_registry()

    # Validate version exists
    found = None
    for v in registry.get("versions", []):
        if v["version"] == req.version:
            found = v
            break
    if found is None:
        raise HTTPException(
            status_code=404,
            detail=f"Version '{req.version}' not found in model registry.",
        )

    # Reject if already active
    if registry.get("active_version") == req.version:
        raise HTTPException(
            status_code=400,
            detail=f"Version '{req.version}' is already the active model.",
        )

    # Update registry on disk
    registry["active_version"] = req.version
    try:
        _write_registry(registry)
    except OSError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to write model registry: {e}",
        )

    # Invalidate in-memory predictor cache
    from ml.xgboost_predictor import set_active_version

    set_active_version(req.version)

    return _registry_to_response(registry)


# ── Rollback Router ─────────────────────────────────────────────────────────


def _acquire_rollback_lock() -> bool:
    """Try to acquire rollback lock. Returns True if acquired."""
    try:
        if ROLLBACK_LOCK_FILE.exists():
            return False
        ROLLBACK_LOCK_FILE.touch()
        return True
    except OSError:
        return False


def _release_rollback_lock():
    """Release rollback lock."""
    try:
        if ROLLBACK_LOCK_FILE.exists():
            ROLLBACK_LOCK_FILE.unlink()
    except OSError:
        pass


@rollback_router.get("/api/models/versions")
def get_model_versions():
    """Return all model versions from the registry."""
    registry = _read_registry()
    return {
        "active_version": registry.get("active_version"),
        "versions": registry.get("versions", []),
    }


@rollback_router.post("/api/models/xgboost/rollback")
def rollback_xgboost(
    version: str = Query(..., description="Version tag to rollback to"),
):
    """Rollback XGBoost model to a previous registry version.

    Validates version exists in registry, updates active_version,
    and invalidates the in-memory cache.
    """
    registry = _read_registry()
    active = registry.get("active_version")
    versions = registry.get("versions", [])

    # Find the target version
    target = None
    for v in versions:
        if v["version"] == version:
            target = v
            break

    if target is None:
        raise HTTPException(
            status_code=404,
            detail=f"Version '{version}' not found in registry. Available: {[v['version'] for v in versions]}",
        )

    if version == active:
        raise HTTPException(
            status_code=400,
            detail=f"Version '{version}' is already active. Nothing to rollback.",
        )

    # Check model file exists
    model_path = Path(__file__).resolve().parent.parent / "ml" / target["model_file"]
    if not model_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Model file '{target['model_file']}' not found on disk.",
        )

    # Acquire lock
    if not _acquire_rollback_lock():
        raise HTTPException(
            status_code=409,
            detail="A rollback is already in progress. Try again later.",
        )

    try:
        previous_active = active

        # Update registry
        registry["active_version"] = version
        _write_registry(registry)

        # Invalidate in-memory cache
        from ml.xgboost_predictor import set_active_version

        set_active_version(version)

        logger.info(
            "Model rolled back: %s -> %s (trigger: API call by admin)",
            previous_active,
            version,
        )

        return {
            "status": "success",
            "previous_version": previous_active,
            "active_version": version,
            "model_file": target["model_file"],
            "metrics": target.get("metrics", {}),
        }

    except Exception as e:
        # Rollback the rollback on failure
        registry["active_version"] = active
        _write_registry(registry)
        logger.error("Rollback failed, restored to %s: %s", active, str(e))
        raise HTTPException(
            status_code=500,
            detail=f"Rollback failed: {str(e)}",
        )

    finally:
        _release_rollback_lock()
