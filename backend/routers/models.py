"""
Model version management router.

Provides read-write access to the model registry:
- GET  /api/model/versions  — list all registered model versions
- GET  /api/model/status   — active model info with cross-version comparison
- POST /api/model/activate — switch the active model version
"""

import json
import os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

REGISTRY_PATH = Path(__file__).resolve().parent.parent / "ml" / "model_registry.json"


class ActivateRequest(BaseModel):
    version: str


router = APIRouter(prefix="/api/model", tags=["Model Version Management"])


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
    # Reference baseline from retrain verification (2026-07-08).
    # A snapshot, not recomputed from live inference.
    score_comparison = {
        "baseline_scores": [94, 87, 71, 63, 55, 41, 22],
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
