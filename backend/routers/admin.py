"""
Admin configuration endpoints for TriageMate.
Auth-gated — requires JWT authentication with admin role.
"""

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from auth import get_current_user_if_enabled
from middleware.rate_limit import limiter, RATE_LIMIT_ADMIN, RATE_LIMIT_DEFAULT

# NOTE: We import the module (not its attrs) so that reload_weights() updates
# are visible through scoring_cfg.SCORING_WEIGHTS / scoring_cfg.TOTAL_WEIGHT.
import pipeline.config.scoring as scoring_cfg

from pipeline.config.scoring import (
    _MAX_WEIGHT,
    _MIN_TOTAL,
    _MIN_WEIGHT,
    reload_weights,
    reset_weights_to_defaults,
)

logger = logging.getLogger("triagemate.admin")
router = APIRouter(tags=["Admin"])

# Hardcoded defaults for reference
_DEFAULT_WEIGHTS = {
    "cvss": 40,
    "epss": 20,
    "criticality": 20,
    "exposure": 12,
    "patch": 5,
    "ml_exploitation": 10,
}
_DEFAULT_TOTAL = sum(_DEFAULT_WEIGHTS.values())


class WeightUpdateRequest(BaseModel):
    weights: dict[str, int] = Field(
        ...,
        description=(
            "Six scoring weights: cvss, epss, criticality, exposure, "
            "patch, ml_exploitation (security_context was removed in Sprint 21)"
        ),
    )


class ScoringConfigResponse(BaseModel):
    weights: dict[str, int]
    total_weight: int
    defaults: dict[str, int]
    default_total: int
    min_weight: int = _MIN_WEIGHT
    max_weight: int = _MAX_WEIGHT
    min_total: int = _MIN_TOTAL


def _build_response() -> ScoringConfigResponse:
    """Build a response from the current live scoring config."""
    return ScoringConfigResponse(
        weights=scoring_cfg.SCORING_WEIGHTS,
        total_weight=scoring_cfg.TOTAL_WEIGHT,
        defaults=_DEFAULT_WEIGHTS,
        default_total=_DEFAULT_TOTAL,
    )


@router.get("/api/admin/config/scoring", response_model=ScoringConfigResponse)
@limiter.limit(RATE_LIMIT_DEFAULT)
def get_scoring_config(request: Request, user=Depends(get_current_user_if_enabled)):
    """Return current scoring weights, defaults, and validation bounds."""
    return _build_response()


@router.put("/api/admin/config/scoring", response_model=ScoringConfigResponse)
@limiter.limit(RATE_LIMIT_ADMIN)
def update_scoring_config(
    body: WeightUpdateRequest,
    request: Request,
    user=Depends(get_current_user_if_enabled),
):
    """Update scoring weights. Validates and saves to scoring_weights.json."""
    weights = body.weights

    # Validate
    required = {
        "cvss",
        "epss",
        "criticality",
        "exposure",
        "patch",
        "ml_exploitation",
    }
    if set(weights.keys()) != required:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Must provide exactly these keys: {required}. "
                f"Got: {set(weights.keys())}"
            ),
        )

    for key, value in weights.items():
        if not isinstance(value, int) or value < _MIN_WEIGHT or value > _MAX_WEIGHT:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Weight '{key}'={value} is invalid. "
                    f"Must be int between {_MIN_WEIGHT} and {_MAX_WEIGHT}."
                ),
            )

    total = sum(weights.values())
    if total < _MIN_TOTAL:
        raise HTTPException(
            status_code=422,
            detail=f"Total weight {total} is below minimum {_MIN_TOTAL}.",
        )

    # Save to config file (atomic write: temp file → fsync → rename)
    config_dir = Path(__file__).resolve().parent.parent / "pipeline" / "config"
    config_file = config_dir / "scoring_weights.json"
    tmp_file = config_dir / "scoring_weights.json.tmp"
    with open(tmp_file, "w") as f:
        json.dump({"weights": weights}, f, indent=2)
        f.flush()
        import os

        os.fsync(f.fileno())
    tmp_file.replace(config_file)

    # Reload in-memory
    reload_weights()

    return _build_response()


@router.post("/api/admin/config/scoring/reset", response_model=ScoringConfigResponse)
@limiter.limit(RATE_LIMIT_ADMIN)
def reset_scoring_config(request: Request, user=Depends(get_current_user_if_enabled)):
    """Reset scoring weights to factory defaults."""
    reset_weights_to_defaults()
    return _build_response()
