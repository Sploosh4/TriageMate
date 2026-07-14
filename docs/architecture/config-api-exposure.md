# Config API Exposure — Feature Names Removal

**Date:** 2026-07-14
**Status:** Design/code pending — product-owner decision not yet recorded (Issue #58 remains open)

## Decision

The `feature_names` key has been removed from the `GET /api/config` response. The underlying `pipeline.config.feature_names` module remains intact — only the API exposure is stripped.

## Background

The `GET /api/config` endpoint (added Sprint 21, `backend/routers/config.py`) exposes all TriageMate configuration values grouped by domain: thresholds, scoring weights, multiplier values, and feature names. It is a read-only endpoint used by operators and the frontend admin settings page.

The `feature_names` block contained the full list of 68 tabular feature names used by the ML pipeline's feature vector:

```json
"feature_names": {
    "tabular_count": 68,
    "tabular_names": [
        "cvss_score",
        "epss_score",
        "nvd_reference_count",
        ...
    ]
}
```

While this is not a secret (no API keys, no credentials), exposing the exact feature vector order allows an attacker to:

1. **Reverse-engineer the ML pipeline** — knowing the feature order enables targeted adversarial inputs.
2. **Identify which features have zero weight** — an attacker could craft inputs that exploit dead features.
3. **Replicate the same feature layout** in a shadow model, probing for decision boundaries.

## Implementation

One change to `backend/routers/config.py`:

```python
# Before:
return {
    "thresholds": {...},
    "scoring": {...},
    "feature_names": {                         # ← removed
        "tabular_count": len(feature_names.TABULAR_FEATURE_ORDER),
        "tabular_names": feature_names.TABULAR_FEATURE_ORDER,
    },
    "threshold_info": _load_threshold_info(),
}

# After:
return {
    "thresholds": {...},
    "scoring": {...},
    "threshold_info": _load_threshold_info(),
}
```

The import of `feature_names` from `pipeline.config` was also removed to avoid an unused-import lint warning.

## What Was Not Changed

| Aspect | Status |
|---|---|
| `pipeline.config.feature_names` module | **Untouched** — still the single source of truth for feature ordering |
| XGBoost predictor | **Untouched** — still reads `TABULAR_FEATURE_ORDER` for inference |
| Feature parity checks | **Untouched** — still validate training vs inference feature alignment |
| Auth on `/api/config` | **Retained** — existing `get_current_user_if_enabled` guard unchanged |
| Other config domains | **Retained** — thresholds, scoring, threshold_info still exposed |

## Verification

- `GET /api/config` no longer contains a `feature_names` key.
- `pytest` passes (457+ tests, 0 fail).
- Existing test `test_config_has_feature_names` was removed; all other config endpoint tests remain.

## References

- `backend/routers/config.py` — Config API endpoint
- `backend/pipeline/config/__init__.py` — Config package
- `backend/pipeline/config/feature_names.py` — Feature names (unchanged)
- Sprint 29 security hardening
