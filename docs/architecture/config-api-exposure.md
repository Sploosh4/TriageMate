# Config API Exposure

**Date:** 2026-07-14
**Status:** IMPLEMENTED and approved in GitHub Issue #58; merged in PR #75

## Decision

`GET /api/config` exposes operational thresholds, scoring configuration, and
`threshold_info`, but does not expose the ML feature-name list.

The endpoint retains `get_current_user_if_enabled`: authentication is enforced
when auth is enabled and remains optional under the project's existing
environment-gated auth model.

## Implementation

`backend/routers/config.py` no longer imports
`pipeline.config.feature_names` and no longer returns a `feature_names` key.
The underlying feature registry is unchanged and remains available to internal
training, inference, contract, and parity code.

## What remains exposed

- Tier and drift thresholds
- Scoring weights and limits
- Security-context multiplier configuration
- The status/content of `threshold_info.json`

No credentials, tokens, model artifacts, or feature-order metadata are exposed
by this route.

## Verification

The config API regression tests verify the response contract and the removal
of `feature_names`. PR #75 passed the GitHub Actions test matrix.

## References

- `backend/routers/config.py`
- `backend/tests/test_config.py`
- `backend/pipeline/config/feature_names.py` (internal registry, unchanged)
- GitHub Issue #58
- GitHub PR #75
