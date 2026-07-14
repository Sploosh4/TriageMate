# Scoring Weight Zero Policy

**Date:** 2026-07-14
**Status:** FINAL

## Decision

A scoring weight of **zero is NOT supported**. Each of the six scoring dimensions must have a minimum weight of 1.

## Rationale

1. **Semantic clarity** — Each weight dimension represents a meaningful factor in the priority score. Setting a dimension to zero would silently remove it, potentially confusing operators who expect it to contribute.
2. **Simplicity** — The current minimum of 1 ensures all six dimensions are always active. If an organization wants to exclude a dimension entirely, the scoring model itself should be reconfigured (not just zero-weighted).
3. **Total weight invariant** — The minimum total of 100 ensures at least 100 points are distributed. Zero-weight dimensions would require other dimensions to compensate, potentially distorting the scoring model.

## Implementation

| Component | Current behavior | Decision |
|---|---|---|
| Backend (`_MIN_WEIGHT = 1`) | Rejects weight < 1 | ✅ Retain |
| Frontend slider (`min = '1'`) | Cannot slide below 1 | ✅ Retain |
| API validation (`value < _MIN_WEIGHT`) | Returns 422 for weight < 1 | ✅ Retain |

## References

- Sprint 27 bug: FE-LOW-3
- Files: `backend/pipeline/config/scoring.py`, `backend/routers/admin.py`, `frontend/js/components/adminSettings.js`
