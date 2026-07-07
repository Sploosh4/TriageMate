---
name: audit-checklist
description: Technical audit procedures, ML calibration checks, schema parity validation, feature vector compliance, EPSS evaluation, regression testing. Use when running audits, verifying changes, validating deployment readiness, or performing sprint quality gates.
---

# Audit Checklist

This skill grows over time as audit patterns emerge. Add new sections when an agent repeatedly does the same verification.

---

## 1. ML Calibration Audit

**Command:** `python -m analysis.calibration_audit`
**What it checks:** XGBoost probability calibration (predicted vs. actual exploitation rates)
**When:** After any model retraining or feature change

## 2. EPSS Evaluation

**Command:** `python -m analysis.epss_eval`
**What it checks:** EPSS substitution model accuracy vs. real EPSS scores
**When:** After EPSS model retraining or cache refresh

## 3. Feature Parity Check

**Command:** `python -m analysis.feature_parity_check`
**What it checks:** Feature vector keys match between build script and prediction pipeline
**When:** After any change to `build_feature_vector()` or `build_training_corpus.py`

## 4. Schema Conversion Validation

**Command:** `python -m analysis.validate_conversion`
**What it checks:** Data schema integrity after conversion or migration
**When:** After database schema changes

## 5. Full Regression Test

**Command:** `pytest backend/tests/ -v`
**What it checks:** All tests — ingest, queue, health, demo generator, integration, fuzzed ingest
**When:** Before any deployment or sprint completion

---

## Placeholder Audits (to be implemented)

### 6. Schema Parity Audit
Verify SQLite and PostgreSQL table schemas match exactly. Compare `_init_db_sqlite()` and `_init_db_pg()` in `database.py`. Every column in one must exist in the other with correct type mapping.

### 7. Demo Data Plausibility Audit
Check all demo scenarios against `wa-gov-consulting` rules. No real WA government hostnames, IPs, or department identifiers. Hostnames must follow PRD-APP-SERVER01.dept.wa.gov.au pattern. OS-to-department mappings must be realistic.

### 8. LLM Cost-Per-Case Audit
Track Tier 2 LLM calls — token counts, provider used, fallback triggered. Compare actual costs to the $0.0004/case target. Flag cases that hit the expensive provider or exceeded token budget.

### 9. Cache Freshness Audit
Check last-modified timestamps on all cache files in `backend/data/`. Flag any cache older than its TTL. Identify which caches need refresh before the next pipeline run.

### 10. Score Drift Audit
Track the 7 demo row scores over time. If any score shifts by more than ±3 from its baseline (94, 87, 71, 55, 63, 41, 22), flag for investigation. This catches silent model drift.

### 11. Integration Health Audit
Test each integration module with a known CVE. Verify graceful degradation — failed integrations must not crash the pipeline. Check that all integrations return safe defaults on error.

### 12. DDL Compliance Audit
Verify that any recent `database.py` change has entries in both `_init_db_sqlite()` and `_init_db_pg()`. Cross-reference with the `backend-engineering` skill (dual-DDL pattern was consolidated there after `dual-database-ddl` was archived).
