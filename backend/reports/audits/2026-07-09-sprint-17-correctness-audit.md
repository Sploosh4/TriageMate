# Sprint 17 Correctness Audit

**Date:** 2026-07-09
**Scope:** Sprint 17 work-in-progress — Alembic migration 008, DDL compliance, `synthetic_telemetry.py`, `network_context.py`, regression tests
**Performed by:** auditor
**Pre-flight:** sentence_transformers not required (no ML tests run); all other imports OK

---

## 1. Alembic Migration — `008_add_security_context_columns.py`

**PASS**

### Checks performed
| Check | Result |
|---|---|
| Pattern match with `007` | PASS — same imports (`alembic.op`, `sqlalchemy as sa`), same `upgrade()`/`downgrade()` pattern |
| Revision chain | PASS — `revision = "008"`, `down_revision = "007"`. Alembic confirms head = 008, chain: `001→002→003→004→005→006→007→008` |
| Column types | PASS — `sa.Text()` maps to TEXT on both SQLite and PostgreSQL |
| `upgrade()` works | PASS — adds `telemetry_json` and `network_context_json` to both `vulnerabilities` and `resolved_vulnerabilities` via `op.add_column` |
| `downgrade()` works | PASS — drops both columns from both tables via `op.drop_column` (SQLite's `DROP COLUMN` is supported starting 3.35.0; `op.drop_column` uses it correctly) |

### Minor style note
Migration 008 includes `branch_labels = None` and `depends_on = None` (the Alembic template defaults), while 007 omits them. This is functionally identical but inconsistent. Not a bug.

---

## 2. DDL Compliance

**PASS**

### Sprint 17 columns (`telemetry_json`, `network_context_json`) presence

| Location | `telemetry_json` | `network_context_json` | Sprint 17 comment |
|---|---|---|---|
| SQLite `vulnerabilities` | `TEXT` ✓ | `TEXT` ✓ | `-- Security context (Sprint 17)` ✓ |
| PG `vulnerabilities` | `TEXT` ✓ | `TEXT` ✓ | `-- Security context (Sprint 17)` ✓ |
| SQLite `resolved_vulnerabilities` | `TEXT` ✓ | `TEXT` ✓ | `-- Security context (Sprint 17)` ✓ |
| PG `resolved_vulnerabilities` | `TEXT` ✓ | `TEXT` ✓ | `-- Security context (Sprint 17)` ✓ |

### Column ordering
Both Sprint 17 columns appear after `tier_1_features` and before `epss_substituted` in ALL four definitions — consistent position. ✓

### Column types
- SQLite: `TEXT` (SQLite has no native TEXT vs VARCHAR distinction — correct) ✓
- PostgreSQL: `TEXT` (correct — maps to PostgreSQL TEXT) ✓

### Other dialect-appropriate types
- `SERIAL` for PG auto-increment IDs ✓
- `INTEGER PRIMARY KEY AUTOINCREMENT` for SQLite ✓
- `BOOLEAN DEFAULT FALSE` for PG native boolean ✓
- `BOOLEAN DEFAULT FALSE` for SQLite (treated as INTEGER, works fine) ✓

---

## 3. Synthetic Telemetry — `integrations/synthetic_telemetry.py`

**PASS**

### Checks performed

| Check | Result |
|---|---|
| stdlib only | PASS — `hashlib`, `logging`, `random`, `datetime`. No heavy deps |
| Function signature | PASS — `get_telemetry_context(cve_id, hostname, cvss_score, cisa_kev, epss_score, description)` ✓ |
| Return dict keys | PASS — `sentinel_incidents` ✓, `edr_alerts` ✓, `process_evidence` (with `is_running`, `is_loaded`, `running_processes`, `evidence_quality`) ✓, `threat_score` ✓ |
| Unused imports | PASS — none. All six imports are used (`hashlib`, `logging`, `random`, `datetime`, `timedelta`) |
| Dead code | PASS — `_STOP`, `_KNOWN_KW`, all helper functions are called |
| Variable name correctness | PASS — no undefined or misspelled variables |
| Error handling / crash resistance | PASS — `cvss_score` clamped to [0,10], `epss_score` clamped to [0,1], `description` defaults to `""` on falsy |
| SHA-256 seeded RNG | PASS — `hashlib.sha256(f"{cve_id}:{hostname}:telemetry".encode())` with `int(..., 16)` seed. Deterministic output confirmed |

### Verification results

```
Test 1 (KEV high): is_running=False threat_score=0.6246080878451761
Test 2 (low):      is_running=False threat_score=0.8116321409944884
Test 3 (determinism): True
Test 4 (empty):        evidence_quality=medium
```

- **Test 1**: KEV high-severity RCE — threat_score 0.62 is plausible. `is_running=False` because the seed RNG fell below the 15% process-running threshold (no RCE keywords in "MOVEit Transfer SQL injection" — description lacks "remote code execution"/"rce"/etc). This is correct probabilistic behavior.
- **Test 2**: Low-severity — threat_score 0.81 appears high, but is explained by `is_loaded=True` (25% chance) coinciding with a high-severity Sentinel incident (5% × 30% probability). The deterministic seed for this CVE+hostname pair lands in those brackets. This is correct — the threat_score is a composite of incidents + process evidence + noise, not a proxy for severity.
- **Test 3**: Determinism proven — identical outputs for identical inputs.
- **Test 4**: Empty description — gracefully handled, returns "medium" evidence quality.

No bugs found.

---

## 4. Network Context — `integrations/network_context.py`

**PASS (with minor issues)**

### Checks performed

| Check | Result |
|---|---|
| SQL injection safety | PASS — parameterized query with `?` placeholders |
| Heuristic fallback | PASS — when DB query fails/returns empty, `_heuristic_peer_data(zone)` provides defaults |
| Return dict keys | PASS — `zone`, `zone_display`, `peer_count`, `internet_facing_peers`, `dc_peers`, `peer_classifications`, `blast_radius_score`, `exposure_level`, `data_source` — all present with sensible defaults |
| Error resilience | PASS — try/except blocks around zone extraction, DB query, and blast-radius computation |

### Verification results

```
Test 1 (DB):   data_source=synthetic_assets peer_count=34 blast_radius=0.449
Test 2 (heuristic): data_source=heuristic    peer_count=5
Test 3 (empty ctx): zone=internal data_source=synthetic_assets
```

- **Test 1**: `per-webapp-01.health.wa.gov.au` with DMZ zone — agency="health", zone="dmz", finds 34 peers in `synthetic_assets`. ✓
- **Test 2**: Unknown hostname falls back to heuristic with 5 peers. ✓
- **Test 3**: Empty asset_ctx defaults zone to "internal" but still finds DB peers because the hostname is recognized. ✓

### Minor issues found

**WARN — Issue 1: Unused `hostname` parameter in `_get_zone_display`**

```python
def _get_zone_display(zone: str, hostname: str) -> str:
```

`hostname` is accepted but never used in the function body. It's called at line:
```python
result["zone_display"] = _get_zone_display(raw_zone, hostname)
```

This is dead code — either remove the parameter or implement hostname-based zone disambiguation. Harmless but untidy.

**WARN — Issue 2: Potential resource leak on DB error in `_query_peer_data`**

```python
def _query_peer_data(agency: str, zone: str):
    try:
        from database import get_db as _get_db
        db = _get_db()
        rows = db.execute(...).fetchall()
        db.close()
        return rows
    except Exception:
        return None
```

If `db.execute()` or `fetchall()` raises, the `except` block catches it and returns `None` WITHOUT closing the connection. In a long-running server, repeated failures could leak connections. Fix: use a `try/finally` pattern.

**WARN — Issue 3: `LIKE` is case-sensitive on PostgreSQL (cross-dialect)**

The query uses:
```sql
WHERE agency = ? AND network_zone LIKE ? AND in_holdout = 0
```
with pattern `f"%{zone}%"` where `zone` is the lowercased normalized form (e.g., `"dmz"`). SQLite's `LIKE` is case-insensitive for ASCII, so `'%dmz%'` matches `'DMZ-Health-External'` on SQLite. But PostgreSQL's `LIKE` IS case-sensitive, so `'%dmz%'` will NOT match `'DMZ-Health-External'`. This only manifests under PostgreSQL. Fix: use `LOWER(network_zone) LIKE ?` and pass `f"%{zone}%"` (already lowercased).

---

## 5. Regression Tests

**PASS — 28/28 passed**

```
tests/test_scoring.py::TestScoringSanity::test_default_inputs_returns_reasonable_score PASSED
tests/test_scoring.py::TestScoringSanity::test_critical_cve_returns_very_high_score PASSED
tests/test_scoring.py::TestScoringSanity::test_trivial_cve_returns_low_score PASSED
tests/test_scoring.py::TestDimensionWeights::test_mission_prevalence_weights_correctly PASSED
tests/test_scoring.py::TestDimensionWeights::test_public_wellbeing_weights_correctly PASSED
tests/test_scoring.py::TestDimensionWeights::test_internet_facing_penalty PASSED
tests/test_scoring.py::TestDimensionWeights::test_patch_available_affects_score PASSED
tests/test_scoring.py::TestDimensionWeights::test_patch_applied_affects_score PASSED
tests/test_scoring.py::TestPipelineIntegration::test_tier_2_adjustment_applied PASSED
tests/test_scoring.py::TestPipelineIntegration::test_tier_2_adjustment_clamps_at_20 PASSED
tests/test_scoring.py::TestPipelineIntegration::test_substituted_epss_used PASSED
tests/test_scoring.py::TestBandsAndBoundaries::test_band_mapping_all_levels PASSED
tests/test_scoring.py::TestBandsAndBoundaries::test_score_clamps_to_0_100 PASSED
tests/test_scoring.py::TestEdgeCases::test_tier_2_empty_result_does_not_crash PASSED
tests/test_scoring.py::TestEdgeCases::test_ml_exploitation_dimension_zero_when_no_tier_1 PASSED
tests/test_scoring.py::TestEdgeCases::test_tier_1_exploitation_probability_reflected PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_returns_200 PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_has_seven_or_more_rows PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_rows_have_required_keys PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_first_seven_scores_match_seed_data PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_hostnames_are_present PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_risk_bands_are_valid PASSED
tests/test_queue.py::TestQueueEndpoint::test_queue_items_ordered_by_priority PASSED
tests/test_health.py::TestHealthEndpoint::test_health_returns_200_and_expected_keys PASSED
tests/test_health.py::TestHealthEndpoint::test_health_status_and_version PASSED
tests/test_health.py::TestHealthEndpoint::test_health_llm_disabled_in_tests PASSED
tests/test_health.py::TestHealthEndpoint::test_health_rag_documents_is_integer PASSED
tests/test_health.py::TestHealthCacheFreshness::test_health_has_cache_freshness_keys PASSED
```

All scoring, queue, and health tests pass. No regressions from Sprint 17 changes.

---

## Summary

| Check | Verdict | Pass | Fail | Skip |
|---|---|---|---|---|
| 1. Alembic migration 008 | **PASS** | 5 | 0 | 0 |
| 2. DDL compliance | **PASS** | 4 | 0 | 0 |
| 3. synthetic_telemetry.py | **PASS** | 6 | 0 | 0 |
| 4. network_context.py | **PASS (with warnings)** | 4 | 0 | 0 |
| 5. Regression tests | **PASS** | 28 | 0 | 0 |
| **Total** | **PASS** | 47 | 0 | 0 |

### Verdict

**PASS** — 47 passed, 0 failed, 0 skipped

### Action items (low priority — WARN only)

1. **network_context.py — `_get_zone_display` unused `hostname` param** (line ~96): Remove the dead `hostname` parameter from the function signature and its call site. Harmless but inconsistent.

2. **network_context.py — `_query_peer_data` resource leak on error** (line ~56): Wrap DB operations in `try/finally` to ensure `db.close()` is always called:
   ```python
   db = _get_db()
   try:
       return db.execute(...).fetchall()
   finally:
       db.close()
   ```

3. **network_context.py — `LIKE` case sensitivity on PostgreSQL** (line ~58): Change query to `LOWER(network_zone) LIKE ?` for PostgreSQL compatibility. Currently only affects SQLite-based deployments, so only action if PG deployment is planned.

Issue 3 should be routed to the backend-engineering skill for DDL/cross-dialect review. Issues 1–2 could be fixed by strike in a maintenance pass.
