# Audit: EPSS Tenable Aggregation Script

**Date:** 2026-07-08
**Scope:** `backend/scripts/aggregate_tenable_sectors.py` and `backend/tests/test_aggregate_sectors.py`
**Performed by:** auditor
**Pre-flight:** `python3` found at `/usr/bin/python3` (3.12.3); `sentence_transformers` not required for this audit; all applicable analysis scripts import clean.

---

## Checks Performed

### 1. Import Correctness — `_extract_agency`

| Check | Result | Evidence |
|---|---|---|
| `_extract_agency` exists in `epss_substitutor.py` | **PASS** | Defined at line 242 |
| Signature matches call site | **PASS** | `def _extract_agency(hostname: str) -> str:` — single `hostname` param, matches all 3 call sites in the aggregator (lines 104, 184) |
| Import resolves at runtime | **PASS** | `python3 -c "from ml.epss_substitutor import _extract_agency"` succeeds. Runtime `--test` mode ran correctly, extracting 4 sectors from 5 test findings. |
| No duplicate logic | **PASS** | Aggregator imports from `epss_substitutor` rather than reimplementing agency extraction (as required by Sprint 13 review) |

**Verdict: PASS** — Import is correct and properly reusable.

---

### 2. Error Handling

| Check | Result | Evidence |
|---|---|---|
| Missing `plugin` key | **PASS** | `finding.get("plugin", {})` returns empty dict; falls through to `cve` check; logged as warning |
| Empty/missing `cve` array | **PASS** | Guard `not cve_list or not isinstance(cve_list, list) or not cve_list[0]` catches empty list, non-list, and falsy first element (None, "") |
| Missing `asset` key | **PASS** | `finding.get("asset", {})` returns empty dict; `_extract_hostname` returns `"unknown"` |
| Missing `fqdn` (fallback to `hostname`) | **PASS** | `test_missing_fqdn_fallback` passes; `_extract_hostname` tries `fqdn` → `hostname` → `"unknown"` |
| Neither `fqdn` nor `hostname` | **PASS** | `test_no_fqdn_or_hostname` passes; maps to `"unknown"` sector |
| Non-string `fqdn` (e.g., int) | **PASS** | `isinstance(fqdn, str)` check fails; falls to hostname check, then `"unknown"` |
| Null/None CVE in array | **PASS** | `not cve_list[0]` catches `None`; finding skipped with warning |
| Empty string CVE in array | **PASS** | `not ""` is True; finding skipped |
| Logging configured | **PASS** | `logger = logging.getLogger("triagemate.aggregate_tenable_sectors")` defined; `logging.basicConfig` called in `main()` |
| `min_frequency` > total findings | **PASS** | Returns metadata-only dict; `total_findings` reflects pre-filter count, `unique_cves` = 0, `unique_sectors` = 0 |

**Verdict: PASS** — All error paths handled gracefully without crashes.

---

### 3. Output Format

| Check | Result | Evidence |
|---|---|---|
| `_metadata` present | **PASS** | Always included in output dict |
| `total_findings` correct | **PASS** | Pre-filter count; verified via CLI test (5) and unit tests |
| `unique_cves` correct | **PASS** | Count of keys before filtering; verified via CLI test (2) |
| `unique_sectors` correct | **PASS** | Set of all sector names across all CVEs; CLI test showed 4 |
| `generated_at` ISO format | **PASS** | `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")` — verified in test and CLI output |
| Output structure | **PASS** | `{CVE-ID: {sector: count, ...}, "_metadata": {...}}` — matches docstring spec |

**Verdict: PASS** — Output format matches documented contract exactly.

---

### 4. Test Coverage — Gaps Analysis

8 tests exist, all passing:

| Test | Covers | Gaps Identified |
|---|---|---|
| `test_empty_input` | Empty list → metadata-only | None |
| `test_basic_aggregation` | Same CVE, same sector → count=3 | None |
| `test_multi_sector_grouping` | Same CVE across sectors | None |
| `test_min_frequency_filter` | `min_frequency=2` excludes count-1 | None |
| `test_missing_fqdn_fallback` | `hostname` key used when `fqdn` absent | None |
| `test_missing_cve_skipped` | Empty `cve` array skipped | None |
| `test_no_fqdn_or_hostname` | `"unknown"` sector for IP-only findings | None |
| `test_multiple_cves_different_sectors` | Full cross-tabulation | None |

**Potential gaps (minor, acceptable):**

| Gap | Severity | Recommendation |
|---|---|---|
| No test for `--test` CLI flag end-to-end | Low | The `--test` mode is a self-validating smoke test, not a pytest unit test. Acceptable as-is. |
| No test for findings with missing `plugin` key entirely | Low | Code handles it gracefully (warning logged); could add a test for completeness |
| No test for `min_frequency=0` | Low | Edge case with no practical use; code works correctly (no filtering) |
| No test for multi-CVE findings (only `cve_list[0]` used) | Low | Design decision to take only first CVE; would be nice to document with a comment or test |

**Verdict: PASS** — 8 tests provide solid coverage. Gaps are minor and acceptable for the scope.

---

### 5. Existing Test Suite — No Regressions

Full test suite run: **84 passed, 8 failed, 1 skipped** (93 total)

**New tests (test_aggregate_sectors.py): 8/8 PASSED** — no regressions introduced.

**Pre-existing failures (not caused by new code):**

| Test | Failure Reason | Needs |
|---|---|---|
| `test_fuzzed_ingest_no_crashes` | `nvd_corpus.json` not found | NVD corpus data file |
| 7 `test_model_versions` tests | `model_registry.json` not found; `active_version` is None | Model registry file + seeded models |

These are pre-existing failures unrelated to the aggregation script.

**Verdict: PASS** — No regressions from the new test file.

---

### 6. ROADMAP Changes

| Check | Result | Evidence |
|---|---|---|
| Sprint 12 in sprint table | **PASS** | Line 26: `Sprint 12 \| Gap Hardening \| ✅ Complete` |
| Sprint 13 in sprint table | **PASS** | Line 27: `Sprint 13 \| EPSS Data Pipeline + Documentation \| 🔧 In progress` |
| Item 17 updated | **PASS** | Line 226: `Item 17: EPSS substitution retrain \| 🔧 Assessed` with link to assessment report |

**Verdict: PASS** — ROADMAP correctly reflects Sprint 12/13 status and Item 17.

---

### 7. SKILL.md Sprint 12 Fix Integrity

| Check | Result | Evidence |
|---|---|---|
| Line 34 lists `models` in router list | **PASS** | `backend-engineering/SKILL.md` line 34: `- \`backend/routers/\` — API endpoint routers (auth, cases, ingest, models, queue)` |
| `models` router exists | **PASS** | `backend/routers/models.py` exists with 3 endpoints: `GET /versions`, `GET /status`, `POST /activate` |
| `main.py` wires models router | **PASS** | Confirmed in Sprint 12 hypercritical review; `main.py` line 169 wires `models_router.router` |

The Sprint 12 fix (adding `models` to the stale router list in `backend-engineering/SKILL.md`) remains intact.

**Verdict: PASS** — Fix preserved.

---

## Summary of Results

| Check | Result |
|---|---|
| 1. Import Correctness — `_extract_agency` | **PASS** |
| 2. Error Handling | **PASS** |
| 3. Output Format | **PASS** |
| 4. Test Coverage | **PASS** (8 tests, minor gaps noted) |
| 5. Full Test Suite — No Regressions | **PASS** (8/8 new tests pass; 8 pre-existing unrelated failures) |
| 6. ROADMAP Sprint 12/13 + Item 17 | **PASS** |
| 7. SKILL.md Sprint 12 Fix Integrity | **PASS** |

---

## Verdict

**PASS** — 7/7 checks pass. 8/8 new tests pass. No regressions.

### Recommendations (non-blocking)

1. **Document multi-CVE behavior**: Add a comment in `aggregate_findings()` clarifying that only `cve_list[0]` is used per finding, since multiple CVEs per finding are technically possible in the Tenable schema.

2. **Add a test for missing `plugin` key**: Simple 3-line test case for completeness — currently the only gap in the error-handling coverage.

3. **Pre-existing failures**: The 8 test failures (`test_fuzzed_ingest`, `test_model_versions`) are unrelated but should be addressed by the team:
   - `test_model_versions` needs `ml/model_registry.json` to be present (seeded with v1/v2/v3 entries)
   - `test_fuzzed_ingest` needs `data/nvd_corpus.json` to be present
