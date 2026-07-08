# Verification Report: Tier 2 CWE Encoder (ModernBERT) Claim

**Date:** 2026-07-08
**Scope:** Verify the claim that Tier 2 CWE encoder (ModernBERT) is deferred, blocked on SecureBERT bug fixes, and currently uses NVD API + regex (`ingest_cwe.py`) for CWE lookup.
**Performed by:** auditor
**Pre-flight:** N/A — static file analysis, no import/runtime tests required.

---

## Claim Under Verification

> "Tier 2 CWE encoder (ModernBERT) is deferred — blocked on SecureBERT bug fixes. Currently uses NVD API + regex (ingest_cwe.py) for CWE lookup."

---

## Results

| Check | Result |
|---|---|
| 1. `modernbert` anywhere in codebase | ✅ No matches found |
| 2. `securebert` anywhere in codebase | ✅ Only in `.dockerignore` (cache dir exclusion) — no implementation |
| 3. `cwe_encoder` anywhere in codebase | ✅ Only in archived doc (`docs/archive/`) — no implementation |
| 4. ModernBERT model file in `backend/ml/` | ✅ No `cwe_encoder/` directory or model file exists |
| 5. ModernBERT import in `tier_2.py` | ✅ Zero references to ModernBERT, SecureBERT, or any local CWE encoder |
| 6. `tier_2.py` CWE source | ✅ Receives `cwe_result` as a parameter — does NOT call NVD or ingest_cwe directly |
| 7. `ingest_cwe.py` uses NVD API | ✅ Calls `get_nvd_data()` from `integrations.nvd.py` |
| 8. `ingest_cwe.py` uses regex fallback | ✅ Regex extraction from description if NVD fails |
| 9. `ingest_cwe.py` is the ONLY CWE mechanism | ✅ Called from `routers/ingest.py` line 108; result flows through pipeline to Tier 2 |
| 10. Deferral documented in `ROADMAP.md` | ✅ Line 194: "Tier 2 CWE encoder (ModernBERT) \| Blocked on SecureBERT bug fixes" |
| 11. Deferral documented in `MVP_SCOPE.md` | ✅ Line 79: "Local CWE encoder (ModernBERT) replacement is POST-MVP" |
| 12. SecureBERT bug reference exists | ✅ `AI_PROBLEMS.md` items #1-3 documented and marked ✅ BYPASSED |

---

## Detailed Evidence

### 1. No ModernBERT/SecureBERT Implementation Exists

**Codebase-wide grep:**
- `modernbert` — **zero matches** across entire codebase
- `securebert` — **1 match** in `.dockerignore:31` (`backend/ml/securebert_cache/`) — a cache dir exclusion, not an implementation
- `cwe_encoder` — **1 match** in archived doc `docs/archive/TriageMate MVP Transformation.md:1220` — historical plan, not active code

**No model files:**
The `backend/ml/` directory contains XGBoost models, EPSS models, pre-tier model, and SBERT encoder. There is **no** `cwe_encoder/` directory, no `cwe_classifier.py`, and no `cwe_classifier_deprecated.py` on disk.

### 2. `tier_2.py` Does Not Implement or Call a CWE Encoder

`backend/pipeline/tier_2.py` (724 lines) contains:
- No import of `modernbert`, `torch`, `transformers`, or any ML CWE classifier
- No reference to `SecureBERT`, `cwe_encoder`, or `cwe_classifier`
- CWE data enters via the `cwe_result: dict | None = None` parameter (line 184, 657)
- `build_prompt()` (line 174) simply formats the CWE result into the LLM prompt as a text block (lines 216–222)
- `evaluate_tier_2()` (line 647) passes `cwe_result` through to `build_prompt()`

The Tier 2 stage is purely a cloud LLM orchestrator — it does not perform CWE resolution.

### 3. `ingest_cwe.py` Is the Sole CWE Resolution Mechanism

`backend/ingest_cwe.py` (57 lines):
- **Docstring (line 4-6):** `"Uses NVD API for CWE mapping, with regex fallback from description. This is NOT an ML classifier — it delegates to backend/integrations/nvd.py for NVD API lookup."`
- **Primary path:** Calls `get_nvd_data(cve_id)` from `integrations.nvd.py` (line 45)
- **Regex fallback:** `_regex_fallback(text)` (line 21) extracts `CWE-\d+` patterns via `re.search(r"CWE-(\d+)", text)`
- **Fallback chain:** NVD data → regex on description → regex on CVE ID → empty string (lines 46–52)

**Pipeline integration (routers/ingest.py line 108):**
```python
cwe_result = get_cwe(payload.vulnerability_id, payload.raw_description or "")
```
This flows through EPSS substitution (line 114–124), Tier 1 (line 147–150), and Tier 2 (line 158–168) via the `cwe_result` parameter.

### 4. Deferral Explicitly Documented

**`docs/planning/ROADMAP.md` — Line 194:**
```
| Tier 2 CWE encoder (ModernBERT) | Blocked on SecureBERT bug fixes |
```
This is under the "Deferred (no current plan)" sub-section (lines 189–196).

**`docs/architecture/MVP_SCOPE.md` — Line 79:**
```
- **Local CWE encoder (ModernBERT) replacement is POST-MVP** (see §3)
```

**`docs/architecture/MVP_SCOPE.md` — Lines 120–121 (§3.1):**
```
| Tier 2 CWE encoder (ModernBERT, replacing NVD API CWE lookup) |
The NVD API + regex lookup (ingest_cwe.py) provides authoritative CWE
without the 656MB SecureBERT model.
```

**`docs/architecture/MVP_SCOPE.md` — Lines 168–169 (§3.6):**
```
| Fix CWE classifier SecureBERT head naming mismatch (AI_PROBLEMS.md #1) |
✅ BYPASSED — CWE classifier deprecated in favour of NVD API + regex lookup
(ingest_cwe.py). The 656MB SecureBERT2.0 model is no longer loaded.
```

### 5. SecureBERT Bug References

**`docs/reference/AI_PROBLEMS.md` — Items #1-3 (all ✅ BYPASSED):**

| # | Bug | Status |
|---|---|---|
| 1 | CWE Classifier: Head naming mismatch with SecureBERT2.0 | ✅ BYPASSED — replaced by NVD API + regex |
| 2 | CWE Classifier: ModernBERT has no `pooler_output` | ✅ BYPASSED — same as #1 |
| 3 | CWE Classifier: Cache dir bypasses shared HuggingFace cache | ✅ BYPASSED — 656MB model no longer loaded |

The original `backend/ml/cwe_classifier.py` was renamed to `cwe_classifier_deprecated.py` and later **removed from disk entirely**.

### 6. ROADMAP.md Also Confirms Deprecation

**Line 147:**
```
| CWE classifier | 🐛 Deprecated — replaced by NVD API + regex |
```

---

## Findings

1. **Claim confirmed: ALL 5 assertions are CORRECT.**
   - ✅ ModernBERT is deferred (no code or model exists)
   - ✅ Deferral is explicitly documented in ROADMAP.md and MVP_SCOPE.md
   - ✅ Blocked on SecureBERT bug fixes (items #1-3 in AI_PROBLEMS.md)
   - ✅ Current implementation uses NVD API + regex
   - ✅ `ingest_cwe.py` is the active CWE resolution mechanism

2. **No discrepancy found** between the claimed state and the actual codebase/documentation state.

3. **Archived docs still mention the CWE encoder plan** but these are properly marked as OUTDATED and reference ROADMAP.md for current state.

---

## Verdict

**PASS** — 12/12 checks passed, 0 failed, 0 skipped.

The claim is **accurate in all respects**. The ModernBERT CWE encoder is deferred with no implementation, blocked on SecureBERT bugs (AI_PROBLEMS.md #1-3), and the active CWE resolution mechanism is `ingest_cwe.py` (NVD API + regex fallback).

**No action required.** The documentation is consistent with the codebase state.
