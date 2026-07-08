# Verification Report: `KNOWN_CONFLICTS` Claim

**Date:** 2026-07-08
**Scope:** Verification of claim about `KNOWN_CONFLICTS` dict in `backend/pipeline/tier_2.py`
**Performed by:** auditor
**Pre-flight:** N/A (no scripts run — manual code inspection)

## Results

| Check | Status | Evidence |
|---|---|---|
| KNOWN_CONFLICTS has exactly 3 CVEs | ✅ PASS | Lines 54-103 in tier_2.py — exactly 3 entries |
| The 3 CVEs are correctly named | ✅ PASS | CVE-2023-36884, CVE-2023-22515, CVE-2022-47966 — confirmed |
| Fallback for unknown CVEs uses confidence=0.30 | ✅ PASS | `_neutral_default()` at line 635, `"confidence": 0.30` (line 642) |
| Fallback has "no adjustment" (score_adjustment=0) | ✅ PASS | `"score_adjustment": 0` at line 643 |
| Fallback for unknown CVEs is actually reachable | ✅ PASS | Lines 710-724: `if cve_id in KNOWN_CONFLICTS:` → else → `_neutral_default()` |
| No TODO/FIXME about expanding KNOWN_CONFLICTS | ✅ PASS (noted) | Neither file contains TODOs about expansion |
| Empty KNOWN_CONFLICTS in llm.py is separate | ✅ PASS (noted) | `llm.py` has `KNOWN_CONFLICTS: Dict[...] = {}` — empty, separate from tier_2.py |

## Findings

### 1. KNOWN_CONFLICTS in `tier_2.py` — Lines 54-103

**File:** `backend/pipeline/tier_2.py`

The dictionary is defined at line 54 and closes at line 103. It contains exactly **3 entries**:

| CVE | confidence | score_adjustment |
|---|---|---|
| `CVE-2023-36884` | 0.72 | -15 |
| `CVE-2023-22515` | 0.68 | -37 |
| `CVE-2022-47966` | 0.91 | -66 |

All three have `"text_conflict": True` and include detailed `conflict_note` text.

### 2. Fallback Path — Lines 710-724

The fallback chain in `evaluate_tier_2()` (line 647):

```
Primary LLM provider → Backup LLM provider → KNOWN_CONFLICTS → _neutral_default()
```

- **Line 710-719:** If `cve_id in KNOWN_CONFLICTS`, the cached dict is returned (with a note appended about cloud LLM unavailability).
- **Line 721-724:** If NOT in `KNOWN_CONFLICTS` (and all providers failed), `_neutral_default()` is returned.

### 3. Neutral Default — Lines 635-644

```python
def _neutral_default(cve_id: str, error_msg: str) -> dict:
    return {
        "text_conflict": False,
        "conflict_note": "Cloud LLM unavailable (...) No cached resolution available.",
        "rag_result": "NOT_QUERIED",
        "resolution": "Unable to perform semantic analysis. Deferring to Tier 1 score.",
        "confidence": 0.30,
        "score_adjustment": 0,
    }
```

- **`confidence`**: 0.30 ✅
- **`score_adjustment`**: 0 (no adjustment) ✅
- **`text_conflict`**: False (neutral)
- **`rag_result`**: `"NOT_QUERIED"`

### 4. Secondary `KNOWN_CONFLICTS` in `llm.py` (Minor Inconsistency)

**File:** `backend/integrations/llm.py`, lines 145-155

There is a **second, empty** `KNOWN_CONFLICTS` dictionary:

```python
KNOWN_CONFLICTS: Dict[str, Dict[str, Any]] = {
    # Known CVE → neutral default scores used when LLM is unavailable
    # or when the CVE is part of the demo set.
    #
    # These ensure the pipeline never crashes on demo CVEs and provide
    # a zero-cost fallback when the LLM is unreachable.
}
```

This is a separate definition. It is **empty** and has **no actual entries**. It is used by `get_known_conflict()` (line 160) which is exported for other modules, but the real data lives in `tier_2.py`. This appears to be leftover from a refactoring where `llm.py` was extracted but the conflict data was not migrated.

### 5. No TODOs About Expansion

Neither `tier_2.py` nor `llm.py` contain `TODO`, `FIXME`, or `HACK` comments about expanding `KNOWN_CONFLICTS`. The docstrings in both files treat the dictionary as a stable, known-resolution cache for demo CVEs.

### 6. Documentation Consistency

The archive docs confirm the 3-CVE scope:
- `docs/archive/sprints-1-6/SPRINT_1_HANDOFF.md:187` — explicitly states "CVE-2023-36884, CVE-2023-22515, and CVE-2022-47966"
- `docs/architecture/MVP_SCOPE.md:76` — explicitly ties KNOWN_CONFLICTS to "3 SLM demo CVEs"

## Verdict

**PASS** — 6 checks passed, 0 failed.

The claim is **fully accurate**:

1. ✅ `KNOWN_CONFLICTS` in `tier_2.py` covers exactly **3 CVEs**
2. ✅ The 3 CVE IDs are **CVE-2023-36884, CVE-2023-22515, CVE-2022-47966**
3. ✅ Defined at **lines 54-103**
4. ✅ Unknown CVEs fall through to `_neutral_default()` with **confidence 0.30** and **score_adjustment 0** (no adjustment)

### Out of scope, but noted:
- `backend/integrations/llm.py` has a separate empty `KNOWN_CONFLICTS` dict (lines 145-155) that is dead code — no entries are ever populated. If this module is meant to be the canonical source of conflict data, it should be populated or removed.
