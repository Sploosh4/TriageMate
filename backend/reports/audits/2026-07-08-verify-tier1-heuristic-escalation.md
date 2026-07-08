# Verification Report: AI_PROBLEMS #14 — Tier 1 Heuristic Escalation

**Date:** 2026-07-08
**Scope:** Verify the claim in AI_PROBLEMS.md entry #14 about `_heuristic_evaluate()` in `backend/pipeline/tier_1.py`
**Performed by:** auditor
**Pre-flight:** N/A (code review, no script execution needed)

## Files Examined

| File | Lines |
|---|---|
| `backend/pipeline/tier_1.py` | Full (103 lines) — try/except flow, `_heuristic_evaluate()` body, routing logic |
| `backend/ml/xgboost_predictor.py` | Lines 34-38 (thresholds), 316-391 (`predict()` routing) |
| `docs/reference/AI_PROBLEMS.md` | Entry #14 (lines 168-173) |

## Verdict

| # | Claim | Result | Detail |
|---|---|---|---|
| 1 | Heuristic fires ONLY when XGBoost model loading fails | ✅ **TRUE** | Lines 26-55: try imports `xgboost_predictor.predict()`, except catches `FileNotFoundError`/`ImportError`/etc. and calls `_heuristic_evaluate()` |
| 2 | Confidence is ALWAYS in 0.72–0.85 range | ✅ **TRUE** | Lines 86-90: default `0.85`, conditionally lowered to `0.78` or `0.72`. Documented values exactly match code. |
| 3 | 0.72–0.85 ALWAYS lands in escalation band | ❌ **FALSE** | Routing uses `exploitation_probability`, NOT confidence. See Findings §1 below. |
| 4 | WON'T FIX explicitly stated in doc | ✅ **TRUE** | AI_PROBLEMS.md line 173: `**Status:** 🟢 WON'T FIX (fallback path, training model removes need)` |

**Overall: FAIL WITH ISSUES** — 3 passed, 1 failed, 0 skipped

---

## Findings

### §1. Routing is probability-based, not confidence-based (CLAIM IS FALSE)

The AI_PROBLEMS #14 entry states the routing logic as:

> `routing = "escalated" if 0.55 <= confidence <= 0.85 else "auto_resolved"`

This is **incorrect**. The actual routing code at `tier_1.py:92-97` is:

```python
if exploitation_prob >= 0.50:
    routing = "escalated"
elif exploitation_prob >= 0.30:
    routing = "escalated" if confidence <= 0.80 else "auto_resolved"
else:
    routing = "auto_resolved"
```

The decision is based on `exploitation_probability`, not confidence. There are **two code paths** where the heuristic produces `"auto_resolved"`:

| Condition | exploitation_prob range | confidence | Result |
|---|---|---|---|
| Very low CVSS/EPSS, non-internet-facing | < 0.30 | any (0.72–0.85) | `auto_resolved` |
| Moderate CVSS/EPSS, no reachability or cross_boundary risk | 0.30 – 0.50 | 0.85 (default) | `auto_resolved` |
| Moderate CVSS/EPSS, reachability>20 or cross_boundary>10 | 0.30 – 0.50 | 0.78 or 0.72 | `escalated` |
| High CVSS/EPSS, multiple risk factors | ≥ 0.50 | any (0.72–0.85) | `escalated` |

**Evidence of concrete auto-resolve scenario:** A CVE with `cvss_score=2.0`, `epss_score=0.01`, `internet_facing=False` would produce:
- `base_score = (2.0/10)*0.4 + 0.01*0.3 = 0.083`
- `env_score = -0.15` (not internet-facing)
- `exploitation_prob = max(0.0, 0.083 - 0.15) = 0.0`
- → `routing = "auto_resolved"` (exploitation_prob < 0.30)

The claim that the heuristic **always escalates** is false.

### §2. Stale line numbers in AI_PROBLEMS.md

The entry references:
- "line 63" — current file has `wellbeing = features.get(...)` at line 63 (not routing)
- "line 57" — current file has no line 57 (the heuristic is 103 lines long)

The file was modified after the AI_PROBLEMS entry was last updated, shifting all line numbers.

### §3. No 0.55 threshold exists anywhere in tiers

The entry mentions `"0.55 <= confidence <= 0.85"` but the number **0.55** does not appear anywhere in `tier_1.py` or `xgboost_predictor.py` as a routing threshold. The XGBoost predictor uses `LOW_PROB_THRESHOLD = 0.20` and `MID_PROB_THRESHOLD = 0.40`. The heuristic uses `0.50` and `0.30`. The source of the 0.55 threshold is unknown — likely a conflation from an older version or external documentation.

### §4. "WON'T FIX" rationale is reasonable

The AI_PROBLEMS entry correctly notes that the heuristic path is a **fallback only** (lines 38-46). When the XGBoost model is properly trained and deployed, `_heuristic_evaluate()` is never reached. The `WON'T FIX` designation is appropriate — fixing the routing logic of a rarely-used fallback is low priority.

However, the entry's **description of the problem is wrong**: the bug is not that "confidence always escalates" (it doesn't), but rather that the heuristic's routing thresholds (0.50/0.30) differ from the XGBoost model's thresholds (0.40/0.20), meaning heuristic fallback cases use a different escalation standard.

---

## Recommendations

1. **Update AI_PROBLEMS.md entry #14** to reflect the actual routing logic (probability-based, not confidence-based). The entry should describe the mismatch in routing thresholds between heuristic (0.50/0.30) and XGBoost model (0.40/0.20) as the actual issue, and correct the incorrect routing formula.

2. **Fix stale line numbers** in the entry — `line 63` should reference lines 92-97, `line 57` should reference line 86.

3. **(Optional) Harmonize heuristic thresholds** — change lines 92-96 to use 0.40/0.20 (matching xgboost_predictor.py) so the fallback at least routes consistently with the primary model. This would make the fallback behavior equivalent to a zero-knowledge XGBoost prediction. **Assumption:** I'm recommending this as a minor quality improvement; the WON'T FIX rationale still holds since this path is only reached when the model is absent.

---

## Cross-References

- **Line number audit:** AI_PROBLEMS.md references tier_1.py:63 and tier_1.py:57; actual routing at lines 92-97, confidence at lines 86-90
- **Routing threshold mismatch:** Heuristic 0.50/0.30 vs. XGBoost 0.40/0.20 — see `xgboost_predictor.py:35-38`
