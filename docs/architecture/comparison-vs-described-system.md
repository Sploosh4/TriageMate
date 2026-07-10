# Comparison: Described System vs Current Implementation

> **Status:** CURRENT · **Last updated:** 2026-07-10
> **Purpose:** Maps each of the 5 described system areas to the actual MVP code to identify what was simplified, added onto, or completely changed.

---

## 1. Routing & Uncertainty Checking

**Described system:** ML layer → uncertainty check → (low uncertainty) auto-approve with 5–10% audit sample OR (high uncertainty) escalate to advanced AI (LLM).

### What was simplified

| Item | Described | Implemented |
|---|---|---|
| Uncertainty formula | "Complex formula shown in image_fdf722.png" | **Ensemble variance.** XGBoost partial-tree prediction standard deviation (`ensemble_std`). 1 line of computation vs an entire formula. |
| Confidence zones | Single uncertainty threshold | 3 probability zones + ensemble uncertainty: low (<0.20), mid (0.20–0.40), high (>0.40) with ensemble_std ≤0.10 as the uncertainty gate. Marginally more complex but still a handful of `if` statements. |
| Audit sample | 5–10% | 7.5% (`AUDIT_SAMPLE_RATE = 0.075`). Same pattern, exact rate fixed. |

### What was added onto

| Addition | Where | Why |
|---|---|---|
| **Pre-Tier classifier** (asset tagger) | `pipeline/pre_tier.py` | Not in the described system at all. Adds a hostname-to-mission-tags step before the routing pipeline — 3-phase (known dict → RF model → default). |
| **Tier 0 deterministic rules** | `pipeline/tier_0.py` | The described system goes straight from ML to uncertainty check. The MVP has a whole rule-based tier before ML: NVD ref ≥21 auto-resolve, KEV+CVSS≥9+IF auto-resolve, KEV+EPSS+Sensitive auto-resolve, CVSS<4+EPSS<threshold auto-resolve. |
| **Pre-model bypass** | `xgboost_predictor._tier_zero_check()` | KEV fast-path and CWE-stratified EPSS threshold check skip XGBoost entirely for clear signals. |
| **3-tier pipeline** | Full routing flow | Described: ML → LLM. Actual: Pre-Tier → Tier 0 (rules) → Tier 1 (XGBoost) → Tier 2 (LLM). Four stages, not two. |
| **Provider fallback chain** | `tier_2.py` | Primary → backup → KNOWN_CONFLICTS cache → neutral default. Not described. |

### What was completely changed

Nothing fundamentally — the high-level "ML routes, uncertain cases go to LLM" structure matches. But the *number of stages* and *pre-ML rule system* are unmentioned in the description.

---

## 2. Composite Risk Score (CRS)

**Described system:** 3 areas (Internal Environment, Exploit Likelihood, Asset Importance) × custom importance multipliers → 0–100 score.

### What was simplified

| Item | Described | Implemented |
|---|---|---|
| Core equation | "Complex equation like in image_fdf740.png" | **Simple weighted sum** of 7 dimensions. `total = sum(dimensions.values())`, clamp to 0–100. Straight arithmetic. |
| Multipliers | "Custom importance levels set by security team" | Hardcoded per-dimension max weights (CVSS=40, EPSS=20, etc.) — no runtime user configuration. *Simpler but less flexible.* |

### What was added onto

| Addition | Where | Why |
|---|---|---|
| **7 dimensions** instead of 3 | `scoring.py` | CVSS (40), EPSS (20), Asset Criticality (20), Exposure (12), Patch (5), ML Exploitation (10), Security Context (5). More granular than the described 3-area model. |
| **Tier 2 score adjustment** | `scoring.py:59–61` | LLM can adjust score by −20 to +20 before clamp. Not described. |
| **Security Context dimension** | `scoring.py:38–40` | Sprint 17 addition combining telemetry threat score (×3) + network blast radius (×2) → max 5. Not described. |
| **EPSS substitution feeds into score** | `scoring.py:28` | Sector-adjusted EPSS replaces raw EPSS in the EPSS dimension. Not described. |
| **Score bands** | `scoring.py:65–72` | Low (≤25), Medium (26–50), Critical (51–75), Very Critical (76–100). Not described. |
| **Per-dimension breakdown** | Everywhere | The scoring engine returns full per-dimension breakdown for the frontend display. Not described. |

### What was completely changed

The 3-area multiply-by-importance model was **replaced** by a 7-dimension weighted sum with hardcoded caps. The described system's "grade 3 areas × custom importance" is more flexible in theory but was never implemented — the actual code uses fixed-weight additive scoring.

---

## 3. Simplifying Text Data for the AI

**Described system:** Text → "massive lists of numbers" (embeddings) → compressed into "much smaller, targeted summaries" that can safely combine with structured data.

### What was simplified

Nothing in this area was simplified — the opposite occurred.

### What was added onto

Nothing — the described compression step does not exist.

### What was completely changed

| Aspect | Described | Implemented |
|---|---|---|
| **Embedding size** | "Massive lists" → compressed small | **Full 384-dim SBERT** (`all-MiniLM-L6-v2`), no compression. |
| **Combination strategy** | Compress embeddings before combining with tabular data | **Concatenate** 35 tabular + 384 SBERT = **419-dim total**. No compression step. |
| **Dimensionality handling** | Compression to avoid "confusing the system" | **XGBoost regularization** (colsample_bytree=0.8, max_depth=4, subsample=0.8) handles the full 419-dim space. |
| **PCA** | Not mentioned | **Was present, then removed in v2.5** — commit message: "PCA removed to eliminate data leakage" (PCA was fitted on entire dataset before train/test split). |

**This is the most divergent area.** The described system's central claim — that massive lists need compression to be usable — is handled by the opposite approach in the actual code: throw the full 384-dim SBERT at a regularized XGBoost and let it learn feature importance naturally.

---

## 4. Balancing Rare and Common Threats

**Described system:** Heavy penalty for ignoring critical threats, small penalty for flagging harmless bugs. "Replaces the math shown in image_fdf79e.png."

### What was simplified

| Item | Described | Implemented |
|---|---|---|
| Penalty formula | "Complex formula in image_fdf79e.png" | **`scale_pos_weight = n_neg / n_pos`**. Standard XGBoost parameter, one line. |

### What was added onto

| Addition | Where | Why |
|---|---|---|
| **Point-in-time KEV labels** | `train_xgboost.py:construct_labels()` | CVEs added to KEV after the training data cutoff are labeled 0 (not 1). Prevents future information leakage. Not described. |
| **Dynamic observation window** | `train_xgboost.py` ~line 360 | Median KEV lag (~190 days) used to exclude unreliable negatives (CVEs too recent to have KEV labels). Not described. |
| **Decision threshold tuning** | `train_xgboost.py:phase_train()` | Finds optimal classification threshold by maximizing F1 on validation set. Not described. |
| **Platt calibration** | `train_xgboost.py:phase_train()` | Logistic regression calibrator on validation set to fix probability distortion. Not described. |
| **Chronological split** | `train_xgboost.py:phase_train()` | Train/val/test split by publication date, not random. Not described. |

### What was completely changed

The core concept matches: penalize the model more for missing rare positives than for false positives on negatives. The mechanism (`scale_pos_weight`) is the standard XGBoost approach, which maps to the described "heavy/small penalty" language. But the training pipeline is much more sophisticated than just a weight — it adds temporal bias correction, calibration, and threshold optimisation that aren't mentioned.

---

## 5. Safety Guardrails for the Advanced AI

**Described system:**
- **Step limit:** Max 40 investigative steps per vulnerability
- **Retry limit:** 3 attempts per action, then tool locked
- **Self-doubt check:** Must argue against itself before final decision

### What was simplified

| Item | Described | Implemented |
|---|---|---|
| Self-doubt check | Two-step: (1) assess, (2) verify | **Single force-reflection prompt** — the LLM performs steps A (primary assessment), B (counter-argument), and C (final determination) in one response. Same logic, less infrastructure. |
| Multi-step investigation | Up to 40 steps | **Single-shot call**. The entire Tier 2 is one LLM API call, not a loop. Drastically simpler. |

### What was added onto

| Addition | Where | Why |
|---|---|---|
| **Provider fallback chain** | `tier_2.py:evaluate_tier_2()` | Primary → backup → KNOWN_CONFLICTS cache → neutral default. Not described. |
| **Cost tracking** | `tier_2.py:_record_api_call()` | Per-call token counts and estimated USD cost. Not described. |
| **Structured JSON schema** | `tier_2.py:_build_openai_schema()` | LLM output constrained to `TriageConflictResult` Pydantic schema. Not described. |
| **RAG context** | `vector_store.py` + `tier_2.py` | LanceDB vector store queried for internal document context fed into the prompt. Not described. |
| **CWE classification in prompt** | `tier_2.py:build_prompt()` | CWE pillar/class/base/variant included in LLM context. Not described. |

### What was completely changed

| Aspect | Described | Implemented |
|---|---|---|
| **Step limit (40)** | Multi-turn investigation loop | **Not implemented.** The LLM gets one shot per vulnerability. No step counter, no loop logic. |
| **Retry limit as "tool lock"** | Per-action retries, tool locked after 3 failures | **`_MAX_RETRIES = 3` per provider** — for API connectivity errors, not per-tool. On total failure, falls through provider chain to known conflicts cache, not a "locked tool." No tool-locking mechanism exists. |
| **Investigation architecture** | Agentic loop with tool use | **Stateless prompt + response.** The LLM doesn't have tools to call; it receives all context (CVE, RAG, scores) in a single prompt and returns a JSON decision. |

**This area is the most architecturally divergent after text compression.** The described system envisions an agentic LLM that can take multiple investigative steps (search databases, check records, etc.), while the implemented system is a single-shot structured-output classifier. Both produce a decision, but the mechanism is fundamentally different.

---

## Summary Matrix

| Area | Simplified | Added Onto | Completely Changed |
|---|---|---|---|
| **1. Routing & Uncertainty** | Uncertainty formula (→ ensemble_std) | Pre-Tier, Tier 0 rules, pre-model bypass, 3-tier pipeline, provider fallback | — (structure matches but is more elaborate) |
| **2. Composite Risk Score** | Complex equation (→ weighted sum) | 7 dims (vs 3), Tier-2 adjustment, security context, score bands, breakdown | 3-area × multiplier model **replaced** by 7-dim weighted sum with hardcoded caps |
| **3. Text Data Simplification** | — | — | **Compression does not exist.** Full 384-dim SBERT + 35 tabular = 419-dim. PCA was removed. XGBoost regularization handles dimensionality. |
| **4. Class Imbalance** | Complex penalty formula (→ `scale_pos_weight`) | Temporal bias correction, observation window, threshold tuning, Platt calibration, chronological split | — (concept matches, implementation is more thorough) |
| **5. LLM Safety Guardrails** | Multi-step investigation (→ single shot), self-doubt check (→ unified prompt) | Provider fallback, cost tracking, JSON schema, RAG context, CWE context | **40-step agentic loop does not exist.** Single-shot stateless API call. Retry limit is for connectivity, not tool-locking. |

## Key Takeaways

1. **The largest gap is in #3 (Text Compression)** — the entire premise of the described system is contradicted by the actual implementation. This would be the first thing to correct in any design document based on this description.

2. **The second-largest gap is in #5 (LLM Guardrails)** — the described system envisions an agentic multi-step LLM, while the implementation is a single-shot classifier. The guardrails that exist (retries, force-reflection prompt) are shadows of what was described.

3. **The described system omitted entire subsystems** — Pre-Tier classifier, Tier 0 deterministic rules, EPSS substitution engine, RAG vector store, temporal bias correction, and the provider fallback chain are all absent from the description but critical in the actual code.

4. **Where the description matches, it's at the conceptual level** — the actual implementations tend to use standard ML/library techniques (XGBoost `scale_pos_weight`, ensemble variance, weighted sum) rather than the "complex formulas" referenced in the described system.
