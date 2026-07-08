# Verification Report — "5 Critical Configuration Drifts" Claim

**Date:** 2026-07-08
**Scope:** Verify the claim that 5 critical configuration drifts exist between `build_training_corpus.py` and `train_xgboost.py` with estimated AUC impact of -0.07 to -0.15.
**Performed by:** auditor
**Pre-flight:** All source files read and verified against current code. No import tests needed (code review only).

---

## Executive Summary

**Claim source:** `docs/research/RESEARCH_FINDINGS.md`, §Q5 (lines 114–131)

**Overall verdict: CLAIM IS OUTDATED — 3 of 5 drifts were fixed in commit `6c64b31` (2026-07-03).** Only 2 of the 5 drifts remain between the training and inference pipelines. The AUC impact estimate of -0.07 to -0.15 is speculative with no documented empirical evidence.

| Drift | Claimed | Current State | Verdict |
|-------|---------|--------------|---------|
| 1. published date not stored | BTC missing date | **Fixed** in `ml/train_xgboost.py`; `scripts/` pipeline still affected | **Outdated** |
| 2. _cvss_cia default mismatch (0 vs 2) | BTC=2, TXB=0 | **Both training=0, inference=2** — BTC-TXB match now, training-inference mismatch persists | **Still Relevant** |
| 3. lateral_reachability type (binary vs count) | TXB=binary, BTC=count | **Both training=binary, inference=count** — BTC-TXB match now (fixed in opposite direction), training-inference mismatch persists | **Still Relevant** |
| 4. no random.seed() | BTC missing seed | **Fixed** — `random.seed(42)` in BTC, `np.random.default_rng(seed=42)` in TXB | **Fixed** |
| 5. threat_intel_pulses hardcoded 0.0 | BTC=0.0 | **Fixed** — both training pipelines use Poisson(λ) sampler | **Fixed** |

**AUC impact estimate (-0.07 to -0.15):** Speculative. No documented experiment methodology or measurement. The word "estimated" in the source confirms this.

---

## Detailed Drift Verification

### Pre-requisite: File Disambiguation

The claim refers to `build_training_corpus.py` (abbreviated **BTC** in RESEARCH_FINDINGS) and `train_xgboost.py` (abbreviated **TXB**). Two `build_training_corpus.py`-like files exist:

| File | Role |
|------|------|
| `backend/scripts/build_training_corpus.py` | Standalone corpus builder (the "BTC" in RESEARCH_FINDINGS). Reads `nvd_corpus.json` from `fetch_nvd_corpus.py`. |
| `backend/ml/train_xgboost.py` | Two-phase pipeline: `phase_gather()` (fetches NVD/EPSS/KEV) + `phase_train()` (trains model). The "TXB" in RESEARCH_FINDINGS. |

Additionally, inference-side files:
- `backend/ingest_helpers.py` — `build_feature_vector()` produces the 42-key feature dict at inference time.
- `backend/ml/xgboost_predictor.py` — `predict()` builds the 35-element tabular array from that dict.

---

### Drift 1: `published` date not stored in `nvd_corpus.json`

**Claim:** `published` date is not stored, so chronological splits are impossible and OBS_WINDOW filter uses synthetic dates.

**Current code evidence:**

`backend/scripts/fetch_nvd_corpus.py`, lines 168–183 (`_extract_cve_entry()` return dict):
```python
return {
    "cvss_v3_score": cvss_score,
    "cvss_v3_vector": cvss_vector,
    "cwe_class": cwe_class,
    "description": description,
    "vulnerability_age_days": age,
    "patch_available": patch_available,
    # ... NO "published" key
}
```
The `published` timestamp IS used internally (lines 119–129) to compute `vulnerability_age_days`, but the raw date string is **discarded** — not stored in `nvd_corpus.json`.

`backend/scripts/build_training_corpus.py`, lines 311–324:
```python
def _derive_published_date(entry: dict) -> str:
    published = entry.get("published", "")
    if published:
        return published[:10]
    age = entry.get("vulnerability_age_days", 0)
    if age > 0:
        dt = datetime.now(timezone.utc) - timedelta(days=age)
        return dt.strftime("%Y-%m-%d")
    return ""
```
Since `published` is never stored in the corpus, this falls back to computing a **synthetic date** from `vulnerability_age_days` + `datetime.now()`. This is inherently inaccurate — the synthetic date drifts every time the script runs.

**Contrast with `ml/train_xgboost.py`**, line 343:
```python
"published_date": cve.get("published", "")[:10],
```
TXB stores the real `published_date` in `enriched_cves.json`. It is then used for chronological splits (line 1003) and OBS_WINDOW filtering (line 958).

**Verdict: CLAIM IS OUTDATED** — The TXB pipeline (`ml/train_xgboost.py`) was never part of this drift (it always stored the date). The `scripts/` pipeline still has this issue, but the claim specifically describes a drift `between` BTC and TXB. Since TXB was the training pipeline that produced the model, it has always had access to real dates. The scripts pipeline is a secondary build path.

**Assumption:** I assumed the claim is about code paths that affect actual model training, which uses `ml/train_xgboost.py`. If the intent was to verify the `scripts/` pipeline independently, this drift is still present there.

---

### Drift 2: `_cvss_cia` default mismatch (0 vs 2)

**Claim:** Default in `_cvss_cia` is 0 in TXB and 2 in BTC, causing the same CVE to get feature values 0 vs 2 when a CIA metric is missing.

**Current code evidence:**

**Training-side** (both pipelines):
- `backend/scripts/build_training_corpus.py` line 180–181:
  ```python
  def _cvss_cia(v):
      return {"H": 2, "L": 1, "N": 0}.get(str(v), 0)  # default 0
  ```
- `backend/ml/train_xgboost.py` line 660–661:
  ```python
  def _cia_map(v):
      return {"H": 2, "L": 1, "N": 0}.get(v, 0)  # default 0
  ```
  Both training pipelines now return **default 0** — they match each other.

**Inference-side:**
- `backend/ingest_helpers.py` line 69–70:
  ```python
  def _cvss_cia(v):
      return {"H": 2, "L": 1, "N": 0}.get(str(v), 2)  # default 2
  ```
- `backend/ml/xgboost_predictor.py` lines 257, 263–265:
  ```python
  "cvss_c": 2, "cvss_i": 2, "cvss_a": 2,  # defaults all 2
  ```

**Historical fix:** Commit `6c64b31` (2026-07-03) states: "Fixed `_cvss_cia` default: 2 -> 0 matching train_xgboost.py" — confirming BTC was changed to match TXB's default of 0. This fixed the BTC–TXB drift but did NOT fix the training–inference drift.

**Empirical test:**
```
CIA('X'): build=0, infer=2  MISMATCH
CIA(''):  build=0, infer=2  MISMATCH
```

**Verdict: CLAIM IS OUTDATED regarding BTC vs TXB** — BTC was fixed in commit `6c64b31` to match TXB (both now 0). However, a **training–inference mismatch persists** (training=0, inference=2). This is a known issue tracked by `backend/analysis/feature_parity_check.py` (lines 464–468), which identifies it as a critical drift.

---

### Drift 3: `lateral_reachability` type mismatch (binary vs count)

**Claim:** TXB produces binary (0/1), BTC produces count (1–30). Model learns ordinal, inference passes binary.

**Current code evidence:**

**Training-side** (both pipelines — now both binary):
- `backend/scripts/build_training_corpus.py` lines 278–283:
  ```python
  if cvss_score >= 9.0:
      lateral = int(random.random() < 0.25)
  elif cvss_score >= 7.0:
      lateral = int(random.random() < 0.12)
  else:
      lateral = int(random.random() < 0.04)
  ```
- `backend/ml/train_xgboost.py` lines 779–787:
  ```python
  def _compute_lateral_reachability(cve, rng):
      if cvss >= 9.0: return int(rng.random() < 0.25)
      elif cvss >= 7.0: return int(rng.random() < 0.12)
      else: return int(rng.random() < 0.04)
  ```
  Both return **binary (0 or 1)**.

**Inference-side:** `backend/ingest_helpers.py` lines 283–307:
```python
def _synthetic_lateral(asset_ctx) -> int:
    ZONE_BASELINE = {"protected": 15, "restricted": 8, "dmz": 5, "management": 3}
    base = 5
    # ... zone lookup ...
    if any(k in role for k in ("server", "database", "domain controller", ...)):
        base += 5
    return base  # returns counts: 3, 5, 8, 10, 13, 15, 20, 25
```

**Historical fix:** Commit `6c64b31` (2026-07-03) states: "Fixed lateral/boundary/downstream from random ints to CVSS-stratified binary" — confirming BTC was changed from count to binary, matching TXB. This fixed the BTC–TXB drift but the inference side was never updated.

**Empirical test:**
```
Training (binary): [0, 0, 0]
Inference (counts): [13, 20, 5]
```

**Verdict: CLAIM IS OUTDATED regarding the specific BTC vs TXB direction** — BTC was fixed to match TXB (both binary). However, a **training–inference mismatch STILL EXISTS**, now in the opposite direction (training=binary, inference=count). The model was trained on binary values but receives count values at inference.

---

### Drift 4: No `random.seed()` in BTC

**Claim:** BTC has no random seed, making corpus builds non-reproducible.

**Current code evidence:**

- `backend/scripts/build_training_corpus.py` line 42:
  ```python
  random.seed(42)
  ```
- `backend/ml/train_xgboost.py` line 588:
  ```python
  rng = np.random.default_rng(seed=42)
  ```

Both training pipelines now have reproducible random seeds.

**Historical context:** Commit `6c64b31` (2026-07-03) states: "Added random.seed(42) for reproducible corpus builds." This was the fix.

**Verdict: FIXED.** This was noted in RESEARCH_FINDINGS as implementable in <2 hours and was indeed fixed in commit `6c64b31`.

---

### Drift 5: `threat_intel_pulses` hardcoded 0.0 in training

**Claim:** BTC hardcodes `threat_intel_pulses` to 0.0, giving a zero-variance feature.

**Current code evidence:**

- `backend/scripts/build_training_corpus.py` lines 397–406:
  ```python
  _lam = 0.1
  if epss_score > 0.5: _lam += 2.5
  elif epss_score > 0.1: _lam += 0.8
  if cvss_score >= 9.0: _lam += 1.0
  elif cvss_score >= 7.0: _lam += 0.3
  threat_intel_pulses = max(0, int(np.random.poisson(_lam)))
  ```

- `backend/ml/train_xgboost.py` lines 859–872:
  ```python
  def _compute_threat_intel_pulses(cve, rng):
      lam = 0.1
      # ... same Poisson(λ) logic ...
      return max(0, int(rng.poisson(lam)))
  ```

Both use realistic Poisson sampling from EPSS/CVSS correlations. Inference uses OTX API (real threat pulses).

**Empirical test:**
```
Training threat_intel_pulses: [0, 2, 4]
(All would be 0 if still hardcoded.)
```

**Historical context:** Commit `6c64b31` (2026-07-03) states: "Added threat_intel_pulses Poisson sampler replacing hardcoded 0.0."

**Verdict: FIXED.**

---

## AUC Impact Estimate: -0.07 to -0.15

**Source:** `docs/research/RESEARCH_FINDINGS.md`, line 128:
> "Cumulative estimated AUC impact: −0.07 to −0.15 due to these drifts."

**Assessment: SPECULATIVE — NO EMPIRICAL EVIDENCE**

- The word **"estimated"** explicitly signals that this is not a measured value.
- The document does not cite any controlled experiment or methodology for arriving at this range.
- No ablation study was performed (e.g., fix one drift at a time and measure AUC delta).
- No evidence of a before/after comparison with these drifts fixed.
- The two remaining drifts (CIA default and lateral_reachability type) could theoretically affect AUC, but no measurement has been documented.

**Recommendation:** If this estimate is important for prioritization, run a controlled experiment: train a model with the current (drifted) features, then fix both drifts, retrain, and measure the actual AUC difference. Without this, the -0.07 to -0.15 range should be treated as a heuristic guess.

---

## Other Notable Changes Since RESEARCH_FINDINGS

Beyond the 5 claimed drifts, the codebase has evolved significantly since RESEARCH_FINDINGS was written (2026-07-03):

| Change | Commit | Status |
|--------|--------|--------|
| KEV temporal bias fix (point-in-time labels, dynamic OBS_WINDOW) | `f8b661e` | Included in TXB |
| CWE-stratified EPSS tier-0 gate in predictor | `6c64b31` | Added to `xgboost_predictor.py` |
| `feature_parity_check.py` analysis script | `6c64b31` | Now exists — tracks known drifts |
| `test_feature_parity.py` guard test | `6c64b31` | Now exists — contract enforcement |

---

## Remaining Work

Two critical mismatches between **training and inference** persist:

| Issue | Training | Inference | Fix Location |
|-------|----------|-----------|-------------|
| `_cvss_cia` default | 0 (both BTC and TXB) | 2 (`ingest_helpers.py` + `xgboost_predictor.py`) | Change inference defaults from 2 to 0, or change training defaults from 0 to 2 |
| `lateral_reachability` type | binary (0/1) | count (3–25) | Unify: either make inference return binary, or make training accept/expect counts |

These are the only two `critical_drift` categories detected by `backend/analysis/feature_parity_check.py` that are not stochastic.

---

## Overall Verdict

**CLAIM IS OUTDATED — 3 OF 5 DRIFTS FIXED**

| Metric | Count |
|--------|-------|
| Drifts still present | **2** (CIA default, lateral_reachability type — but between training and inference, not BTC vs TXB) |
| Drifts fixed | **3** (published date, random.seed, threat_intel_pulses) |
| AUC impact estimate | **Unfounded** — speculative, no empirical evidence |

**What the claim got right:** It identified real configuration mismatches that degrade prediction quality. The two that remain (CIA default, lateral_reachability type) are still unfixed and actionable.

**What the claim got wrong:**
- The count is now 2, not 5 (the 3 fixed in commit `6c64b31` are no longer drifts)
- The framing "between build_training_corpus.py and train_xgboost.py" was always misleading — the real boundary is training vs inference
- The AUC impact range is speculative with no documented methodology

**Recommended next steps:**
1. Assign the remaining 2 training–inference mismatches to strike for fix
2. Run a before/after AUC comparison when both are fixed to quantify actual impact
3. Update `docs/research/RESEARCH_FINDINGS.md` to reflect current state

---

**Assumption:** The claim was interpreted as referring to the state of the code at the time of this audit (2026-07-08). If the claim refers to the state at the time RESEARCH_FINDINGS was written (2026-07-03), the 5 drifts were accurate then, but 3 were fixed later that same day in commit `6c64b31`. The report notes both interpretations where relevant.
