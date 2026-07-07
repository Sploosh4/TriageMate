# TriageMate — Sprint NEXT+2 Research Findings

> **Status: CURRENT** (3 July 2026)

**Prepared for:** Commander  
**Date:** 2026-07-03  
**Method:** 5-agent swarm (prompt design → research → synthesis → verification)

---

## Executive Summary

Five parallel research streams analysed TriageMate's exploitation prediction pipeline. Three cross-cutting themes emerged:

1. **The training corpus is the binding constraint.** 516 of 1,631 KEV entries are missing from the training set (31.6% loss). 14 configuration drifts exist between the two pipeline implementations. Fixing these yields the highest per-hour ROI of any change.

2. **EPSS alone is a strong signal but not sufficient.** ROC-AUC 0.94 for KEV prediction, but best F1 is only 0.42. Stratified thresholds by CWE and CVSS band materially improve this and are trivial to implement.

3. **Free signals already in the corpus are underutilised.** NVD reference count ≥21 has 8.6× baseline KEV rate. CWE-843 (Type Confusion) has 10.9×. OSV's `published` timestamp is fetched from the API every time but thrown away by the parser.

---

## Q1 — Label Strategy Research

**Question:** What label strategy maximises model performance beyond binary KEV membership?

**Four strategies evaluated:**

| Strategy | Label Type | #Positives | Feasibility | Verdict |
|---|---|---|---|---|
| Multi-window binary (3-class) | Categorical | 856 active / 397 PoC | Medium | Extreme imbalance (99.1% negative); tiny 2nd class |
| EPSS regression | Continuous (0–1) | All 140K contribute | **High** | Uses all data; seamless XGBoost integration |
| Survival/hazard (T, E) | Time-to-event | 884 valid intervals | Low | Too few events; needs new model architecture |
| Composite score | Continuous (0–1) | 59 high / 1K med | Medium | KEV baked into formula creates leakage |

**Recommendation: EPSS regression as secondary output.** Keep binary KEV as primary triage gate. Add continuous EPSS prediction as a prioritisation score for the ~835 confirmed positives. All 140K CVEs contribute to regression training vs 835 for binary. Requires only changing XGBoost objective from `binary:logistic` to `reg:logistic`.

---

## Q2 — Early-Indicator Features

**Question:** What signals are available before KEV / EPSS catches up? (Median KEV lag: 212 days from NVD publish)

**Top 10 ranked signals by feasibility × impact:**

| Rank | Signal | Source | KEV Rate Lift | Lead Time | Cost |
|---|---|---|---|---|---|
| 1 | NVD Reference Count ≥21 | NVD (corpus) | **8.6×** | Day 0 | Free |
| 2 | CWE-843 (Type Confusion) | NVD (corpus) | **10.9×** | Day 0 | Free |
| 3 | CVSS Score ≥9.0 | NVD (corpus) | 12.1× (1.93% vs 0.16%) | Day 0 | Free |
| 4 | Patch Available flag | NVD (corpus) | 6.0× | Day 0 | Free |
| 5 | CWE-121 (Stack Overflow) | NVD (corpus) | Median lag only **18 days** | Day 0 | Free |
| 6 | Vendor = Citrix/Sophos/SonicWall | vendor_popularity.json | 10–17× | Day 0 | Free |
| 7 | Composite AV:N+AC:L+PR:N+UI:N | CVSS vector | 1.7× | Day 0 | Free |
| 8 | NVD Reference Count 11–20 | NVD (corpus) | 5.2× | Day 0 | Free |
| 9 | OSV published date | OSV API (already called) | Earliest disclosure date | 0–30d | **Free—already fetched, not stored** |
| 10 | CWE-288 (Auth Bypass variant) | NVD (corpus) | 4.9×, median lag 22d | Day 0 | Free |

**Key finding:** ExploitDB PoC and Metasploit fields in the corpus (`exploitdb_has_poc`, `metasploit_has_payload`) are **always False for all 186K entries** — zero variance. The data exists in `files_exploits.csv` (25,037 CVEs mapped, 20,097 verified) but was never loaded into the corpus. This is a pipeline gap, not a data gap.

---

## Q3 — Missing KEV Analysis

**Question:** Why are 516 of 1,631 KEV entries missing from the training set?

| Bucket | Count | Root Cause |
|---|---|---|
| Pre-2019 | **433** (83.9%) | `fetch_nvd_corpus.py` default start date is 2019-01-01 |
| Post-2025 | **80** (15.5%) | Default end date is 2025-12-31 (all are CVE-2026-*) |
| Within range but CVSS v3.1 missing | **3** (0.6%) | `_extract_cve_entry()` requires CVSS v3.1 metrics; these 3 CVEs only have v2.0 or v3.0 |

**Year distribution of missing CVEs:** 2002(1), 2004(2), 2005(1), 2006(2), 2007(3), 2008(5), 2009(15), 2010(23), 2011(9), 2012(22), 2013(38), 2014(34), 2015(44), 2016(59), 2017(86), 2018(89), 2023(1), 2025(2), 2026(80).

**Impact:** The pipeline has only 835 usable KEV positives (point-in-time, `dateAdded ≤ 2024-12-31`, in NVD corpus) instead of the full 1,631. That is 51.2% label loss.

**Recommendation:** Add `--kev-ids` flag to `fetch_nvd_corpus.py` to fetch specific CVEs by ID regardless of date range. API cost: ~1.7 minutes for 516 queries. Recovers 100% of missing entries with zero corpus bloat (no need to re-fetch 40K+ pre-2019 non-KEV CVEs).

---

## Q4 — EPSS Baseline

**Question:** How well does EPSS alone predict KEV entry? Does it match XGBoost?

| Metric | Value |
|---|---|
| ROC-AUC (EPSS alone) | **0.9426** |
| Best F1 | **0.418** @ threshold t=0.84 |
| Best F2 | **0.455** @ threshold t=0.30 |
| PR-AUC | 0.408 (baseline 0.6%) → 68× lift |
| Precision @ Recall ≥0.50 | 0.137 @ t=0.10 |
| Precision @ Recall ≥0.80 | N/A (no threshold reaches 80% recall) |

**Stratified optimal thresholds vary significantly:**

| Stratum | ROC-AUC | Best F1 | Optimal t |
|---|---|---|---|
| CWE-22 (Path Traversal) | 0.972 | **0.65** | 0.085 |
| CWE-78 (OS Command Injection) | 0.985 | **0.61** | 0.515 |
| CWE-787 (Out-of-bounds Write) | 0.980 | 0.55 | 0.716 |
| CVSS 0.0–3.9 | 0.942 | 0.43 | 0.005 |
| CVSS 9.0–10.0 | 0.956 | **0.52** | 0.797 |
| Age 0–30 days | 0.871 | 0.30 | 0.030 |
| Age >2 years | 0.958 | 0.51 | 0.875 |

**Interpretation:** A single EPSS threshold misses the fact that some CWE classes (Path Traversal, Command Injection) signal exploitation intent at much lower EPSS scores than others. A stratified approach — CWE-specific thresholds with CVSS-band override — would beat the monolithic threshold and likely match XGBoost.

**Verdict: EPSS-only is NOT sufficient for production** (F1=0.42 is too low for a triage classifier), but **a CWE-stratified EPSS threshold is a viable lightweight fallback** while the full XGBoost pipeline is being fixed.

---

## Q5 — Pipeline Alignment

**Question:** How much has the pipeline drifted between `build_training_corpus.py` and `train_xgboost.py`?

**14 configuration drifts identified.** Five are critical:

| # | Drift | Severity | Impact |
|---|---|---|---|
| 1 | `published` date **not stored** in `nvd_corpus.json` | 🔴 Critical | Chronological splits impossible; OBS_WINDOW filter uses synthetic dates off by days |
| 2 | `_cvss_cia` default: TXB=0, BTC=2 | 🔴 Critical | Same CVE gets CVSS feature values 0 vs 2 if CIA metric missing |
| 3 | `lateral_reachability` type: TXB=binary(0/1), BTC=count(1–30) | 🔴 Critical | Model learns ordinal, inference passes binary |
| 4 | No `random.seed()` in BTC | 🔴 Critical | Non-reproducible builds; every corpus build different |
| 5 | `threat_intel_pulses`: BTC hardcodes 0.0, TXB uses Poisson(λ) | 🟡 High | BTC gives zero-variance feature |

**Other notable drifts:** `vendor_popularity_index` hardcoded 0.0 in TXB (real lookup in BTC); `patch_applied` probability model differs; `DATE_END` = 2024-12-31 (TXB) vs 2025-12-31 (fetch_nvd); `OBS_WINDOW_DAYS` = 30 (BTC) vs ~190 dynamic (TXB).

**Cumulative estimated AUC impact:** −0.07 to −0.15 due to these drifts.

**Migration cost estimate:** ~13 hours for full fix. First 2 hours (critical items) recover most of the AUC loss.

---

## Verification Results

Cross-checks by independent verifier found two corrections to the raw research:

1. **NVD Reference Count ≥21 lift is 8.6×, not 12.0×** — baseline KEV rate is 0.60%, 21+ bin is 5.15% = 8.6×. Still the strongest zero-cost signal.

2. **Q1's 856 positives has 21 unexplained gap** — kev_cache shows 835 KEV entries in NVD corpus with `dateAdded ≤ 2024-12-31`, not 856. The Q1 analysis likely had a string comparison quirk (`"" <= "2024-12-31"` evaluates True in Python for empty date strings).

All 5 code-level claims verified PASS (published_date missing, CIA default mismatch, lateral_reachability type mismatch, no seed, threat_intel_pulses=0.0).

---

> **NOTE:** Some recommendations below (CWE-stratified thresholds, random seed fix) were implemented in Sprint NEXT. This roadmap section was written before Sprint NEXT and may not reflect current completion status. See ROADMAP.md §Sprint NEXT for authoritative status.

## Consolidated Implementation Roadmap

### Sprint NEXT+2 (immediate — <2 hours code)

| Item | Effort | Expected gain |
|---|---|---|
| Add NVD Reference Count ≥21 as Tier 0 rule | 30m | Catch 5.15% KEV rate CVEs at day 0 |
| Fix CIA default in `train_xgboost.py` (0→2) | 5m | Eliminate training/inference feature drift |
| Add `random.seed(42)` to `build_training_corpus.py` | 5m | Reproducible corpus builds |
| Fix `threat_intel_pulses` from 0.0 to sampler | 15m | Restore feature variance |
| Implement CWE-stratified EPSS threshold fallback | 30m | Lightweight guard while pipeline is fixed |

### Sprint NEXT+3 (1–3 days)

| Item | Effort | Expected gain |
|---|---|---|
| Targeted KEV fetch: add `--kev-ids` flag | 2h | +516 positive labels (62% increase) |
| Persist `published` date in `nvd_corpus.json` | 30m | Enable proper chronological splits |
| Fix `lateral_reachability` type (unify binary) | 30m | Eliminate worst type mismatch |
| Create `shared_config.py` | 3h | Single source of truth for all constants |
| Multi-window labels (30/90/365d observation) | 6h | Three time-based binary targets |

### Sprint NEXT+4 (architectural — 3–5 days)

| Item | Effort |
|---|---|
| Pipeline orchestrator: deprecate TXB phase_gather | 2d |
| Feature-parity CI guard test | 1d |
| Composite score label investigation | 2d |

---

## Data Appendix

| Metric | Value |
|---|---|
| NVD corpus entries | 186,102 |
| EPSS cache entries | 140,487 (subset) |
| KEV total | 1,631 |
| KEV in NVD corpus | 1,115 (68.4%) |
| KEV missing from NVD corpus | 516 (31.6%) |
| Usable KEV positives (point-in-time, ≤2024-12-31, in corpus) | 835 |
| Exploit-DB CVEs mapped | 25,037 |
| Exploit-DB verified | 20,097 |
| Vendor popularity entries | 17,100 |
| Pipeline config drifts identified | 14 |
| Critical drifts | 5 |
