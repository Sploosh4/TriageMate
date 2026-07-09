# TriageMate — Sprint NEXT+2 Research Findings

> **Status: OUTDATED** — Research from 3 July 2026. Several findings (threat_intel_pulses variance, missing random seed, CWE-stratified EPSS thresholds, KEV backfill, ExploitDB data load) have been resolved in Sprint NEXT. All 5 critical pipeline drifts now resolved — CIA default mismatch ✅, lateral_reachability type ✅. Historical analysis preserved for context.

**Prepared for:** Commander  
**Date:** 2026-07-03  
**Method:** 5-agent swarm (prompt design → research → synthesis → verification)

---

## Executive Summary

Five parallel research streams analysed TriageMate's exploitation prediction pipeline. Three cross-cutting themes emerged:

1. **The training corpus was the binding constraint.** ~~516 of 1,631 KEV entries~~ → **FIXED (Sprint NEXT):** All 1,631 KEV entries now in corpus via `--kev-ids` backfill (1,617 positive labels). ~~14 configuration drifts~~ → 5 critical drifts identified, 3 fixed. Two remain (CIA default mismatch, lateral_reachability type).

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

**Key finding:** ExploitDB PoC and Metasploit fields ~~are always False~~ → **FIXED (Sprint NEXT):** `build_training_corpus.py` now loads `files_exploits.csv` correctly. Training data has 5,232 EDB positives (2.06%) and 403 Metasploit positives (0.16%). **Note:** `nvd_corpus.json` still hardcodes these as False (pipeline gap in `fetch_nvd_corpus.py` lines 175-176); the fix is in the training corpus builder only.

---

## Q3 — Missing KEV Analysis

> **✅ FIXED (Sprint NEXT):** `--kev-ids` backfill flag + extended date range (1999–2026) + CVSS v3.0 fallback now capture all 1,631 KEV entries. Current training data has 1,617 positive labels (only 14 filtered by 30-day observation window). Original analysis preserved below.

**Question (historical):** Why were 516 of 1,631 KEV entries missing from the training set? ~~FIXED.~~

| Bucket | Count | Root Cause |
|---|---|---|
| Pre-2019 | **433** (83.9%) | `fetch_nvd_corpus.py` default start date is 2019-01-01 |
| Post-2025 | **80** (15.5%) | Default end date is 2025-12-31 (all are CVE-2026-*) |
| Within range but CVSS v3.1 missing | **3** (0.6%) | `_extract_cve_entry()` requires CVSS v3.1 metrics; these 3 CVEs only have v2.0 or v3.0 |

**Year distribution of missing CVEs:** 2002(1), 2004(2), 2005(1), 2006(2), 2007(3), 2008(5), 2009(15), 2010(23), 2011(9), 2012(22), 2013(38), 2014(34), 2015(44), 2016(59), 2017(86), 2018(89), 2023(1), 2025(2), 2026(80).

**Impact (historical):** ~~The pipeline had only 835 usable KEV positives~~ → **FIXED: 1,617 positives now.** That ~~is~~ was 51.2% label loss. Original data preserved for context.

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

> **⚠️ PARTIALLY RESOLVED (Sprint NEXT):** 3 of 5 critical drifts fixed (published date, random.seed, threat_intel_pulses). 2 remain: `_cvss_cia` default mismatch and `lateral_reachability` type mismatch. AUC impact estimate (-0.07 to -0.15) was speculative and partially mitigated. Original analysis preserved below.

**Question:** How much has the pipeline drifted between `build_training_corpus.py` and `train_xgboost.py`?

**14 configuration drifts identified.** Five are critical:

| # | Drift | Severity | Impact |
|---|---|---|---|---|
| ~~1~~ | ~~`published` date not stored~~ → **FIXED** | ✅ Resolved | TXB pipeline stores date; scripts pipeline still affected |
| 2 | `_cvss_cia` default mismatch (training=0, inference=2) | 🔴 Critical | Same CVE gets different CVSS feature values |
| 3 | `lateral_reachability` type mismatch (training=binary, inference=count) | 🔴 Critical | Model learns binary, inference passes count |
| ~~4~~ | ~~No `random.seed()`~~ → **FIXED** | ✅ Resolved | Both pipelines now seed |
| ~~5~~ | ~~`threat_intel_pulses` hardcoded 0.0~~ → **FIXED** | ✅ Resolved | Both pipelines now use Poisson sampler |

**Other notable drifts:** `vendor_popularity_index` hardcoded 0.0 in TXB (real lookup in BTC); `patch_applied` probability model differs; `DATE_END` = 2024-12-31 (TXB) vs 2025-12-31 (fetch_nvd); `OBS_WINDOW_DAYS` = 30 (BTC) vs ~190 dynamic (TXB).

**Cumulative estimated AUC impact (historical):** −0.07 to −0.15 due to these drifts. ~~Estimate was speculative (no empirical methodology). Impact partially mitigated by fixing 3 of 5 critical items.~~

**Migration cost estimate (historical):** ~13 hours for full fix. ~~First 2 hours (critical items) recovered most AUC loss — 3 of 5 items fixed.~~ Remaining 2 drifts (CIA default + lateral_reachability) still need resolution.

---

## Verification Results

Cross-checks by independent verifier found two corrections to the raw research:

1. **NVD Reference Count ≥21 lift is 8.6×, not 12.0×** — baseline KEV rate is 0.60%, 21+ bin is 5.15% = 8.6×. Still the strongest zero-cost signal.

2. **KEV count corrected (856 → 835):** kev_cache shows 835 KEV entries in NVD corpus with `dateAdded ≤ 2024-12-31`, not 856. The 856 figure was an earlier calculation error caused by a string comparison quirk (`"" <= "2024-12-31"` evaluates True in Python for empty date strings). The correct count is 835.

All 5 code-level claims were verified PASS at the time of research (published_date missing, CIA default mismatch, lateral_reachability type mismatch, no seed, threat_intel_pulses=0.0). ~~3 of 5 now fixed.~~

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
| NVD corpus entries | 260,636 (2026-07) / 186,102 (2025-07 research date) |
| EPSS cache entries | 344,852 total (140,487 overlap with NVD corpus) |
| KEV total | 1,631 |
| KEV in NVD corpus | ~~1,115~~ → **1,631 (100%)** fixed via --kev-ids |
| KEV missing from NVD corpus | ~~516~~ → **0** |
| Usable KEV positives (current training data) | ~~835~~ → **1,617** (14 filtered by OBS_WINDOW) |
| Exploit-DB CVEs mapped | 25,037 |
| Exploit-DB verified | 20,097 |
| ExploitDB positives in training data | ~~0~~ → **5,232 (2.06%)** |
| Metasploit positives in training data | ~~0~~ → **403 (0.16%)** |
| Vendor popularity entries | 17,100 |
| Pipeline config drifts identified | 14 (5 critical: 3 fixed, 2 remain) |

---

## Post-Research Fixes Applied (2026-07-08)

The following items documented above have been resolved since the original research date:

| Fix | Sprint | Impact |
|---|---|---|
| `--kev-ids` backfill flag + extended date range (1999–2026) | Sprint NEXT | All 1,631 KEV → 1,617 usable positives (only 14 lost to OBS_WINDOW) |
| `random.seed(42)` added to both pipelines | Sprint NEXT | Reproducible corpus builds |
| `threat_intel_pulses` changed from hardcoded 0.0 to Poisson sampler | Sprint NEXT | Restored feature variance |
| `published` date stored in TXB corpus (scripts still affected) | Sprint NEXT | Proper chronological splits in TXB pipeline |
| ExploitDB CSV loaded into `build_training_corpus.py` | Sprint NEXT | 5,232 EDB + 403 Metasploit positives in training data |
| CVSS v3.0 fallback in NVD fetch | Sprint NEXT | CVEs lacking v3.1 but having v3.0 now included |

**Remaining:**
| Item | Status |
|---|---|
| `_cvss_cia` default mismatch (training=0, inference=2) | ✅ FIXED — parity check script aligned with production inference (both use `_cvss_cia(cvss_vec.get("C", "N"))` = 0) |
| `lateral_reachability` type mismatch (training=binary, inference=count) | ✅ FIXED — inference binarized via `min(1, _synthetic_lateral(asset_ctx))` |

**Bugs discovered during 2026-07-08 verification audit:**
| Bug | File | Status |
|---|---|---|
| Metasploit detection: training checks `author` field, inference checks `platform=="metasploit"` — find different matches | `build_training_corpus.py` vs `integrations/metasploit.py` | ✅ FIXED — both sides now check `author` field |
| Wrong column name: `exploitdb.py` reads `row.get("date", "")` but CSV column is `date_published` | `integrations/exploitdb.py` | ✅ FIXED — now reads `date_published` |
