# EPSS Substitution Model Retrain Assessment

**Date:** 2026-07-08
**Requested by:** Commander (Roadmap Item 17)
**Sources consulted:** Code audit of all EPSS-related files (epss_substitutor.py, train_epss_v3.py, train_epss_v2.py, train_epss_substitutor.py, fetch_epss_data.py, epss_eval.py, tenable.py, advisories.py, seed_data.py, greynoise.py, otx.py)

---

## 1. Current State Inventory

| Component | File | Size | Role |
|---|---|---|---|
| **Hybrid ML + Rule Engine** | `backend/ml/epss_substitutor.py` | 674 lines / 22 KB | Main entry point. Fallback chain: v3 → v2 → v1 → rule engine. |
| **v3 Model (primary)** | `backend/ml/epss_model_v3.pkl` | 1,074,625 bytes (~1 MB) | 37-feature XGBoost; trained on real FIRST.org EPSS baselines (344K CVE records). |
| **v2 Model (fallback)** | `backend/ml/epss_model_v2.pkl` | 1,350,607 bytes (~1.3 MB) | 37-feature XGBoost; trained on fully synthetic data. |
| **v1 Model (last resort)** | `backend/ml/epss_model.pkl` | 535,063 bytes (~523 KB) | 22-feature XGBoost; trained on fully synthetic data. |
| **v3 Training Pipeline** | `backend/ml/train_epss_v3.py` | 393 lines / 12.5 KB | Generates 2,000 synthetic training samples grounded in real EPSS scores but with synthetic sector/CWE/KEV context. |
| **v2 Training Pipeline** | `backend/ml/train_epss_v2.py` | 543 lines / 18 KB | 1,000 fully synthetic samples; target computed by same rule engine it replaces. |
| **v1 Training Pipeline** | `backend/ml/train_epss_substitutor.py` | 337 lines / 9.9 KB | ~500 fully synthetic samples; target = rule engine output. |
| **EPSS Data Fetcher** | `backend/ml/fetch_epss_data.py` | 109 lines / 3.6 KB | Downloads real EPSS scores from `epss.cyentia.com/epss_scores-current.csv.gz` (~344K CVEs). |
| **EPSS Cache** | `backend/data/epss_cache.json` | 20,460,194 bytes (~19.5 MB) | Cached FIRST.org EPSS scores for ~344K CVEs. Fresh (auto-refreshes every 7 days). |
| **EPSS Evaluation** | `backend/analysis/epss_eval.py` | 359 lines / 13 KB | Baseline analysis: EPSS vs KEV prediction, threshold tuning with 5-fold CV. |
| **Commands** | `justfile` (lines 106–129) | — | `just train-epss`, `just fetch-epss-data`, `just audit-epss` |
| **Integration: Tenable (WASOC)** | `backend/integrations/tenable.py` | 181 lines / 6 KB | WASOC Tenable.io/SC export → IngestRequest mapper. Feeds hostname, CVSS, exploit maturity, etc. into pipeline. |
| **Integration: Advisories (WASOC)** | `backend/integrations/advisories.py` | 58 lines / 2.2 KB | Static WASOC advisory stubs with sector-specific threat intel (health, education, communities targeting). |
| **Integration: GreyNoise (deprecated)** | `backend/integrations/greynoise.py` | 112 lines / 3.8 KB | Deprecated — free tier too restrictive. Could theoretically provide sector-level internet scan data. |
| **Integration: OTX** | `backend/integrations/otx.py` | 115 lines / 3.8 KB | AlienVault OTX pulse queries. Returns pulse count, targeted countries. No sector filtering. |
| **Integration: NVD** | `backend/integrations/nvd.py` | — | CVE metadata corpus (CVSS, CWE, descriptions). Used for feature extraction. |
| **Integration: ExploitDB** | `backend/integrations/exploitdb.py` | — | Public PoC/maturity data. Used for exploit_maturity feature. |
| **Seed Data** | `backend/seed_data.py` | 1,348 lines / 54 KB | Demo scenarios referencing WASOC threat intel feed with sector-specific exploitation narratives. |

---

## 2. How Substitution Works Today

### Fallback Chain (load-time, module-level)

```
epss_substitutor.py on import:
  ┌─ Try epss_model_v3.pkl ──→ Loaded? → Use v3 (37 features, real EPSS)
  │
  ├─ Try epss_model_v2.pkl ───→ Loaded? → Use v2 (37 features, synthetic)
  │
  ├─ Try epss_model.pkl ──────→ Loaded? → Use v1 (22 features, synthetic)
  │
  └─ No model → Rule engine only
```

The module-level `_model` variable is set during import based on which `.pkl` files exist. The v3 model is currently on disk and actively used.

### Inference Flow (`calculate_substitution()`)

```
1. Raw EPSS is None? → Defer to rule engine for floor generation
   (0.3 for KEV CVEs, 0.05 conservative default)

2. ML model loaded AND confident (confidence ≥ 0.3)?
   → Build feature vector (37 elements for v2/v3, 22 for v1)
   → XGBoost.predict() → clamped [0, 1]
   → Compute confidence from R² + risk signal count + adjustment ratio
   → If confidence < 0.3 → fall through to rule engine

3. Fallback: Rule engine
   → Apply KEV multiplier (2x)
   → Apply CVE-specific sector adjustment (max with KEV multiplier)
     (e.g., CVE-2023-36884: health=8x, communities=10x, police=6x)
   → Apply CWE multiplier (CWE-78/CWE-434/CWE-862 = 1.5x)
   → Clamp to 0.99
   → Only substitute if change ≥ 0.1 (MIN_CHANGE_THRESHOLD)
```

### How It Feeds Into Scoring

The `calculate_substitution()` result flows into `IngestRequest` → pipeline scoring tier. The `substituted_epss` value replaces `raw_epss` in the priority score calculation (`epss_contribution` dimension). The operator sees both original and substituted values plus the reason string. This is confirmed in `seed_data.py` line 765–768 where a demo finding shows substitution from 0.065 → 0.72 flagged as "sector-specific targeting data from the WASOC threat intelligence feed."

---

## 3. The Synthetic Data Problem

### How v3 Generates Training Data

The `generate_training_data()` function in `train_epss_v3.py` (lines 130–227):

```python
for _ in range(2000):
    cve = random.choice(all_cve_ids)           # Pick random real CVE
    real_epss = epss_cache[cve]["epss"]        # Use its real EPSS score
    agency = random.choice(AGENCIES)            # Synthetic agency
    cwe = random.choice(CWES)                  # Synthetic CWE
    cisa_kev = random() < 0.10                 # 10% KEV probability
    # ...
    target = real_epss                          # Start from real EPSS
    if cisa_kev: target *= 2.0                  # Hardcoded: KEV = 2x
    if maturity >= 2: target *= (1 + m*0.15)    # Hardcoded: maturity scaling
    if no_patch: target *= 1.3                  # Hardcoded: patch penalty
    if health/police/justice: target *= 1.1     # Hardcoded: sector premium
    target += gaussian_noise(0, 0.02)           # Realism noise
```

### Why This Is Circular

The three generations of training data show a clear progression, but all share a fundamental limitation:

| Model | Baseline | Sector Weights | Target Computation |
|---|---|---|---|
| **v1** | Synthetic EPSS (Beta dist.) | Identical to rule engine | Direct rule engine output |
| **v2** | Synthetic EPSS (Beta dist.) | Rule engine + noise | Rule engine × maturity × patch × POC + noise |
| **v3** | **Real** EPSS from FIRST.org | Hardcoded multipliers | Real EPSS × synthetic modifier + noise |

**v3 is the best of the three** — it grounds the training in real EPSS scores, which is a genuine improvement. But the sector/KEV/maturity/patch multipliers are:

- **Hardcoded assumptions**, not learned from data
- **Unvalidated** against any real-world sector exploitation observations
- **Independent** (no interaction terms between agency, CWE, and CVE context)
- **Uniform across all CVEs** within a sector/KEV category (no differentiation between, e.g., a health sector CVE that's being actively mass-exploited vs. one that's only theoretically relevant)

**Consequence**: The XGBoost model learns to approximate the function:

```
target = real_epss × f(kev, maturity, patch, agency, cwe, noise)
```

where `f` is a set of smooth approximations to the hardcoded if-statements in the data generator. The model will **interpolate** well (given inputs similar to training, it produces the right multiplier), but it will **not generalize** to real sector exploitation dynamics because those dynamics were never in the training data.

This is visible in the feature importances: `raw_epss` dominates because it's the strongest signal (the target is always a multiple of it). The sector/CWE features contribute only modest adjustments because the synthetic multipliers are relatively small (1.1x–2x) compared to the variance in raw_epss.

### What a Non-Circular Approach Would Look Like

Real training data would pair each (CVE, sector) combination with an observed exploitation rate:

```
For each CVE that was observed affecting sector S:
  real_epss = FIRST.org global exploitation probability for this CVE
  sector_epss = observed exploitation rate specific to sector S
  target = sector_epss - real_epss (the "sector delta")
```

The model would then learn: "given a CVE with these properties (CWE, CVSS, KEV status, etc.) and a sector with these characteristics, what is the expected sector-specific exploitation delta?" — rather than "apply a fixed multiplier because someone said health is important."

---

## 4. Sector-Weighted Data Analysis

### What "Real Sector Data" Means

Real sector-weighted exploitation data would be structured as incident-level records:

```json
{
  "cve_id": "CVE-2023-34362",
  "sector": "health",
  "agency": "health.wa.gov.au",
  "date_observed": "2023-06-01",
  "incident_type": "ransomware",
  "exploitation_prob_sector": 0.87,
  "cisa_kev": true,
  "cwe": "CWE-89",
  "cvss_score": 9.8,
  "affected_assets": 3,
  "data_breach": true
}
```

Key features this would enable:
- **Real sector-conditional EPSS**: "Given a CVE is observed in sector X, what's its exploitation probability?" vs. global EPSS.
- **Sector × CWE interaction**: E.g., CWE-434 (file upload) may be more dangerous for sharedservices (file-sharing platforms) than for police.
- **Sector × KEV interaction**: Some KEV CVEs target all sectors uniformly; others specifically target government/health (e.g., CVE-2023-34362 targeting MOVEit in health).
- **Temporal sector patterns**: Sector targeting evolves over time (e.g., education targeted during academic terms).
- **Sector baseline rates**: Some sectors (health) are targeted more frequently overall, so even a medium-severity CVE in health may warrant a higher multiplier.

### WASOC References in the Codebase

| File | WASOC Reference | Relevance |
|---|---|---|
| `integrations/tenable.py` | Tenable export format from "WASOC's Tenable.sc or Tenable.io" | WASOC provides the vulnerability scanning pipeline that feeds into TriageMate. The hostnames extracted here drive agency/sector assignment. |
| `integrations/advisories.py` | Static WASOC advisories with sector targeting intelligence | Contains confirmed sector-specific exploitation intelligence (e.g., "Education sector organisations have been disproportionately targeted" for CVE-2023-27350/PaperCut). These are hardcoded examples of the kind of data needed at scale. |
| `seed_data.py` (line 768) | "sector-specific targeting data from the WASOC threat intelligence feed" | Demo narrative explicitly mentions WASOC as the source for EPSS substitution decisions. |
| `seed_data.py` (lines 64, 186, 785, 972) | WASOC threat intel feed references in scenario narratives | Multiple demo findings reference WASOC as a source for confirmed sector targeting. |

### Potential Data Sources

| Source | Sector Data Available? | Access Barrier |
|---|---|---|
| **WASOC incident logs** | ✅ Yes — this is the primary source. Sector/agency attribution per CVE. | Data sharing agreement with WA SOC. |
| **Tenable.io (via WASOC)** | ✅ Partial — asset hostnames reveal agency/sector via FQDN. Scan frequency could approximate sector exploitation rates. | Already integrated (tenable.py). Just need to aggregate scan findings per sector. |
| **OTX (AlienVault)** | ❌ No sector filtering — OTX pulses have `targeted_countries` but no sector targeting metadata. | Low-value without further enrichment. |
| **GreyNoise** (deprecated) | ⚠️ Theoretical — GN tags scanners by actor/industry. Currently deprecated (free tier too restrictive). | Unlikely to be re-enabled without a paid tier. |
| **CISA KEV** | ❌ No sector data — KEV is a simple binary list. | Already used (KEV_MULTIPLIER). No additional sector signal. |
| **ExploitDB** | ❌ No sector data — public PoC metadata only. | Already used for exploit_maturity/has_public_poc features. |
| **CMDB** | ✅ Indirect — hostname → agency mapping, asset criticality per sector. | Already used for agency extraction. Could enrich with asset counts per sector. |
| **MITRE ATT&CK** | ⚠️ Some — techniques mapped to sectors via observed campaigns. | Used in mitre_mapping.py but not for sector EPSS weighting. |

---

## 5. Two Paths Forward

### Path A: Quick Synthetic Improvement (1–2 days)

**Goal:** Improve v3's synthetic data generator to produce more realistic training distributions without any new external data.

**What would change:**

1. **Agency sampling with WA-government-realistic weights** (not uniform):
   - Health: 25% (most targeted WA sector per advisory patterns)
   - Sharedservices: 20% (cross-agency attack surface)
   - Education: 15% (PaperCut, other edu-specific CVEs)
   - Police: 10% (sensitive, smaller footprint)
   - Transport: 8%
   - Communities: 8%
   - Finance: 5%
   - Water Corp / DPIRD / Justice: 3% each
   - Unknown: 3%

2. **CWE frequency matching to NVD corpus** (not uniform):
   - Query nvd_corpus.json for actual CWE distribution in real CVEs
   - Top CWEs (*CWE-79 XSS*, *CWE-89 SQLi*, *CWE-787 OOB Write*) should appear proportionally
   - Rare CWEs should appear less frequently

3. **Realistic sector × CWE interactions** (not independent):
   - CWE-434 (file upload) → higher multiplier for sharedservices (file-sharing platforms)
   - CWE-89 (SQL injection) → higher multiplier for health (patient databases)
   - CWE-78 (OS command injection) → higher multiplier for all sectors (perimeter devices)
   - Model these as interaction terms in the data generator, not independent multipliers

4. **Calibrated KEV + sector co-occurrence**:
   - Not all KEV CVEs affect all sectors equally
   - Some KEV CVEs are sector-agnostic (e.g., Log4j), others sector-specific (e.g., MOVEit → health)
   - Encode a sector-KEV correlation matrix based on advisory patterns

5. **Non-linear sector multiplier targets**:
   - Replace flat 1.1x with a distribution (e.g., log-normal around 1.15 for health)
   - Rare high-multiplier outliers (3x–8x) for known sector-specific campaigns
   - This prevents the model from learning a single "health = 1.1x" rule

6. **Feature interaction diversity** (5–10% of samples):
   - Agency + maturity + no-patch combinations
   - CWE + agency + KEV combinations
   - Helps XGBoost learn interaction terms rather than additive linear effects

**Effort breakdown:**

| Task | Hours |
|---|---|
| Update agency weights and CWE frequencies | 2 |
| Implement sector × CWE interaction logic | 4 |
| Add KEV-sector correlation matrix | 2 |
| Replace flat multipliers with distributions | 3 |
| Retrain, evaluate, smoke-test | 2 |
| Validate against seed_data.py scenarios | 1 |
| **Total** | **~14 hours (2 days)** |

**Risk:** Still synthetic — model learns the new, improved assumptions. Better than v3 but still not grounded in real incident data.

---

### Path B: Real Data Integration (1–2 weeks + data access)

**Goal:** Replace the synthetic data generator with real sector-weighted exploitation observations.

**Prerequisite:** Data sharing agreement with WASOC (or equivalent access to sector-level incident data).

**What's needed:**

1. **Data schema agreement** (2–3 days):
   - Define the minimum viable dataset:
     ```
     cve_id | sector | agency | date_observed | incident_type |
     num_affected_assets | cisa_kev | cvss | cwe
     ```
   - Confirm data sensitivity classification (likely OFFICIAL Sensitive)
   - Establish transfer mechanism (e.g., weekly CSV export from WASOC SIEM)

2. **WASOC incident log integration** (3–5 days):
   - New module: `backend/integrations/wasoc_incidents.py`
   - Parse WASOC incident logs into training records
   - Handle deduplication, missing CVEs, sector aliasing
   - Cache locally for training use (similar to epss_cache.json pattern)
   - See `backend/integrations/advisories.py` (58 lines) as a reference stub — this would be a significant expansion

3. **Aggregate Tenable scan data by sector** (2–3 days):
   - Already have tenable.py for per-finding ingestion
   - Add an aggregation function: group findings by (CVE, sector) → compute sector-specific exploitation rate
   - This yields training targets from existing pipeline data without new sources
   - Requires running batch queries against accumulated findings

4. **Training pipeline upgrade** (2–3 days):
   - `train_epss_v4.py`: Load real incident data instead of synthetic data
   - Train target = sector_exploitation_rate (from incident logs or Tenable aggregates)
   - Evaluate on held-out incidents
   - Compare against v3 performance

5. **Model deployment and fallback** (1 day):
   - Export as `epss_model_v4.pkl`
   - Update `epss_substitutor.py` fallback chain to prefer v4
   - Verify no regression in seed data scenarios

**Effort breakdown:**

| Task | Hours |
|---|---|
| Data schema agreement with WASOC | 8–16 (depends on proc) |
| WASOC incident log integration | 24–40 |
| Tenable scan aggregation | 16–24 |
| Training pipeline (v4) | 16–24 |
| Model deployment + testing | 8 |
| **Total** | **72–112 hours (1–2 weeks)** |
| **Plus:** Data access procurement | **Unknown (outside engineering)** |

**Risk:** Requires external dependency (WASOC data access). If access is denied, the entire path blocks.

**Intermediate option:** Build the Tenable aggregation path (item 3) independently — it uses only data already flowing through TriageMate. Even without a formal WASOC agreement, the distribution of findings per (CVE, sector) from existing scans provides a pseudo-ground-truth signal that's better than synthetic assumptions.

---

## 6. Recommendation

**Recommended: Path B — Real Data Integration, with Tenable aggregation as the immediate first step.**

### Rationale

1. **Path A (synthetic improvement) is diminishing returns.** The v3 pipeline already grounds training in real EPSS scores. Improving the synthetic sector distributions makes the model more realistic, but the fundamental problem remains: we're replacing one set of assumptions with another. The model will still be circular — it learns whatever assumptions the data generator encodes. Path A is a fast iteration, but it doesn't fundamentally advance the state.

2. **The Tenable aggregation path is low-hanging fruit.** TriageMate already ingests Tenable.io findings via `tenable.py`. Every finding has a hostname (→ agency/sector) and a CVE ID. Aggregating existing scan findings by (CVE, sector) immediately yields a distribution of "which CVEs are actually appearing on which agency assets." This is not perfect ground truth (vulnerability presence ≠ exploitation), but it's a real-world signal that's vastly better than uniform random sampling.

3. **WASOC advisory content confirms sector targeting is available.** The `advisories.py` file contains 7 static advisories with confirmed sector-specific exploitation intelligence. Standing up a real WASOC incident feed would make this data fresh and comprehensive.

### Phased Approach

| Phase | What | Time | Data Needed |
|---|---|---|---|
| **Phase 1** | Tenable scan aggregation: collect (CVE, sector) frequency from existing findings | 2–3 days | None (already flowing) |
| **Phase 2** | Train v4 model using Tenable aggregate as target; compare vs v3 | 2–3 days | Phase 1 output |
| **Phase 3** | Negotiate WASOC data sharing for verified incident data | 1–4 weeks (parallel) | WASOC agreement |
| **Phase 4** | Integrate WASOC incident feed → v5 training | 1 week | Phase 3 output |

### What to Do Right Now

1. **Start Phase 1 immediately.** Write a script that queries the existing TriageMate database (or Tenable cache) for all historical findings, groups by (CVE, sector), and outputs a sector-exploitation-frequency table. This is code-only, no external dependencies, and produces usable training data.

2. **Flag Phase 3 to the commander** for engagement with WASOC. The advisory stubs in `advisories.py` (58 lines) hint at the kind of data available — a formal feed would unlock the model's full potential.

3. **Hold Path A as a backup** — if WASOC access is denied or delayed beyond 4 weeks, revisit the synthetic improvements as a stopgap.

---

**Report written to backend/reports/intel/epss-retrain-assessment.md. Key finding: The v3 model grounds training in real EPSS scores but still uses synthetic sector multipliers — the model learns hardcoded assumptions, not real patterns. The fastest path to breaking this circular dependency is aggregating existing Tenable scan findings by (CVE, sector) to produce a real distributional signal, achievable in 2–3 days without any new data access.**
