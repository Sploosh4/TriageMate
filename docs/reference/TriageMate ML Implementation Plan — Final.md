# TriageMate ML Implementation Plan — Final

> **⚠️ OUTDATED:** This document describes the original ML implementation plan from early sprints. The pipeline has since changed significantly: PCA was removed (v2.5), SecureBERT2.0 CWE classifier was deprecated, the feature vector is now 35 tabular + 384 SBERT, and scoring uses 6 dimensions (not 5). See ROADMAP.md for current state. This document is preserved for historical reference only.

## Document Provenance

This document merges two input sources and applies four corrections and four gap-fills from a handoff prompt. The sources are:

- **Source A:** `TriageMate ML Research.md` — detailed ML architecture research covering Components 1–4 (XGBoost, SLM, Pre-Tier, EPSS substitution).
- **Source B:** `Additional Information.md` — pipeline-level operational description covering CMDB ingestion, Tier 0 re-check logic, Tier 3 human review, and background statistical audit.

Where the two sources diverged, the better option was selected with justification. All divergences are catalogued in **Appendix A**.

---

## Section 1: Architecture Overview

TriageMate is a vulnerability prioritization platform for Western Australian government agencies. The full pipeline, incorporating best elements from both source documents, is:

```
[Ingest → Schema Validation] → [Pre-Tier: CMDB + AD Telemetry + Classifier]
  → [Tier 0: Deterministic] → [Tier 1: XGBoost ML] → [Tier 2: Cloud LLM]
  → [Tier 3: Human Review]

Background: [Statistical Audit — 5-10% sample of auto-resolved cases]
```

### Tier Resolution Summary

| Tier | What It Does | Resolves | Escalates |
|------|-------------|----------|-----------|
| Tier 0 | Deterministic rules | Very Critical (KEV + CVSS ≥ 9.0 + internet-facing, or KEV + EPSS ≥ 0.90 + Cat 3/4) and Low (non-KEV + CVSS < 4.0 + EPSS < 0.10) | Everything else → Tier 1 |
| Tier 1 | XGBoost with 37 features + PCA text | High-confidence predictions (ensemble std ≤ 0.15) | Uncertain predictions (ensemble std > 0.15) → Tier 2 |
| Tier 2 | Cloud LLM force-reflection + RAG | Text-conflict resolutions with high LLM confidence | Low LLM confidence → Tier 3 |
| Tier 3 | Human analyst review | Final determination | None — terminal stage |

### Complete Pipeline Data Flow

```
1. INGEST — Raw scanner export arrives:
   {vulnerability_id, hostname/IP, cvss_score, cvss_vector, raw_description,
    detected_software_versions, cisa_kev}

2. SCHEMA VALIDATION — Event-driven validation layer.
   → Malformed? Attempt CVE database recovery for CVSS + description.
   → OK? Proceed.

3. CMDB MATCHING — Match target IP to asset registry.
   → Unknown asset? Tag for manual enrichment, proceed with defaults.
   → Known asset? Pull full CMDB record (data_classification, network_zone,
     interface_type, role, patch_cycle, registered_applications).

4. TELEMETRY GATHERING — Pull from AD (OU paths, group memberships)
   and network flow logs (connection counts).

5. PRE-TIER CLASSIFIER — Multi-label RandomForest predicts:
   → Mission Prevalence: Core / Support / Peripheral
   → Public Well-Being Impact: Severe / Moderate / Minimal
   Both tags attached to payload with confidence scores.

6. THREAT INTEL ENRICHMENT — Pull current EPSS score (FIRST.org, daily)
   and CISA KEV status. Check ExploitDB, Metasploit, GreyNoise, OTX.

7. TIER 0 EVALUATION — Deterministic rules.
   → Very Critical or Low? Auto-resolve. Low cases flagged for 7-day re-check.
   → Ambiguous? → Tier 1.

8. TIER 1 EVALUATION — XGBoost model.
   → SBERT encode description → PCA compress to 32d.
   → Concatenate with 37 tabular features → predict.
   → Ensemble std ≤ 0.15? Auto-resolve.
   → Ensemble std > 0.15? → Tier 2.

9. TIER 2 EVALUATION — Cloud LLM (gpt-4o-mini).
   → Local CWE classifier (SecureBERT2.0) maps description to CWE class.
   → RAG pre-query retrieves asset configuration context from LanceDB.
   → Force-reflection prompt sent to cloud LLM.
   → LLM returns structured JSON with conflict assessment and score_adjustment.
   → High LLM confidence? Apply adjustment → final score.
   → Low LLM confidence? → Tier 3.

10. FINAL SCORING — Six weighted dimensions (0–100):
    CVSS (max 40) + EPSS (max 20) + Asset Criticality (max 20)
    + Exposure (max 15) + Patch/Remediation (max 5)
    + ML Exploitation Probability (max 10)
    + Tier 2 score_adjustment [-70, +10]
    → Band: Low (0–25), Medium (26–50), Critical (51–75), Very Critical (76–100).

11. BACKGROUND AUDIT — 5–10% of auto-resolved cases randomly sampled
    for independent review. Catches model drift without pipeline latency.
```

---

## Section 2: Corrected Research Findings

### 2.1 Feature Engineering: The 37 Tabular Features

Each feature is temporally safe — no look-ahead bias at inference time.

| # | Feature Name | Type | Encoding | Temporal Safety |
|---|-------------|------|----------|-----------------|
| 1 | cvss_av | Ordinal | Network=3, Adjacent=2, Local=1, Physical=0 | Static at disclosure |
| 2 | cvss_ac | Ordinal | Low=1, High=0 | Static at disclosure |
| 3 | cvss_pr | Ordinal | None=2, Low=1, High=0 | Static at disclosure |
| 4 | cvss_ui | Ordinal | None=1, Required=0 | Static at disclosure |
| 5 | cvss_s | Ordinal | Changed=1, Unchanged=0 | Static at disclosure |
| 6 | cvss_c | Ordinal | High=2, Low=1, None=0 | Static at disclosure |
| 7 | cvss_i | Ordinal | High=2, Low=1, None=0 | Static at disclosure |
| 8 | cvss_a | Ordinal | High=2, Low=1, None=0 | Static at disclosure |
| 9 | epss_score | Continuous | [0,1] float | Daily refresh, current at eval |
| 10 | cisa_kev_status | Binary | Listed=1 | Active catalog at eval |
| 11 | patch_available | Binary | Vendor published=1 | Historical state at eval |
| 12 | patch_applied | Binary | Applied to asset=1 | Config snapshot at eval |
| 13 | internet_facing | Binary | Public IP/DMZ route=1 | Routing state at eval |
| 14 | domain_joined | Binary | AD member=1 | Domain membership at eval |
| 15 | data_classification | Ordinal | Cat4=4, Cat3=3, Cat2=2, Cat1=1 | Asset classification at eval |
| 16 | mission_prevalence | Ordinal | Core=3, Support=2, Peripheral=1 | Pre-Tier output |
| 17 | wellbeing_impact | Ordinal | Severe=3, Moderate=2, Minimal=1 | Pre-Tier output |
| 18 | lateral_reachability | Continuous | Integer count of reachable hosts | Network adjacency at eval |
| 19 | boundary_reachability | Continuous | Integer count of cross-zone routes | Network config at eval |
| 20 | downstream_assets | Continuous | Integer count of dependent nodes | Dependency logs at eval |
| 21 | patch_lag_days | Continuous | Days since patch published | Measured dynamically |
| 22 | exploitdb_has_poc | Binary | PoC exists in ExploitDB=1 | Live index at eval |
| 23 | metasploit_has_payload | Binary | Metasploit module exists=1 | Framework state at eval |
| 24 | greynoise_active_scan | Binary | Scanning in last 30 days=1 | Telemetry pre-eval |
| 25 | otx_threat_pulses | Continuous | Integer count of OTX pulses | Real-time indicator |
| 26 | nvd_reference_count | Continuous | Count of NVD reference links | Static at disclosure |
| 27 | cve_desc_tokens | Continuous | Character length of description | Static at disclosure |
| 28 | vulnerability_age_days | Continuous | Days since publication | Calculated at eval |
| 29 | vendor_popularity_index | Continuous | Normalized vendor frequency | Historical representation |
| 30 | cvss_exploitability_sub | Continuous | CVSS v3.1 exploitability sub-score | Derivation of static metrics |
| 31 | cvss_impact_sub | Continuous | CVSS v3.1 impact sub-score | Derivation of static metrics |
| 32 | is_top_25_cwe | Binary | In MITRE Top 25 CWE=1 | CWE-ID match at eval |
| 33 | is_rce_signature | Binary | RCE keyword patterns matched=1 | Text parsing |
| 34 | is_privesc_signature | Binary | Priv esc keyword patterns=1 | Text parsing |
| 35 | is_bypass_signature | Binary | Auth bypass patterns=1 | Text parsing |
| 36 | is_dos_signature | Binary | DoS patterns=1 | Text parsing |
| 37 | is_traversal_signature | Binary | Directory traversal patterns=1 | Text parsing |

**Total after PCA:** 37 tabular + 32 PCA text = 69 features.

### 2.2 SBERT Embedding + PCA Reduction

- **Model:** `all-MiniLM-L6-v2` (384 dimensions). ~1.66× faster than `all-mpnet-base-v2` on CPU.
- **Dimensionality reduction:** PCA to 32 dimensions. Deterministic, 54× faster at inference than UMAP, preserves >85% variance.
- **Why not UMAP:** Out-of-sample projection is computationally intensive, non-linear, and unstable at CPU inference time. PCA provides comparable downstream accuracy with stability.
- **File:** `backend/ml/encoder.py`

### 2.3 Training Data Strategy

- **Positive class:** CISA KEV entries + GreyNoise "observed-in-the-wild" within 30 days of disclosure.
- **Negative class:** CVEs with zero exploitation activity across all sources during the observation window.
- **Class imbalance:** XGBoost `scale_pos_weight` parameter (~15:1 ratio). No SMOTE — synthetic oversampling distorts the PCA space.
- **Asset-level adjustment:** No public internal-exploitation dataset exists. Asset customization via the 11 environmental features (features 11–21) at runtime.

### 2.4 Model Architecture: Standard XGBoost (Not RRF Ensemble)

Source B describes an "XGBoost Reciprocal Rank Fusion (RRF) ensemble." This was evaluated and rejected for the MVP:

| Criterion | RRF Ensemble | Standard XGBoost |
|-----------|-------------|-----------------|
| Models to train | Multiple (2+) | One |
| Hyperparameter surface | N × model_params | Single set |
| Retraining effort | N models per cycle | One model per cycle |
| Accuracy gain on ~10K records | Negligible | Sufficient |
| Debug complexity | High (fusion weight tuning) | Low (single feature importance) |

**Decision: Standard XGBoost.** A single model with 800 trees, Platt calibration, and the 69-feature hybrid matrix is sufficient for the MVP dataset size. RRF is a ranking-fusion technique designed for much larger-scale retrieval tasks. The additional complexity provides no measurable benefit on 10,000–15,000 tabular records.

### 2.5 XGBoost Hyperparameters

```python
model = xgb.XGBClassifier(
    max_depth=4,
    learning_rate=0.03,
    n_estimators=800,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=15.0,       # Ratio of negative:positive samples
    tree_method="hist",           # Optimized CPU histogram
    random_state=42
)
```

### 2.6 Calibration

Platt scaling via `CalibratedClassifierCV(method='sigmoid')`. Preferred over isotonic regression for datasets under 20,000 samples.

### 2.7 Corrected: Ensemble Variance Escalation (Correction 1)

**Problem:** Original research proposed Shannon entropy threshold H(p) > 0.35 → p ∈ [0.062, 0.938]. In vulnerability exploitation, almost all CVEs have p < 0.10, so nearly nothing escalates.

**Solution: Standard deviation of individual tree predictions across the 800 XGBoost trees.**

```
tree_preds = model.predict_proba(X, pred_leaf=False)  # 800 individual tree outputs
std = np.std([tree[i, 1] for each tree])               # std of positive-class predictions

if std > 0.15 → escalate to Tier 2
else → auto-resolve
```

**Justification:** Ensemble variance quantifies model *disagreement*, not mathematical uncertainty of a single probability. When trees disagree (high std), the feature pattern contains conflicting signals — exactly the cases that need Tier 2's structured text analysis.

**Matches demo dataset:**

| Row | Case | Std Prediction | Routing | Rationale |
|-----|------|----------------|---------|-----------|
| 3 | PaperCut (score 71) | Low (< 0.15) | Auto-resolve | Strong signal: domain_joined + lateral_reachability=28 + privileged_account |
| 4 | ScreenConnect (score 55) | Low (< 0.15) | Auto-resolve | Distinct pattern: cross_boundary=14 + RMM software category |
| 5 | Office RCE (score 63) | High (> 0.15) | Escalate | Conflicting: KEV active + EPSS 0.065 anomalous + CVSS 7.8 |
| 6 | Confluence (score 41) | High (> 0.15) | Escalate | Conflicting: CVSS 10.0 + patch record ambiguity + scanner vs CMDB |
| 7 | ManageEngine (score 22) | High (> 0.15) | Escalate | Conflicting: CVSS 9.8 + KEV + not-internet-facing + Cat 2 → config-dependent |

### 2.8 SecureBERT2.0 CWE Encoder

- **Model:** `bziemba/SecureBERT2.0-final`. Domain-adapted cybersecurity transformer with 12 MTL heads (8 CVSS + 4 CWE hierarchy).
- **Fine-tuning:** NVD's ~200,000 CVE-to-CWE mappings. 80/10/10 split stratified across top 50 CWE categories.
- **Runs locally regardless of Tier 2 decoder choice.**
- **File:** `backend/ml/cwe_classifier.py`

### 2.9 Cloud LLM Provider Selection

Source B describes a local 7B–8B parameter decoder model. This was evaluated and rejected for the MVP:

| Criterion | Local 7B-8B Decoder | Cloud gpt-4o-mini |
|-----------|--------------------|--------------------|
| GPU requirement | 8–16GB VRAM (or very slow CPU) | None |
| Setup complexity | Quantization (AWQ/GPTQ/bitsandbytes), model serving, prompt template tuning | API key + HTTP call |
| JSON reliability | Regex/post-hoc parsing, frequent schema failures | FSM-enforced Structured Outputs (100% valid) |
| Cost | Free per-inference but requires dedicated hardware | ~$0.0004 per analysis |
| Latency | 2–15s on CPU, 1–3s on GPU | ~1s |
| Maintenance | Model updates, quantization drift, dependency conflicts | Provider handles updates |

**Decision: Cloud LLM.** The cloud approach is already implemented in `backend/pipeline/tier_2.py`. Adding a local 7B model introduces infrastructure complexity that contradicts the "single developer machine without GPU clusters" MVP constraint. At $0.40 per 1,000 analyses, the cloud cost is negligible.

| Provider | Model | Role | Cost/Analysis |
|----------|-------|------|---------------|
| **OpenAI** | gpt-4o-mini | **Primary** — FSM-enforced Structured Outputs | ~$0.0004 |
| **Anthropic** | claude-3-5-sonnet | Secondary fallback — Tool Use schema enforcement | ~$0.009 |
| **Together AI** | Llama 3 8B | Tertiary budget fallback — JSON mode | ~$0.0003 |

### 2.10 Corrected: Score Adjustment Range (Correction 2)

**Problem:** Pydantic model constrained `score_adjustment` to [-20, 20]. Demo requires -15, -37, -66.

**Solution:** Change to **[-70, +10]**.

```python
score_adjustment: int = Field(
    description="Score modifier in the range [-70, +10].",
    ge=-70,
    le=10
)
```

| Row | CVE | Adjustment | Justification |
|-----|-----|-----------|---------------|
| 5 | CVE-2023-36884 | -15 | Mitigation may be in place, but status unconfirmed |
| 6 | CVE-2023-22515 | -37 | Change record suggests patching was attempted; scanner disagrees |
| 7 | CVE-2022-47966 | -66 | SAML disabled → attack surface eliminated entirely |

- **Lower bound -70:** Row 7 needs -66; 4 points headroom for stronger negative findings.
- **Upper bound +10:** SLM should not unilaterally elevate beyond Tier 0/1 assessments. Its primary role is detecting false positives.

### 2.11 RAG Architecture

- **Vector store:** LanceDB (embedded, zero-copy Arrow, sub-millisecond CPU latency).
- **Embedding model:** `all-MiniLM-L6-v2` (consistent with Tier 1 encoder).
- **Chunking:** Markdown-header chunking, 512-token max, 128-token overlap.
- **Context window:** Max 2,000 tokens (~4 chunks) per prompt.
- **File:** `backend/ml/vector_store.py`

### 2.12 RAG Query: Deterministic Pre-Query (Not SLM-Triggered)

Source B describes the SLM triggering RAG queries ("The SLM triggers a Retrieval-Augmented Generation query"). This was evaluated and rejected:

| Criterion | SLM-Triggered RAG | Deterministic Pre-Query |
|-----------|-------------------|------------------------|
| Round-trips to LLM | Multiple (agentic loop) | One |
| Context guarantee | LLM may query too late or miss key docs | All relevant docs in prompt upfront |
| Cost | Higher (multiple API calls) | Lower (single call) |
| Implementation | Requires tool-use capabilities | Simple function call before prompt assembly |

**Decision: Deterministic pre-query.** `query_rag(hostname, predicted_cwe)` runs before the LLM call and injects results into the prompt. This ensures the LLM has full context in a single round-trip.

```python
def retrieve_asset_context(hostname: str, predicted_cwe: str) -> str:
    query = (f"Security configurations, mitigations, default settings, "
             f"and active hardening parameters for {hostname} "
             f"to resolve {predicted_cwe}")
    table = db.open_table("asset_documentation")
    results = table.search(query).limit(3).to_list()
    return "\n\n".join([r["text"] for r in results])
```

### 2.13 Fallback and Caching

**Fallback sequence:**
1. Exponential backoff retry (3 attempts, 2^N seconds)
2. Secondary provider (OpenAI → Anthropic → Together AI)
3. Fail secure: keep Tier 1 score, escalate to Tier 3 human review

**Prompt caching:**
- Static system prompt first (~1,250 tokens) → cached prefix.
- OpenAI 50% discount on cache hits; Anthropic 90%.
- Dynamic segment (CVE metrics + RAG context) after.

### 2.14 Temperature Note (Correction 4)

```python
# temperature=0.0 for MVP JSON schema reliability.
#
# TESTING CHECKPOINT: If counter-argument quality (Step B of the
# force-reflection loop) is found to be generic or predictable
# during evaluation, increase to 0.1–0.2.
# OpenAI Structured Outputs FSM enforcement maintains schema
# validity regardless of temperature.
temperature=0.0
```

### 2.15 Pre-Tier Classifier

- **Model:** `MultiOutputClassifier` wrapping `RandomForestClassifier`. 150 trees, max_depth=6, class_weight="balanced_subsample".
- **Labels:** Mission Prevalence (Core/Support/Peripheral) + Public Well-Being Impact (Severe/Moderate/Minimal).
- **Features:** AD OU path (target encoded), VLAN/subnet (binary), installed apps (one-hot top 50), service account privileges (ordinal), hostname agency patterns (binary), connection counts (log-scaled).
- **Bootstrapping:** Rules-based labeling from NIST SP 800-60 and Australian ISM.
- **Active learning:** Uncertainty sampling, top 20 highest-entropy unlabeled assets per iteration.
- **File:** `backend/ml/pre_tier_classifier.py`

### 2.16 EPSS Substitution Model

- **Architecture:** Sector-adjusted meta-scorer. Adjusted EPSS = raw EPSS × sector_threat_multiplier.
- **Multiplier formula:** OTX/GreyNoise sector targeting proportion + CISA KEV sector-campaign indicator.
- **Activation:** Only when raw EPSS < 0.10 AND sector_multiplier > 5.0.
- **Transparency:** Original EPSS displayed alongside substituted value with justification.
- **File:** `backend/ml/epss_substitutor.py`

---

## Section 3: Tier 0 Deterministic Rules (Gap 1)

### 3.1 Current Rules

| Rule | Condition | Resolution | SSVC Alignment |
|------|-----------|------------|----------------|
| R1 | CISA KEV + CVSS ≥ 9.0 + internet-facing | Very Critical | Exploitation=Active + Automatable=Yes + Impact=High |
| R2 | CISA KEV + EPSS ≥ 0.90 + data classification Cat 3 or 4 | Very Critical | Exploitation=Active + Technical Impact=Total + Mission=High |
| R3 | NOT KEV + CVSS < 4.0 + EPSS < 0.10 | Low | Exploitation=None + Automatable=No + Impact=Low |
| — | Everything else | Ambiguous → Tier 1 | Requires ML analysis |

### 3.2 Low-Severity 7-Day Re-Check

Source B specifies low-severity vulnerabilities should be "marked to be checked within 7 days." This is incorporated:

| Action | Timing | Mechanism |
|--------|--------|-----------|
| Initial classification | At ingestion | Tier 0 marks as Low |
| 7-day re-check | Cron job scans for Low-classified rows older than 7 days | Re-pull EPSS + KEV status. Re-run Tier 0. If status changed (e.g., newly added to KEV), re-classify |
| Analyst notification | On re-classification | Queue indicator: "Re-checked — status changed" |

**Rationale:** EPSS scores are recalculated daily. CISA KEV is updated as-needed. A vulnerability classified "low" today could have its EPSS jump or be added to KEV within a week. The 7-day window balances risk (stale low classification) against cost (re-processing overhead). No pipeline latency is introduced — the re-check runs asynchronously.

### 3.3 SSVC Literature Support

The SSVC framework [CISA, 2023; CERT/CC, 2022] defines four decision dimensions: Exploitation Status, Automatability, Technical Impact, and Mission/Well-Being Impact. Tier 0 rules align as follows:

- **R1 (internet-facing + KEV + high CVSS):** SSVC typically recommends "Act" when exploitation is active (KEV), automatable (CVSS ≥ 9.0 implies network vector + low complexity), and the asset has mission impact (implied by the check for internet-facing in a government context). The internet-facing criterion is a proxy for "the vulnerability is reachable."
- **R2 (KEV + high EPSS + high data classification):** SSVC's "Mission/Well-Being" dimension is captured by data classification (Cat 3/4 maps to "High" impact in government contexts). EPSS ≥ 0.90 is the FIRST-recommended threshold for "high confidence" exploitation probability [Jacobs et al., 2019]. This rule correctly auto-resolves as Very Critical even without internet exposure because the crown-jewel data classification implies the asset is high-value regardless of network position.
- **R3 (non-KEV + low scores):** SSVC's "Track" or "Monitor" decision — acknowledge but deprioritize.

### 3.4 ManageEngine Case Analysis (CVE-2022-47966, Row 7)

**Tier 0 inputs:** CVSS 9.8, CISA KEV=True, internet_facing=False, data_classification=Category 2.

- R1 not triggered (not internet-facing).
- R2 not triggered (Category 2, not 3 or 4).
- R3 not triggered (CVSS 9.8 > 4.0).

**Result:** Routes "ambiguous" → Tier 1 (which escalates to Tier 2 where SAML status is discovered).

This routing is correct. The ManageEngine product line spans 24 products with varying SAML dependency profiles. Tier 0 cannot know whether SAML is enabled on this specific instance. In SSVC terms, "Automatability" is uncertain — the exploit exists (KEV) but may not be reachable. The framework explicitly recommends deferring to contextual analysis in such cases.

### 3.5 Proposed Rule Evaluation

**Should "CISA KEV + EPSS ≥ 0.90 + data classification Cat 3 or 4" also require internet exposure?**

No. This is already R2 and was deliberately designed without an internet-facing check. A vulnerability confirmed as actively exploited (KEV), with near-certain exploitation probability (EPSS ≥ 0.90), on a crown-jewel asset (Cat 3/4), warrants immediate attention regardless of network position. Consider a hypothetical Row 8: Category 4 law enforcement asset, EPSS 0.92, KEV-listed, on an internal network only. The asset hosts criminal intelligence data. A compromise via an insider or pivoted attacker would be catastrophic. Auto-resolving as Very Critical is correct.

**Should additional deterministic rules be added?**

No. Three rules cover the extremes. Adding mid-range rules reduces training signal for the XGBoost model and increases maintenance burden.

### 3.6 Tier 0 Summary

| Aspect | Assessment |
|--------|-----------|
| Rules supported by SSVC | Yes — all three map to SSVC dimensions |
| ManageEngine routing correct | Yes — configuration-dependent attack surface deferred |
| Additional rules needed | No |
| Low-severity re-check | Yes — 7-day asynchronous re-evaluation |
| File path | `backend/pipeline/tier_0.py` |

---

## Section 4: Training Data Blueprint (Gap 2)

### 4.1 API Endpoints

**NVD API v2:**
| Detail | Value |
|--------|-------|
| Endpoint | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Auth | None required (API key optional for rate limit increase) |
| Rate limit (no key) | 5 requests / 30 seconds |
| Rate limit (with key) | 50 requests / 30 seconds |
| Pagination | `startIndex` + `resultsPerPage` (max 2000) |
| Key registration | https://nvd.nist.gov/developers/request-an-api-key |

**FIRST.org EPSS API:**
| Detail | Value |
|--------|-------|
| Endpoint | `https://api.first.org/data/v1/epss` |
| Auth | None required |
| Rate limit | ~100 requests / minute (public tier) |
| Bulk download | Single GET returns all CVEs with current scores |
| Update frequency | Daily (~0500 UTC) |

**CISA KEV Feed:**
| Detail | Value |
|--------|-------|
| Endpoint | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| Auth | None required |
| Format | JSON array: cveID, dateAdded, product, vendorName, requiredAction |
| Update frequency | As needed (typically weekly batches) |

**GreyNoise Community API:**
| Detail | Value |
|--------|-------|
| Endpoint | `https://api.greynoise.io/v3/community/{cve_id}` |
| Auth | Free API key required |
| Rate limit | 50 requests / day (community tier) |
| Strategy | Pre-fetch in bulk for known KEV entries |

**AlienVault OTX:**
| Detail | Value |
|--------|-------|
| Endpoint | `https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general` |
| Auth | Free OTX API key required |
| Rate limit | ~400 requests / day (community tier) |

### 4.2 Data Construction Logic

**Step 1 — Fetch CVEs with CVSS v3.1 vectors:**
```
Paginate NVD API (2019-01-01 to training cutoff of 2024-12-31)
Filter: has cvssMetricV31 block AND description is in English
→ ~120,000 CVEs
```

**Step 2 — Join EPSS scores:**
```
GET https://api.first.org/data/v1/epss (bulk)
Map CVE ID → epss score + percentile
```

**Step 3 — Join CISA KEV status:**
```
GET CISA KEV JSON feed
Create set of {cveID: dateAdded}
Mark cisa_kev = True for CVEs in KEV with dateAdded ≤ disclosure_date + 30 days
```

**Step 4 — Construct labels:**
```
OBSERVATION_WINDOW = 30 days after disclosure

Positive (label=1):
  - CVE in CISA KEV AND dateAdded ≤ disclosure + 30 days
  - OR GreyNoise "observed-in-the-wild" status within 30 days

Negative (label=0):
  - Zero exploitation activity across KEV, GreyNoise, OTX during window
  - Exclude CVEs with < 30 days of observation time (too recent to assess)
```

**Step 5 — Enrich with auxiliary features:**
```
For each CVE, query (as of training date):
  - ExploitDB: PoC exists?
  - Metasploit: module exists?
  - GreyNoise: active scanning in last 30 days?
  - OTX: pulse count
  - MITRE Top 25 CWE: CWE-ID match?
  - Compute: age_days, vendor_frequency, CVSS subscores
  - Regex parse: is_rce, is_privesc, is_bypass, is_dos, is_traversal
```

**Step 6 — Generate SBERT + PCA:**
```
descriptions = [cve.description for cve in all_cves]
embeddings_384d = SentenceTransformer('all-MiniLM-L6-v2').encode(descriptions)
embeddings_32d = PCA(n_components=32).fit_transform(embeddings_384d)

X = np.hstack([tabular_37_features, embeddings_32d])  # 69 features
y = [cve.label for cve in all_cves]
```

### 4.3 Expected Corpus Size

| Source | Count | Notes |
|--------|-------|-------|
| NVD CVEs (2019–2024) with CVSS v3.1 | ~120,000 | Pre-filtering |
| After: English description + complete features | ~50,000–80,000 | Removes incomplete records |
| Positive class (KEV + GreyNoise confirmed) | ~2,000–2,700 | ~3–5% of filtered |
| **Usable labeled records (after filtering for feature completeness)** | **~8,000–15,000** | Target ratio ~1:4 to ~1:5 |

**Realistic target: 10,000–12,000 records.** This is within the 5,000–20,000 range assumed by the XGBoost hyperparameters.

### 4.4 Train/Val/Test Split (Temporal)

To prevent look-ahead bias:

```
Train:    CVEs disclosed 2019-01-01 to 2023-06-30  (~65%)
Validate: CVEs disclosed 2023-07-01 to 2023-12-31  (~15%)
Test:     CVEs disclosed 2024-01-01 to 2024-12-31  (~20%)
```

Positive class (exploited CVEs) is stratified across splits. No CVE from a future time period appears in earlier splits.

---

## Section 5: RAG Population Plan (Gap 3)

### 5.1 Document Types (Priority Order)

| Priority | Type | Retrieval Value | Example |
|----------|------|-----------------|---------|
| 1 | Application config files (.properties, .config, .yaml) | Confirms/disproves attack surface | `saml.sso.enabled=false` (Row 7) |
| 2 | CMDB change records | Patch history, GPO deployment | CM-2023-10287 (Row 6) |
| 3 | Confluence runbooks | Deployment architecture, mitigations | ASR rule deployment via GPO (Row 5) |
| 4 | SharePoint configuration pages | Network topology, firewall rules | DMZ layout, reverse proxy configs |
| 5 | AD GPO exports | Security hardening verification | ASR enforcement status reports |
| 6 | Network diagrams | Lateral movement path validation | VLAN maps, subnet allocation |

### 5.2 Initial Corpus Size

**MVP pilot: 50–150 documents for a single WA government agency.**

For the 7 demo hosts specifically: approximately 20–25 documents, with each host having 2–4 relevant configuration documents.

### 5.3 Collection Methods

| Method | Tool | Effort |
|--------|------|--------|
| Manual JSON/YAML export | Analyst exports known configs | Low — immediate for MVP |
| Confluence REST API | `GET /wiki/rest/api/content?spaceKey=ICT` | Medium — API token required |
| SharePoint Graph API | `GET /sites/{site-id}/drive/...` | Medium — Azure AD app reg |
| Filesystem crawl | `find /etc -name "*.properties"` (read-only over SSH) | Medium — SSH key deploy |
| CMDB SQL query | Direct DB query for change records | Low — if CMDB accessible |
| PowerShell GPO export | `Get-GPOReport -All -ReportType XML` | Low — one-time dump |

**MVP approach:** Start with manual export of the 7 demo host configurations as structured JSON documents. Then add Confluence API for broader coverage.

### 5.4 Seed Documents for 7 Demo Hosts

To provide immediate RAG value, the vector store is seeded with hardcoded configuration summaries:

| Host | Seed Document |
|------|--------------|
| PRD-MOVEIT-WEB01.health.wa.gov.au | MOVEit Transfer 2023.0.0 build 15.0.0.185. Internet-facing on TCP 443. No WAF. No MFA on admin interface. No VPN required. Patch available (2023.0.2+) not applied. |
| PRD-CITRIX-ADC01.transport.wa.gov.au | NetScaler ADC VPX 13.1-49.13. Internet-facing VIP on TCP 443 (VPN virtual server). Build 49.13 vulnerable (fixed in 49.15+). 20+ downstream application targets. |
| PRD-PRINT-SVR05.education.wa.edu.au | PaperCut MF 22.0.6. Internal only. DOMAIN_EDU\svc-papercut-prd (local admin). 28 downstream endpoints. Flat education network architecture. |
| PRD-RMM-GW01.sharedservices.wa.gov.au | ScreenConnect 23.9.7.8804. Isolated management VLAN 48. 14 downstream agency endpoints across 5 network zones. |
| PRD-FILE-STORE02.communities.wa.gov.au | ASR rule GUID D4F940AB. GPO Communities-Endpoint-ASR-v2 applied Sep 2023. CMDB reports replication failure (error 0x80070005) as of Mar 2026. ASR enforcement status: UNCERTAIN. |
| PRD-WIKI-CORE01.wapol.internal.wa.gov.au | Scanner reports Confluence 8.5.1. Change record CM-2023-10287 claims upgrade to 8.5.2 on target host PRD-WIKI-CORE02 (staging/DR). DNS: PRD-WIKI-CORE01=10.185.42.9, PRD-WIKI-CORE02=10.185.42.10. |
| PRD-ITSM-TOOL01.finance.wa.gov.au | ManageEngine ServiceDesk Plus 14.0 build 13000. SAML SSO: DISABLED (saml.sso.enabled=false). Auth: LDAP only. /SamlResponseServlet: 404 (not active). SAML libs on disk but unreachable. |

### 5.5 Sparse Store Fallback

```python
def query_rag(hostname: str, cwe_class: str, top_k: int = 3) -> dict:
    try:
        table = db.open_table("asset_documentation")
    except Exception:
        return {
            "documents": [],
            "status": "STORE_EMPTY",
            "rag_context": ("RAG document store has not been populated. "
                            "No internal configuration data is available.")
        }

    query = f"Security configurations for {hostname} to resolve {cwe_class}"
    results = table.search(query).limit(top_k).to_list()

    if not results:
        return {
            "documents": [],
            "status": "NO_MATCHES",
            "rag_context": (f"No documentation found for {hostname}. "
                            f"Configuration status for {cwe_class} is unknown.")
        }

    return {
        "documents": results,
        "status": "RESULTS_FOUND",
        "rag_context": "\n\n".join([r["text"] for r in results])[:2000]
    }
```

---

## Section 6: Operational Cadence (Gap 4)

### 6.1 EPSS Score Refresh

| Parameter | Value |
|-----------|-------|
| Frequency | Daily |
| Source | FIRST.org EPSS API (~0500 UTC) |
| Method | Cron job or FastAPI background task |
| DB update | `UPDATE vulnerabilities SET epss_score = new WHERE epss_score != new` |
| Re-score trigger | Any changed EPSS → re-run scoring engine |

### 6.2 CISA KEV Update Handling

| Action | Timing | Mechanism |
|--------|--------|-----------|
| Poll KEV feed | Daily | Compare current vs previous snapshot |
| New CVE detected | Immediate | Set `cisa_kev = TRUE` for all DB rows with that CVE ID |
| Re-pipeline | Immediate | Re-run Tier 0 → Tier 1 → Tier 2 for all affected rows |
| Analyst notification | On priority change | Queue indicator: "KEV Status Changed" |

```python
def poll_kev_feed():
    current = fetch_cisa_kev_json()
    previous = load_kev_snapshot()
    new_kevs = set(current.keys()) - set(previous.keys())

    for cve_id in new_kevs:
        db.execute("UPDATE vulnerabilities SET cisa_kev=TRUE WHERE vulnerability_id=?", [cve_id])
        for row in db.execute("SELECT * FROM vulnerabilities WHERE vulnerability_id=?", [cve_id]):
            re_evaluate_pipeline(row)

    save_kev_snapshot(current)
```

### 6.3 XGBoost Model Retraining

| Trigger | Action |
|---------|--------|
| Scheduled: Quarterly | Refresh training data, retrain, validate against held-out test set |
| Event: >50 new KEV additions since last train | Immediate retraining |
| Event: EPSS distribution KS test p < 0.05 vs training distribution | Flag for analyst review, retrain if confirmed drift |
| Deployment gate | Deploy only if F1 improves or stays within 2% of current model |

### 6.4 Pre-Tier Active Learning Cadence

| Stage | Trigger | Action |
|-------|---------|--------|
| Initial training | 200 rules-labeled assets | Train from bootstrapped labels |
| Active learning loop | 20 new analyst labels | Select top 20 highest-entropy unlabeled |
| Retraining | Every 50 new labels (2–3 iterations) | Retrain on all labeled data |
| Loop termination | Validation F1 plateaus for 3 consecutive cycles | Switch to quarterly scheduled retraining |

### 6.5 Low-Severity 7-Day Re-Check

Incorporated from Source B. See Section 3.2.

### 6.6 Background Statistical Audit

Incorporated from Source B. See Section 7.

### 6.7 Cadence Summary

| Component | Frequency | Trigger |
|-----------|-----------|---------|
| EPSS scores | Daily | Scheduled |
| CISA KEV status | Daily poll + immediate re-score on new entry | Scheduled + event |
| Tier 0 low-severity re-check | 7 days after initial classification | Scheduled |
| XGBoost model retraining | Quarterly | Scheduled + event (>50 KEV, EPSS drift) |
| CWE encoder retraining | Annually or on-demand | When NVD mappings significantly change |
| Pre-Tier classifier retraining | Every 50 new labels | Active learning loop |
| RAG vector store | Continuous | CI/CD or manual upload on doc change |
| EPSS substitution model | Quarterly | Aligned with XGBoost |
| Statistical audit | Continuous (5–10% sample) | Background process |

---

## Section 7: Background Statistical Audit and Tier 3 Human Review

These elements are unique to Source B and are incorporated as follows.

### 7.1 Background Statistical Audit

**Purpose:** Detect model drift and establish true error rates without introducing pipeline latency.

**Mechanism:**
- 5–10% of cases auto-resolved at Tier 0 or Tier 1 are randomly sampled.
- Sampled cases enter an asynchronous background pool.
- An independent review process evaluates them against calibrated criteria (did the model make the right call?).
- Audit results feed into model retraining prioritization and threshold tuning.

**Implementation:**
```python
def should_audit(tier_result: dict) -> bool:
    if tier_result["routing"] == "auto_resolved":
        return random.random() < AUDIT_SAMPLE_RATE  # 0.05 to 0.10
    return False

# In the ingest handler:
if should_audit(result):
    queue_background_audit(case_id=result.id, tier=result.tier)
```

**Key property:** The audit is fully decoupled from the live pipeline. A case is never delayed waiting for audit — it is resolved immediately, and the audit happens asynchronously.

### 7.2 Tier 3 Human Review

**Entry:** Cases where Tier 2 LLM confidence is low (< ~0.65) or where the analyst is explicitly flagged.

**Analyst experience:**
- Full evidence trail: raw scanner logs, predicted asset criticality tags, upstream ML scores, internal documentation citations, SLM narrative summary.
- Analyst makes the final determination (score band, resolution notes).
- No rubber-stamping — the analyst is expected to review, not just approve.

**Feedback ingestion:**
- If the analyst modifies or overturns the automated score, the annotated record is captured.
- Reversed cases are routed to an isolated dataset for future model retraining.
- This prevents feedback loops where the model learns to replicate its own errors (avoiding "rubber-stamped data loops").

**File:** Part of `backend/pipeline/tier_2.py` routing logic — cases with `confidence < 0.65` are flagged for Tier 3 in the database and appear in the "Needs human validation" metric on the frontend.

### 7.3 Schema Validation and CVE Recovery

**Incorporated from Source B Phase 1:**

Before any pipeline processing, incoming payloads pass through an event-driven validation layer:
1. Check for malformed formatting or schema drift.
2. If malformed: attempt to recover CVSS score and description from a locally cached CVE database (updated daily from NVD).
3. If recovery succeeds: proceed with recovered values, flag record as "recovered."
4. If recovery fails: reject payload with error.

This is not an ML concern but is documented here for pipeline completeness. Implementation location: `backend/routers/ingest.py` validation logic.

---

## Section 8: File Path Alignment (Correction 3)

All file paths use the project's `backend/` root:

| Component | File Path |
|-----------|-----------|
| Tier 0 deterministic rules | `backend/pipeline/tier_0.py` |
| Tier 1 XGBoost orchestration | `backend/pipeline/tier_1.py` |
| Tier 2 cloud LLM orchestration | `backend/pipeline/tier_2.py` |
| Pre-Tier orchestration | `backend/pipeline/pre_tier.py` |
| SBERT encoder + PCA | `backend/ml/encoder.py` |
| CWE classifier (SecureBERT2.0) | `backend/ml/cwe_classifier.py` |
| XGBoost predictor model | `backend/ml/xgboost_predictor.py` |
| LanceDB vector store + RAG | `backend/ml/vector_store.py` |
| EPSS substitution model | `backend/ml/epss_substitutor.py` |
| Pre-Tier classifier model | `backend/ml/pre_tier_classifier.py` |
| Serialized model files | `backend/ml/*.pkl` |
| Scoring engine | `backend/scoring.py` |
| CMDB/asset lookups | `backend/ingest_helpers.py` |

---

## Section 9: Consolidated Implementation Roadmap

| # | Component | File Path | Dependencies | Data Required | Est. Effort | Can Start |
|---|-----------|-----------|-------------|---------------|-------------|-----------|
| 1 | Tier 0 Deterministic Rules | `backend/pipeline/tier_0.py` | None | None | Done | — |
| 2 | Tier 2 Cloud LLM Interface | `backend/pipeline/tier_2.py` | openai>=1.12.0, httpx | API key | Done | — |
| 3 | SBERT Encoder + PCA | `backend/ml/encoder.py` | sentence-transformers>=2.3.0, scikit-learn>=1.4.0 | NVD descriptions (public) | 2–3 days | Now |
| 4 | LanceDB Vector Store + Seed Docs | `backend/ml/vector_store.py` | lancedb>=0.5.0, sentence-transformers>=2.3.0 | 7 demo host configs (manual) | 2–3 days | Now |
| 5 | CWE Classifier (SecureBERT2.0) | `backend/ml/cwe_classifier.py` | torch>=2.2.0, transformers>=4.37.0 | NVD CWE mappings (public) | 3–5 days | After #3 |
| 6 | Tier 1 XGBoost Model | `backend/ml/xgboost_predictor.py` | xgboost>=2.0.3, scikit-learn>=1.4.0 | NVD+EPSS+KEV+ExploitDB+GreyNoise | 1–2 weeks | After #3, #5 |
| 7 | Tier 0 7-Day Re-Check (Cron) | `backend/pipeline/tier_0.py` (update) | apscheduler or similar | None (scheduling) | 1 day | After #1 |
| 8 | Background Statistical Audit | `backend/` (new module) | None (random sampling) | None | 2–3 days | After #1, #6 |
| 9 | Pre-Tier Classifier | `backend/ml/pre_tier_classifier.py` | scikit-learn>=1.4.0, pandas>=2.2.0 | 200–500 analyst-labeled assets | 2–3 weeks | After labels collected |
| 10 | EPSS Substitution Engine | `backend/ml/epss_substitutor.py` | pandas>=2.2.0, numpy>=1.26.0 | OTX+GreyNoise sector data (public) | 1–2 weeks | After #3, #6 |
| 11 | Active Learning Loop | `backend/pipeline/pre_tier.py` (update) | Same as #9 | Same as #9 | 1 week | After #9 initial model |
| 12 | Operational Cadence Automation | `backend/` (scheduler) | apscheduler or fastapi-utils | None | 1 week | After #6, #7, #9, #10 |
| 13 | RAG Population Pipeline (Confluence API) | `backend/ml/vector_store.py` (update) | Confluence API client | Agency documentation access | 1–2 weeks | After access granted |
| 14 | Schema Validation + CVE Recovery | `backend/routers/ingest.py` (update) | Local CVE cache (NVD daily sync) | NVD API key (optional) | 2–3 days | After #3 |
| 15 | Tier 3 Human Review Enrichment | `backend/pipeline/tier_2.py` (update) | None (routing logic) | None | 1–2 days | After #2 |

**Dependency chain:**
```
#1, #2: Done (no dependencies)
#3 → #5 → #6 (critical path to working ML pipeline)
#4: Parallel with #3
#7: After #1
#8: After #1, #6
#9: Independent of text pipeline (tabular only)
#10: After #3, #6
#11: After #9
#12: After #6, #7, #9, #10
#13: After #4 + agency access
#14: After #3
#15: After #2
```

**Critical path to a working ML pipeline:** Items #3 → #5 → #6, estimated 3–4 weeks from start using only public data.

---

## Appendix A: Source Divergence Catalogue

This appendix catalogues every point where Source A (`TriageMate ML Research.md`) and Source B (`Additional Information.md`) provided competing approaches, and which was selected.

### A.1 Tier 2 Decoder: Local Model vs Cloud LLM

| | Source B | Source A |
|---|---|---|
| Approach | Local 7B–8B parameter reasoning decoder model | Cloud-hosted gpt-4o-mini with FSM-enforced JSON |
| Selected | | ✓ |
| Reason | Already implemented in `tier_2.py`. Zero GPU requirement. FSM guarantees 100% JSON validity. $0.0004/analysis. Local 7B model would require quantization infrastructure, 8–16GB VRAM, model serving, and ongoing maintenance — contradicting the "single developer machine" MVP constraint. |

### A.2 XGBoost Model: RRF Ensemble vs Standard

| | Source B | Source A |
|---|---|---|
| Approach | "XGBoost Reciprocal Rank Fusion (RRF) ensemble model" | Standard XGBoost with 800 trees, Platt calibration |
| Selected | | ✓ |
| Reason | RRF requires multiple models, fusion weight tuning, and N× retraining effort. On a binary classification task with ~10K records, the complexity provides no measurable accuracy gain. Standard XGBoost is simpler to implement, debug, and retrain. |

### A.3 RAG Query: SLM-Triggered vs Pre-Query

| | Source B | Source A |
|---|---|---|
| Approach | "The SLM triggers a Retrieval-Augmented Generation (RAG) query against internal documentation" | Deterministic pre-query based on hostname + CWE class before LLM call |
| Selected | | ✓ |
| Reason | Agent-triggered RAG requires multiple round-trips to the LLM (higher cost, latency, complexity) and tool-use capabilities. Deterministic pre-query injects all relevant context into a single prompt, guaranteeing the LLM has full context upfront. |

### A.4 Tier 0 Low-Severity Re-Check

| | Source B | Current Implementation |
|---|---|---|
| Approach | Low severity "marked to be checked within 7 days" | Auto-resolve with no re-check |
| Selected | ✓ | |
| Reason | EPSS and KEV status can change. A vulnerability classified "low" today could have its EPSS jump or be added to KEV within a week. 7-day window balances risk against re-processing overhead. Runs asynchronously — zero pipeline latency impact. |

### A.5 Background Statistical Audit

| | Source B | Source A |
|---|---|---|
| Approach | 5–10% random sample of auto-resolved cases for independent audit | Not addressed |
| Selected | ✓ | |
| Reason | Standard ML ops practice for detecting model drift. Fully decoupled from live pipeline — zero latency impact. |

### A.6 Tier 3 Human Review Workflow

| | Source B | Source A |
|---|---|---|
| Approach | Detailed workflow: full evidence trail, feedback ingestion for retraining, rubber-stamped data loop prevention | Briefly mentioned as escalation path |
| Selected | ✓ (detail incorporated) | |
| Reason | Source B's feedback ingestion mechanism is essential for model improvement. The detail about preventing rubber-stamped data loops is a concrete operational safeguard. |

### A.7 Pre-Ingest Schema Validation

| | Source B | Current Implementation |
|---|---|---|
| Approach | Event-driven validation layer checking for malformed records with CVE database recovery | Not implemented |
| Selected | ✓ (incorporated as pipeline pre-processing) | |
| Reason | Defense-in-depth for data quality. Not ML-specific but important for pipeline robustness. Low implementation effort. |

### A.8 CMDB Matching + Telemetry Flow

| | Source B | Current Implementation |
|---|---|---|
| Approach | Detailed flow: IP → CMDB match → AD telemetry → classifier. Unknown assets tagged. | `KNOWN_HOSTS` dictionary stub + `ingest_helpers.py` |
| Selected | Both — Source B describes the ideal architecture; current implementation is the MVP bridge. | |
| Reason | The stub provides immediate functionality for the 7 demo hosts while the documented flow describes what the real integration should look like. |

---

*End of document.*
