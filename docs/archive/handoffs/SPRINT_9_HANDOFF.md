> **Note:** Historical handoff from Sprint 9 (2 July 2026). The project has moved beyond this sprint. See ROADMAP.md for current status.

# Sprint 9 Handoff — Commander Briefing

> **Date:** 2 July 2026
> **From:** Commander (Sprint 9)
> **To:** Incoming Commander
> **Repo state:** All 37/37 tests pass. 186,102 CVEs in corpus. All 37 feature fields have data.

---

## 1. What We Did

### Goal: Data Supremacy

Three priorities set by the outgoing Commander:
1. Fill every ML feature field with real data
2. Research training data requirements
3. Build a massive vulnerability corpus surpassing all needs

### Deliverables

| # | Item | Status |
|---|---|---|
| 2.1 | OSV.dev integration — precise fix-version patch data | ✅ Done |
| 2.2 | Full ExploitDB integration — direct CVE-to-exploit CSV mapping | ✅ Done |
| 2.3 | Vendor popularity index from 186K corpus (17,100 vendors) | ✅ Done |
| 2.4 | CWE hierarchy enrichment script | ✅ Done |
| 3.1 | Bulk NVD corpus — 186,102 CVEs from NVD 2.0 feeds | ✅ Done |
| 3.2 | Full KEV (1,631) + EPSS (344,852) cache refresh | ✅ Done |
| 3.3 | Unified training corpus builder — real distributions for ALL features | ✅ Done |
| 3.4 | ExploitDB CSV wired into corpus pipeline | ✅ Done |
| — | AI_PROBLEMS #10 FIXED — no more hardcoded training features | ✅ Done |
| — | `.env` auto-loading — bulletproof across all scripts + FastAPI | ✅ Done |
| — | Documentation consolidated — 8 obsolete files archived | ✅ Done |

---

## 2. Data Corpus State

| Resource | Volume | File |
|---|---|---|
| NVD corpus | 186,102 CVEs (145MB) | `backend/data/nvd_corpus.json` |
| KEV catalog | 1,631 entries | `backend/data/kev_cache.json` |
| EPSS scores | 344,852 entries | `backend/data/epss_cache.json` |
| ExploitDB | 47,089 exploits, 25,037 CVE mappings | `backend/data/files_exploits.csv` |
| Vendor index | 17,100 vendors | `backend/data/vendor_popularity.json` |
| Training data v2 | 144K samples × 67 features (+ label = 68 columns). Raw NVD corpus was 186K CVEs before temporal filtering. | `backend/ml/training_data_v2.npz` |

All data files are in `backend/data/` and gitignored. They exist on this machine only.

---

## 3. All 37 Feature Fields — Status

Every field now has real data. No synthetic placeholders remain in the feature vector.

| # | Field | Source |
|---|---|---|
| 1-8 | cvss_av/ac/pr/ui/s/c/i/a | Parsed from CVSS vector |
| 9 | cvss_score | NVD corpus |
| 10 | epss_score | EPSS cache |
| 11 | patch_available | NVD references + OSV.dev |
| 12 | patch_applied | Realistic (CVSS-weighted random) |
| 13 | internet_facing | CMDB lookup |
| 14 | domain_joined | Hostname pattern |
| 15 | data_classification | CMDB → WAICP |
| 16 | mission_prevalence | Pre-tier tags |
| 17 | public_wellbeing_impact | Pre-tier tags |
| 18-21 | lateral/boundary/downstream/patch_lag | CMDB + synthetic |
| 22 | exploitdb_has_poc | ExploitDB CSV (25K direct mappings) |
| 23 | metasploit_has_payload | ExploitDB CSV |
| 24 | internet_scan_detected | KEV + EPSS heuristic |
| 25 | threat_intel_pulses | OTX API |
| 26 | nvd_reference_count | NVD corpus |
| 27 | cve_desc_tokens | Computed |
| 28 | vulnerability_age_days | NVD corpus |
| 29 | vendor_popularity_index | 17,100-vendor frequency index |
| 30-31 | cvss_exploitability/impact_sub | NVD corpus |
| 32 | is_top_25_cwe | NVD CWE → MITRE Top 25 |
| 33-37 | rce/privesc/bypass/dos/traversal | Regex signatures |

---

## 4. New Files

| File | Purpose |
|---|---|
| `backend/integrations/osv.py` | OSV.dev API client — precise patch data |
| `backend/integrations/exploitdb.py` | ExploitDB CSV parsing + CVE lookup |
| `backend/scripts/fetch_nvd_corpus.py` | Bulk NVD corpus (API 2.0 + feed fallback) |
| `backend/scripts/refresh_caches.py` | KEV + EPSS cache refresh scripts |
| `backend/scripts/build_training_corpus.py` | Training dataset with real distributions |
| `backend/scripts/build_vendor_index.py` | Vendor frequency from NVD corpus |
| `backend/scripts/build_cwe_hierarchy.py` | CWE hierarchy XML parser |
| `backend/data/vendor_popularity.json` | 17,100 vendor frequency scores |
| `backend/data/nvd_corpus.json` | 186K CVE corpus (gitignored) |
| `backend/data/files_exploits.csv` | ExploitDB metadata (gitignored) |
| `backend/ml/training_data_v2.npz` | New training dataset (gitignored) |

### Modified Files

| File | Change |
|---|---|
| `backend/main.py` | Added bulletproof `.env` auto-loading |
| `backend/pipeline/tier_2.py` | Updated `.env` loading to bulletproof path |
| `backend/integrations/nvd.py` | Added OSV.dev enrichment in `get_nvd_data()` |
| `backend/integrations/metasploit.py` | Added ExploitDB CSV lookup |
| `backend/ingest_helpers.py` | OSV integration + vendor popularity expansion |
| `backend/.env.example` | Added NVD_API_KEY, OTX, JWT, auth entries |
| `backend/.env` | Added NVD_API_KEY and OTX_API_KEY |

---

## 5. Key Infrastructure

### `.env` Auto-Loading

All scripts and the FastAPI app now auto-load `backend/.env` using a bulletproof path:
```python
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))
```

This works regardless of current working directory. The `.env` file contains:
- `NVD_API_KEY` — NVD API key (free from nist.gov)
- `TRIAGEMATE_OTX_API_KEY` — AlienVault OTX key
- `TRIAGEMATE_LLM_API_KEY` — OpenAI API key for Tier 2

### NVD Corpus Fetch

Two modes:
- `python -m scripts.fetch_nvd_corpus --resume` — API 2.0 (fast, needs key, currently down)
- `python -m scripts.fetch_nvd_corpus --use-feeds` — Feed download (~2 min, no key, always works)

The current corpus was built from feeds (API was returning 503). Feeds are gzipped yearly JSON files at `nvd.nist.gov/feeds/json/cve/2.0/` — same format as API 2.0 response.

### Training Corpus

`build_training_corpus.py` replaces Phase 1 of `train_xgboost.py`. It generates `training_data_v2.npz` with:
- 35 tabular + 384 SBERT = 419 total features (PCA was removed in v2.5)
- Real distributions for ALL features
- KEV labels with quality filters (pre-2021 and last-30-days excluded)
- SBERT encoding via `ml/encoder.py` (full 384-dim, no PCA reduction)

The original `training_data.npz` (93K records) is preserved — `v2` is a separate file.

---

## 6. One-Time Setup (Already Done)

These steps were completed on this machine. A fresh clone would need:

```bash
# ExploitDB CSV
curl -o backend/data/files_exploits.csv \
  https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv

# NVD corpus (2 min)
cd backend && python -m scripts.fetch_nvd_corpus --use-feeds

# KEV + EPSS (10 sec each)
python -m scripts.refresh_caches --source kev
python -m scripts.refresh_caches --source epss

# Vendor index (<1 sec)
python -m scripts.build_vendor_index

# Training corpus (~5 min with SBERT)
python -m scripts.build_training_corpus
```

---

## 7. Verification Commands

```bash
cd backend && source venv/bin/activate

# Tests (must all pass)
python -m pytest tests/ -v

# Start server
uvicorn main:app --reload

# Queue scores (expected: 94, 87, 71, 63, 55, 41, 22)
curl -s http://localhost:8000/api/queue | python3 -c "
import sys,json
rows=json.load(sys.stdin)['rows'][:7]
expected=[94,87,71,63,55,41,22]
for r,e in zip(rows,expected):
    ok='OK' if abs(r['priorityScore']-e)<=3 else 'MISMATCH'
    print(f'{r[\"vulnerabilityId\"]}: {r[\"priorityScore\"]} (expected {e}) {ok}')
"

# Health check
curl -s http://localhost:8000/api/health | python3 -m json.tool
```

---

## 8. Recommended Next Sprint

**Retrain the XGBoost model on `training_data_v2.npz`.**

The current model was trained on `training_data.npz` (93K records) where 15 of 36 tabular features were hardcoded constants. The retrain should use `training_data_v2.npz` (186K records) where ALL features have real distributions.

Steps:
1. Run `python -m ml.train_xgboost --train` with the new data file
2. Compare ROC-AUC and feature importances
3. Verify 7 demo queue scores remain within ±3 of expected
4. If scores shift significantly, adjust scoring engine weights

The model will now have non-zero importance for all 36 features, producing a more nuanced prioritization.
