# TriageMate — Feature Parity Report

> Compares feature definitions across inference code, training code,
> and the ML inventory document. Auto-generated from AST parsing.

---

## 1. Inference (`ingest_helpers.py` → `build_feature_vector()`)

| # | Key | Category |
|---|-----|----------|
| 0 | `cvss_av` | tabular |
| 1 | `cvss_ac` | tabular |
| 2 | `cvss_pr` | tabular |
| 3 | `cvss_ui` | tabular |
| 4 | `cvss_s` | tabular |
| 5 | `cvss_c` | tabular |
| 6 | `cvss_i` | tabular |
| 7 | `cvss_a` | tabular |
| 8 | `cvss_score` | metadata |
| 9 | `epss_score` | tabular |
| 10 | `patch_available` | tabular |
| 11 | `osv_fixed_versions` | metadata |
| 12 | `osv_package` | metadata |
| 13 | `osv_ecosystem` | metadata |
| 14 | `patch_applied` | tabular |
| 15 | `internet_facing` | tabular |
| 16 | `domain_joined` | tabular |
| 17 | `data_classification` | tabular |
| 18 | `mission_prevalence` | tabular |
| 19 | `public_wellbeing_impact` | tabular |
| 20 | `lateral_reachability` | tabular |
| 21 | `boundary_reachability` | tabular |
| 22 | `downstream_assets` | tabular |
| 23 | `patch_lag_days` | tabular |
| 24 | `exploitdb_has_poc` | tabular |
| 25 | `metasploit_has_payload` | tabular |
| 26 | `internet_scan_detected` | tabular |
| 27 | `threat_intel_pulses` | tabular |
| 28 | `nvd_reference_count` | tabular |
| 29 | `cve_desc_tokens` | tabular |
| 30 | `vulnerability_age_days` | tabular |
| 31 | `vendor_popularity_index` | tabular |
| 32 | `cvss_exploitability_sub` | tabular |
| 33 | `cvss_impact_sub` | tabular |
| 34 | `is_top_25_cwe` | tabular |
| 35 | `is_rce_signature` | tabular |
| 36 | `is_privesc_signature` | tabular |
| 37 | `is_bypass_signature` | tabular |
| 38 | `is_dos_signature` | tabular |
| 39 | `is_traversal_signature` | tabular |
| 40 | `threat_intel_status` | metadata |
| 41 | `description` | metadata |

**Tabular count:** 36  
**Metadata count:** 6  

---

## 2. Training — Column Order

### `analysis/feature_parity_check.py` → `build_training_vector()`

| Pos | Expression |
|-----|-----------|
| 0 | `float()` |
| 1 | `float()` |
| 2 | `float()` |
| 3 | `float()` |
| 4 | `float()` |
| 5 | `float()` |
| 6 | `float()` |
| 7 | `float()` |
| 8 | `float()` |
| 9 | `float()` |
| 10 | `float()` |
| 11 | `float()` |
| 12 | `float()` |
| 13 | `float()` |
| 14 | `float()` |
| 15 | `float()` |
| 16 | `float()` |
| 17 | `float()` |
| 18 | `float()` |
| 19 | `float()` |
| 20 | `float()` |
| 21 | `float()` |
| 22 | `float()` |
| 23 | `float()` |
| 24 | `float()` |
| 25 | `float()` |
| 26 | `float()` |
| 27 | `float()` |
| 28 | `float()` |
| 29 | `float()` |
| 30 | `float()` |
| 31 | `float()` |
| 32 | `float()` |
| 33 | `float()` |
| 34 | `float()` |

**Count:** 35  

### `ml/train_xgboost.py` → `build_tabular_features()`

| Pos | Expression |
|-----|-----------|
| 0 | `_av_map()` |
| 1 | `_ac_map()` |
| 2 | `_pr_map()` |
| 3 | `_ui_map()` |
| 4 | `_s_map()` |
| 5 | `_cia_map()` |
| 6 | `_cia_map()` |
| 7 | `_cia_map()` |
| 8 | `get()` |
| 9 | `patch_avail` |
| 10 | `_compute_patch_applied()` |
| 11 | `_compute_internet_facing()` |
| 12 | `_compute_domain_joined()` |
| 13 | `_compute_data_classification()` |
| 14 | `_compute_mission_prevalence()` |
| 15 | `_compute_public_wellbeing_impact()` |
| 16 | `_compute_lateral_reachability()` |
| 17 | `_compute_boundary_reachability()` |
| 18 | `_compute_downstream_assets()` |
| 19 | `_compute_patch_lag_days()` |
| 20 | `_compute_exploitdb_has_poc()` |
| 21 | `_compute_metasploit_has_payload()` |
| 22 | `_compute_threat_intel_pulses()` |
| 23 | `get()` |
| 24 | `len()` |
| 25 | `_compute_age_days()` |
| 26 | `0.0` |
| 27 | `get()` |
| 28 | `get()` |
| 29 | `int()` |
| 30 | `int()` |
| 31 | `int()` |
| 32 | `int()` |
| 33 | `int()` |
| 34 | `int()` |

**Count:** 35  

---

## 3. Parity Comparison

| Source | Column Count |
|--------|-------------|
| Inference (`ingest_helpers.py`) | 36 |
| Training (feature_parity_check.py) | 35 |

❌ **MISMATCH:** Inference produces 36 tabular features but training expects 35.

### Inference vs ML Inventory

Inventory features parsed: 37

❌ **In inventory but not in code:** cvss_score

### Inference Names vs XGBoost Positions

Column-by-column check: 22 mismatches

---

## 4. Key Discrepancies

- Inference produces 36 tabular features but training expects 35. Feature count drift detected.
- Inference has 36 tabular feature keys (expected 35). Some metadata keys may be incorrectly classified.
