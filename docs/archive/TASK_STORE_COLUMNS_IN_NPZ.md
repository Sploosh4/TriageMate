# Task: Store Column Names in NPZ Metadata

**Priority:** Next time the XGBoost model is retrained

## Why

The NPZ file (`training_data_v2.npz`) is a raw float64 matrix with zero column metadata. Feature parity checks (Approach B in graphify) can only compare *counts* and *heuristic expression names* — they're blind to what the columns actually are. Storing column names inside the NPZ lets graphify mechanically verify that the training data matches the inference code, catching column renames, reorderings, and semantic drift.

## What to Change

### 1. Modify `backend/scripts/build_training_corpus.py`

In the function that builds the NPZ (`save_training_data()` or equivalent), add a `columns` array alongside `X` and `y`:

```python
# Before:
np.savez_compressed("training_data_v2.npz", X=X, y=y)

# After:
feature_names = [
    "cvss_av", "cvss_ac", "cvss_pr", "cvss_ui", "cvss_s",
    "cvss_c", "cvss_i", "cvss_a", "epss_score",
    "patch_available", "patch_applied",
    "internet_facing", "domain_joined", "data_classification",
    "mission_prevalence", "public_wellbeing_impact",
    "lateral_reachability", "boundary_reachability", "downstream_assets",
    "patch_lag_days",
    "exploitdb_has_poc", "metasploit_has_payload", "threat_intel_pulses",
    "nvd_reference_count", "cve_desc_tokens", "vulnerability_age_days",
    "vendor_popularity_index",
    "cvss_exploitability_sub", "cvss_impact_sub",
    "is_top_25_cwe",
    "is_rce_signature", "is_privesc_signature", "is_bypass_signature",
    "is_dos_signature", "is_traversal_signature",
]
np.savez_compressed("training_data_v2.npz",
    X=X, y=y,
    columns=np.array(feature_names, dtype=str),
)
```

These 35 names must match the positional order in `ml/train_xgboost.py:build_tabular_features()` (lines 592-632) exactly.

### 2. Rebuild the corpus

```bash
cd backend
python -m scripts.build_training_corpus
```

This overwrites `backend/ml/training_data_v2.npz` with the new format.

### 3. Verify

```python
import numpy as np
data = np.load("backend/ml/training_data_v2.npz", allow_pickle=True)
print(data["columns"])  # Should show 35 feature names
print(data["X"].shape)  # Should be (n, 35)
```

## What It Enables

Once columns are stored in the NPZ, graphify's `feature_parity.py` generator can read them directly and compare against:

| Source | What it tells you |
|--------|-------------------|
| NPZ `columns` | What was actually trained |
| `ingest_helpers.py` → `build_feature_vector()` | What inference produces (by name) |
| `train_xgboost.py` → `build_tabular_features()` | What training produces (by position) |
| `ml_inventory.md` (graphify output) | What the AI expects |

A 4-way diff catches drift instantly. If someone adds a feature to inference code but doesn't rebuild the corpus, the NPZ column list won't match the inference dict keys — and graphify will flag it.
