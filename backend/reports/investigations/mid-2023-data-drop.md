# Mid-2023 Training Data Drop — Root Cause Analysis

**Investigation date:** 2026-07-14
**Investigator:** Strike Team (code-writing agent)
**Status:** ✅ Root cause identified

---

> **⚠️ CURRENT STATUS:** This investigation accurately diagnosed the root cause of degenerate val/test splits. However, **Fix 1 ("Apply observation window to training split only")** in the Potential Fixes section below is **SUPERSEDED** by the point-in-time split policy implemented in Sprint 30 (PR #68). The actual fix that was applied used a different approach — **split-before-filter with primary/prospective/censored cohorts** — rather than the simple train-only filter window proposed in Fix 1. See ROADMAP.md §Sprint 29 Item 3 for details.

## Executive Summary

The `phase_gather()` pipeline in `backend/ml/train_xgboost.py` applies a **dynamic KEV observation window filter** that removes all label-0 (not-in-KEV) CVEs published within 706 days of `DATE_END` (2024-12-31). This produces a cutoff date of **2023-01-25**. The filter is applied globally **before** the chronological train/val/test split. Since the validation period (2023-07-01 to 2023-12-31) and test period (2024-01-01+) fall entirely after this cutoff, **every single negative example is stripped from those splits**. The validation and test sets become degenerate: 81 records (100% positive) and 125 records (100% positive) respectively. The model cannot be properly evaluated — it sees only positives in the held-out sets, making metrics like ROC-AUC and F1 unreliable.

This is not a bug in the filter concept (which is a legitimate temporal bias fix introduced in v2.3), but a **design flaw in the interaction between the global reliability filter and the chronological split**.

---

## Monthly CVE Counts from `enriched_cves.json` (260,636 records)

```
Pre-filter data shows healthy monthly volume throughout 2023-2024:

2023-01  2,292    2023-07  2,351    2024-01  2,515
2023-02  2,032    2023-08  2,331    2024-02  2,564
2023-03  2,623    2023-09  2,252    2024-03  3,583
2023-04  2,436    2023-10  2,522    2024-04  3,448
2023-05  2,197    2023-11  2,466    2024-05  4,615
2023-06  2,496    2023-12  2,841    2024-06  3,228
   Total mid-2023: 14,763
```

**Conclusion:** There is no data scarcity in the source. The 14,763 mid-2023 CVEs and 39,029 2024 CVEs are present in `enriched_cves.json`. The loss occurs entirely within the gather pipeline.

---

## Pipeline Trace — Step by Step

### Step 1: Load enriched CVEs
- **Input:** `backend/ml/enriched_cves.json` → 260,636 records
- **Action:** Load existing file (no re-fetch), then fetch fresh KEV catalog (1,638 KEV entries)
- **Result:** 260,636 records loaded

### Step 2: Construct labels (`construct_labels()`)
- **Action:** Assign multi-window KEV labels 0–4, point-in-time filtered to `DATE_END = 2024-12-31`
- **Result:**
  - Label 0 (not KEV):    259,397
  - Label 1 (≤30d):        16
  - Label 2 (31-90d):      39
  - Label 3 (91-365d):    131
  - Label 4 (>365d):     1,053
  - Excluded (future KEV): 397
- **Note:** 1,239 total KEV positives (0.48% of dataset)

### Step 3: Build tabular features + SBERT encoding
- **Result:** Feature matrix `X` (260,636 × 419), labels `y`, dates array all computed. No data lost here.

### Step 4: ⚠️ KEV Temporal Bias Filter (Observation Window) — **ROOT CAUSE LOCATION**

Computation:
```python
obs_window_days = compute_kev_lag_stats(cves, kev)["median"]  # = 706 days
obs_cutoff = DATE_END - timedelta(days=obs_window_days)        # = 2023-01-25
too_recent = dates_arr > obs_cutoff_str                         # after 2023-01-25
obs_mask = ~(too_recent & (y_arr == 0))                         # remove label-0 CVEs after cutoff
```

- **Records removed:** 144,237 (all label-0 CVEs published after 2023-01-25)
- **Records kept:** 116,399
- **KEV positives preserved in window:** 266 (rapid exploitation cases)
- **Why 266 preserved?** These are KEV-positive CVEs published after 2023-01-25 that survive the filter because only `label=0` CVEs are excluded.

### Step 5: Chronological Split (applied AFTER filter)

```python
train_mask = dates <= TRAIN_CUTOFF   # <= 2023-06-30
val_mask   = (dates > TRAIN_CUTOFF) & (dates <= VAL_CUTOFF)  # 2023-07-01 to 2023-12-31
test_mask  = dates > VAL_CUTOFF                              # 2024-01-01+
```

| Split | Records | KEV Positives | Negatives | % Positive |
|-------|---------|---------------|-----------|-----------|
| Train | 116,193 | 1,033 | 115,160 | 0.89% |
| Val   | 81      | 81    | 0        | **100%** |
| Test  | 125     | 125   | 0        | **100%** |

### Why Val/Test Have 0 Negatives

All CVEs in the val period (2023-07-01 to 2023-12-31) and test period (2024-01-01+) fall **after** the observation cutoff of 2023-01-25. The filter removed ALL label-0 CVEs after that date. The only CVEs that survive in those date ranges are KEV positives (1,239 total, with 206 falling outside the training cutoff of 2023-06-30).

---

## Root Cause

**The global application of the KEV observation window filter before the chronological split creates a structural mismatch.**

The temporal bias fix (v2.3) computes a dynamic observation window anchored to `DATE_END`:
```
obs_cutoff = DATE_END - median_KEV_lag
           = 2024-12-31 - 706 days
           = 2023-01-25
```

This cutoff falls **156 days before** `TRAIN_CUTOFF = 2023-06-30`. The filter strips label-0 CVEs from the entire 2023-2024 period. When the chronological split is subsequently applied, the validation and test periods fall entirely within this stripped zone, leaving them with zero negative examples.

### Code location

`backend/ml/train_xgboost.py`, lines 1027–1057 (`phase_gather()` function):

```python
obs_cutoff = datetime.strptime(DATE_END, "%Y-%m-%d") - timedelta(
    days=obs_window_days
)
too_recent = dates_arr > obs_cutoff_str
obs_mask = ~(too_recent & (y_arr == 0))
# ... applies obs_mask globally to X, y_arr, dates_arr, cve_ids, cves
# ... then later splits by TRAIN_CUTOFF / VAL_CUTOFF
```

### Why the median lag is 706 days

The median KEV lag is computed from 1,088 KEV entries (those with `dateAdded <= DATE_END = 2024-12-31`). The high value (706 days) reflects the real distribution of CISA KEV additions — many CVEs are added to KEV long after publication. However, this is a **global** median that includes many old CVEs (KEV additions for vulnerabilities published 10+ years ago), which inflates the median and creates an overly aggressive filter window for recent data.

---

## Impact

1. **Degenerate validation and test splits:** Both val (81 records) and test (125 records) are 100% positive. The model's held-out evaluation is meaningless:
   - ROC-AUC cannot be computed reliably (no true negatives)
   - F1 score measures recall only (precision is ill-defined with no negatives)
   - Platt calibration has no negative examples to calibrate against
   - The calibration warning is triggered: `[WARN] Validation set has only NN positive(s). Skipping calibration`

2. **Training data contamination:** While the training set has negatives (115,160), ALL of them are from before 2023-01-26. The model never sees negative examples from the 2023-01-26 to 2023-06-30 window in training, reducing its ability to generalize to modern CVE patterns.

3. **Unreliable model metrics:** The data quality report in the log shows plausible-looking numbers (1.1% positive rate, etc.), but they are misleading because they reflect the post-filter distribution, not real-world conditions.

---

## Potential Fixes

### Fix 1: Apply observation window to training split only ⚠️ SUPERSEDED (see banner above)

**Strategy:** Apply the unreliable-negative filter only to the training set. Keep val/test untouched.

**Implementation:**
```python
# Split first
train_mask = dates_arr <= TRAIN_CUTOFF
val_mask = (dates_arr > TRAIN_CUTOFF) & (dates_arr <= VAL_CUTOFF)
test_mask = dates_arr > VAL_CUTOFF

# Apply observation window filter to training only
too_recent_train = (dates_arr[train_mask] > obs_cutoff_str)
reliable_train = ~(too_recent_train & (y_arr[train_mask] == 0))
# ... filter train arrays only
```

**Tradeoffs:**
- ✅ Val/test have representative class distributions (including negatives)
- ✅ Training benefits from the temporal bias fix
- ✅ Simplest change, minimal code impact
- ⚠️ Val/test may contain unreliable negatives (published within the observation window but not in KEV). This is acceptable for evaluation purposes — the model's ability to predict exploitation risk on recent CVEs is precisely what we want to measure.

### Fix 2: Window anchored to TRAIN_CUTOFF instead of DATE_END

**Strategy:** Compute the observation window relative to `TRAIN_CUTOFF` (2023-06-30) instead of `DATE_END` (2024-12-31).

```python
obs_cutoff = datetime.strptime(TRAIN_CUTOFF, "%Y-%m-%d") - timedelta(days=obs_window_days)
```

**Tradeoffs:**
- ✅ Keeps the global filter approach
- ✅ Training negatives from after ~2021-07-24 would be excluded (instead of after 2023-01-25)
- ⚠️ Val/test would still be affected if the window extends into their period (less likely with a shorter relative window)
- ⚠️ Changes the training set size significantly

### Fix 3: Cap the observation window to val/test boundary

**Strategy:** Ensure the observation cutoff does not extend into the val/test period.

```python
# After computing obs_cutoff, clamp it to TRAIN_CUTOFF
obs_cutoff = min(obs_cutoff, datetime.strptime(TRAIN_CUTOFF, "%Y-%m-%d"))
```

**Tradeoffs:**
- ✅ Prevents any val/test contamination
- ⚠️ Artificially shortens the observation window for training
- ⚠️ Some unreliable negatives may leak into training

---

## How to Verify a Fix

Run the gather pipeline and check the quality report:

```bash
source backend/.venv/bin/activate
cd backend
python -m ml.train_xgboost --gather
```

Expected output after fix:
- Val set: should have both positives AND negatives (not 100% positive)
- Test set: should have both positives AND negatives (not 100% positive)
- The val set should have significantly more than 81 records
- The test set should have significantly more than 125 records
- Positive rate in val/test should be closer to the overall population rate (~0.5-1%)

Specific numbers to verify:
- Val set size should be ~14,000-15,000 (not 81)
- Test set size should be ~39,000 (not 125)
- Val positive rate should be ~0.5-1% (not 100%)
- Test positive rate should be ~0.4-0.6% (not 100%)

Also verify with `print_quality_report()` — the data quality report at the end of `phase_gather()` should show balanced val/test splits.

---

## Additional Findings (Out of Scope, But Noted)

1. **The enriched_cves.json extends to 2026-07** but `DATE_END` in the current code is hardcoded to `2024-12-31`. The observation window computation uses 2024-12-31, which means CVEs from 2025-2026 are all treated as "too recent" and all their negatives are dropped — but this doesn't cause current issues because the split cutoffs (TRAIN_CUTOFF=2023-06-30, VAL_CUTOFF=2023-12-31) already exclude them.

2. **397 KEV entries excluded** as "future KEV" (dateAdded after 2024-12-31). This is correct behavior for the point-in-time label fix (v2.3), but the count may grow over time as more KEV entries are added for pre-2025 CVEs.

3. **The median KEV lag of 706 days** is inflated by historical KEV additions for very old CVEs. A more representative window might use the median lag for CVEs published in the last 3 years only, or use a percentile-based approach.
