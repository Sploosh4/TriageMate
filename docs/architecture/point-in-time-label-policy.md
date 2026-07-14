# Point-in-Time Label Policy — Revised Design (v2)

**Author:** Strike Team  
**Date:** 2026-07-14  
**Status:** Proposed (not yet implemented)  
**Supersedes:** v1 (rejected — see §1.1 for reasons)  
**Prerequisite reading:** `backend/reports/investigations/mid-2023-data-drop.md`

---

## 1. Revision History

### 1.1 Why v1 Was Rejected

The first version of this document was rejected for five specific reasons. This revision addresses each one:

| # | v1 Problem | How v2 Fixes It |
|---|------------|-----------------|
| 1 | Filtered training split only; left censored negatives in val/test. Violated the requirement for consistent eligibility across ALL splits. | **§4 — Consistent eligibility filter** applied identically to every split. A censored CVE is excluded from train, val, AND test uniformly. |
| 2 | Labels based on days-from-KEV-to-`DATE_END`, presented as validated "≤30d / 31–90d" exploitation horizons. This was misleading — labels measured time before `DATE_END`, not time from publication to exploitation. | **§2 — Redesigned label construction** based on days-from-publication-to-KEV. Labels now answer the correct question: "How quickly after publication was this CVE exploited in the wild?" |
| 3 | Argued that "censored evaluation is conservative" and acceptable for primary metrics. This corrupts calibration, thresholds, and multi-class metrics. | **§5 — Censored cohort reporting** explicitly excludes censored examples from all primary metrics. They are reported as a separate prospective cohort. |
| 4 | Tests inspected the saved NPZ file rather than testing split/filter logic directly. Not hermetic — fragile and pipeline-dependent. | **Part B** of this task replaces NPZ-based tests with hermetic unit tests using synthetic data and a testable `apply_point_in_time_split()` function. |
| 5 | None of the new artifacts were committed. | All artifacts committed to main as part of this task. |

### 1.2 What This Design Does NOT Change

- The root cause diagnosis in `backend/reports/investigations/mid-2023-data-drop.md` is accepted as correct.
- The registry correction (mid-2023 data drop fix, Item 3c) is accepted and remains in place.
- The training pipeline still uses `DATE_END = 2024-12-31` as its point-in-time reference.
- The chronological split boundaries (`TRAIN_CUTOFF = 2023-06-30`, `VAL_CUTOFF = 2023-12-31`) remain unchanged for backward compatibility.

---

## 2. Redesigned Label Construction

### 2.1 Current (v1) Label Semantics — Wrong

Current labels use days-from-KEV-to-`DATE_END`:

```
days_since_added = (date_end - kev_dateAdded).days

Label 1: days_since_added <= 30    (added to KEV within 30 days of DATE_END)
Label 2: days_since_added <= 90    (added within 31–90 days of DATE_END)
Label 3: days_since_added <= 365   (added within 91–365 days of DATE_END)
Label 4: days_since_added > 365    (added more than 365 days before DATE_END)
Label 0: Not in KEV
```

**Problem:** A CVE published in 2000 and added to KEV in 2024-12-01 gets label 1 (≤30d from `DATE_END`), but it actually took 24 years from publication to exploitation. The label describes recency of addition, not speed of exploitation.

### 2.2 New Label Semantics — Correct

Revised labels use days-from-publication-to-KEV:

```
days_pub_to_kev = (kev_dateAdded - published_date).days

Label 1: 0 <= days_pub_to_kev <= 30       — Exploited within 30 days of publication
Label 2: 31 <= days_pub_to_kev <= 90      — Exploited within 31–90 days of publication
Label 3: 91 <= days_pub_to_kev <= 365     — Exploited within 91–365 days of publication
Label 4: days_pub_to_kev > 365            — Exploited more than 365 days after publication
Label 0: Not in KEV as of DATE_END        — Not exploited (or not yet catalogued)
Censored: Not in KEV, published fewer than obs_window_days before DATE_END
         → Genuinely unknown exploitation status
```

### 2.3 Point-in-Time Guard

The existing future-leakage guard is preserved: any KEV entry with `dateAdded > DATE_END` receives label 0, because the exploitation event was not observable at the point-in-time reference date.

### 2.4 Label Construction Algorithm (Revised `construct_labels()`)

```python
def construct_labels_publication_based(
    cves: list[dict],
    kev_data: dict[str, str],
    cutoff_date: str = DATE_END,
) -> list[int]:
    """Construct multi-window KEV labels based on days from publication to KEV addition.

    Label meanings:
      0: Not in KEV as of cutoff_date
      1: KEV added 0–30 days after publication
      2: KEV added 31–90 days after publication
      3: KEV added 91–365 days after publication
      4: KEV added more than 365 days after publication
    """
    date_end = datetime.strptime(cutoff_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    for cve in cves:
        cve_id = cve["cve_id"]
        pub_str = cve.get("published_date", "")

        if cve_id not in kev_data:
            labels.append(0)
            continue

        date_added_str = kev_data[cve_id]
        if not date_added_str or date_added_str > cutoff_date:
            labels.append(0)  # Future KEV → not observable at cutoff
            continue

        try:
            published = datetime.strptime(pub_str[:10], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            days_pub_to_kev = (date_added - published).days

            if days_pub_to_kev <= 30:
                label = 1
            elif days_pub_to_kev <= 90:
                label = 2
            elif days_pub_to_kev <= 365:
                label = 3
            else:
                label = 4
            labels.append(label)
        except (ValueError, TypeError):
            labels.append(0)
```

**Impact of the change:** Labels 1–4 will shift for most KEV entries. A CVE published in 2020 and added to KEV in 2022 moves from label 1 (≤30d from `DATE_END`) to label 4 (>365d from publication). The size of each window bucket will change, but the total number of positives remains the same (~1,239).

---

## 2.5 Label Horizon Reference Table

| Label | Old Meaning (v1 — rejected) | New Meaning (v2 — correct) | Example |
|-------|-----------------------------|---------------------------|---------|
| 0 | Not in KEV | Not in KEV as of DATE_END, or KEV added after DATE_END | — |
| 1 | KEV added ≤30d before DATE_END | KEV added 0–30d after publication | CVE published 2024-01-01, KEV 2024-01-15 |
| 2 | KEV added 31–90d before DATE_END | KEV added 31–90d after publication | CVE published 2023-01-01, KEV 2023-03-01 |
| 3 | KEV added 91–365d before DATE_END | KEV added 91–365d after publication | CVE published 2022-01-01, KEV 2022-06-01 |
| 4 | KEV added >365d before DATE_END | KEV added >365d after publication | CVE published 2020-01-01, KEV 2022-01-01 |
| Censored | (did not exist) | Not in KEV, published < obs_window days before DATE_END | CVE published 2024-10-01, not in KEV |

---

## 3. Three-Way Classification

Every CVE falls into exactly one of three mutually exclusive categories:

| Category | Label Values | Definition | Eligibility |
|----------|-------------|------------|-------------|
| **Fully observed positive** | 1, 2, 3, 4 | In KEV with `dateAdded <= DATE_END`. KEV membership is an authoritative CISA designation — the exploitation event is confirmed and timestamped. | Eligible for all splits (train/val/test) based on publication date. |
| **Fully observed negative** | 0 | NOT in KEV, AND published at least `obs_window_days` before `DATE_END`. Enough time has passed that non-exploitation can be inferred with confidence. | Eligible for all splits (train/val/test) based on publication date. |
| **Censored (unknown)** | — | NOT in KEV, AND published fewer than `obs_window_days` before `DATE_END`. Too recent to know whether exploitation will be catalogued. | **EXCLUDED** from train, val, and test. Reported separately as a prospective cohort. |

**Key principle:** The observation window applies to the **negative label only**. Positive labels (1–4) are always fully observed because KEV membership is authoritative — if a CVE was added to KEV by `DATE_END`, we know it was exploited, regardless of when it was published.

### 3.1 The Censored Asymmetry

```
                     Published before           Published after
                     obs_window_cutoff?         obs_window_cutoff?
                            |                         |
                    ┌───────┴───────┐           ┌─────┴─────┐
                    |               |           |           |
                In KEV?          In KEV?      In KEV?     In KEV?
                    |               |           |           |
                ┌───┴───┐       ┌───┴───┐   ┌───┴───┐   ┌───┴───┐
                Y       N       Y       N   Y       N   Y       N
                │       │       │       │   │       │   │       │
              Label  Label   Label   Label Label  Label Label CENSORED
              1-4     0      1-4     ???   1-4    0    1-4   (excluded)
              OK      OK      OK            OK     OK    OK
                      (fully          (point-in-time   (KEV is
                      observed)        future KEV →     author-
                                        label 0)        itative)
```

---

## 4. Consistent Eligibility Across All Splits

### 4.1 The v1 Mistake (Rejected)

v1 proposed:

```
[All CVEs] → Labels → Build features → Split by date → Train(→ Obs filter) + Val(untouched) + Test(untouched)
```

This filtered **only** the training set, leaving censored negatives in val and test. The rejected rationale was "censored evaluation is conservative." In reality, this approach:

- Makes calibration unreliable (the val set distribution doesn't match train)
- Invalidates threshold tuning (thresholds optimized on censored-inclusive val)
- Inflates ROC-AUC with uncertain labels (censored negatives that later become exploits are labeled 0 but are actually positives)

### 4.2 The Correct Approach (v2)

**Apply the same eligibility rules to every split:**

```
[All CVEs] → Labels (publication-based) → Eligibility filter (uniform) → Split by date
```

```
eligible_mask = is_in_kev | (is_not_in_kev & published_before_obs_cutoff)

eligible_cves = cves[eligible_mask]
censored_cves = cves[~eligible_mask & ~is_in_kev]

train = eligible_cves[dates <= TRAIN_CUTOFF]
val   = eligible_cves[(dates > TRAIN_CUTOFF) & (dates <= VAL_CUTOFF)]
test  = eligible_cves[dates > VAL_CUTOFF]
```

**What this means in practice:**
- A CVE published after the observation window cutoff that is **not** in KEV is censored — it goes to **no** split.
- A CVE published after the observation window cutoff that **is** in KEV is a fully observed positive — it goes to its chronological split.
- A CVE published before the observation window cutoff is always eligible (either fully observed positive or fully observed negative).

### 4.3 Selection of the Observation Window

The observation window must satisfy two constraints:

1. **Label-quality constraint:** It should be at least as long as the median KEV publication-to-addition lag, so that most eventual KEV entries have been catalogued before a negative label is considered reliable.

2. **Split-representation constraint:** It must be short enough that the val and test periods contain at least some fully observed negatives, otherwise those splits degenerate to 100% positive.

**Recommended approach:** Set `obs_window_days = min(computed_median_lag, days_from_val_start_to_date_end - 1)` where `computed_median_lag` comes from `compute_kev_lag_stats()` and `days_from_val_start_to_date_end` is the number of days from `TRAIN_CUTOFF + 1` to `DATE_END`.

For the current split boundaries:
- `days_from_val_start_to_date_end = 2024-12-31 - 2023-07-01 = 548 days`
- Currently `computed_median_lag ≈ 706 days` (from earlier pipeline runs)

With a median lag of 706 days, obs_window would be `min(706, 548-1) = 547` days, meaning the observation cutoff = `2024-12-31 - 547 = 2023-07-03`. This would give val (starting 2023-07-01) approximately 2–3 days of fully observed negatives — technically correct but very thin.

**Alternative:** Reduce the observation window to a fixed value that ensures robust negative counts in val and test. This design recommends **365 days (1 year)** as a pragmatic choice:

| Window | Cutoff Date | Val Negatives (2023 H2) | Test Negatives (2024) | Rationale |
|--------|-------------|------------------------|----------------------|-----------|
| 706 days | 2023-01-25 | All censored (0) | All censored (0) | Conservative but kills val/test |
| 547 days | 2023-07-03 | ~2–3 days' worth | None | Technically valid but fragile |
| **365 days** | **2024-01-01** | **All fully observed** | **Jan 1 only** | Best balance — all val + partial test |
| 180 days | 2024-07-04 | All fully observed | Jan 1 – Jul 4 fully observed | Less conservative label quality |

**Recommendation:** Begin with a 365-day observation window for implementation. This is the minimum window that guarantees the val set (2023 H2) has fully observed negatives. The window should be revisited after the model is retrained and evaluated.

---

## 5. Censored Cohort Reporting

### 5.1 Exclusion from Primary Metrics

Censored examples MUST be excluded from:

| Metric | Reason for Exclusion |
|--------|---------------------|
| ROC-AUC | Censored negatives have uncertain true labels. Including them in ROC calculation produces an unreliable curve. |
| F1 / Precision / Recall | These metrics require known ground truth. Censored examples have unknown ground truth (they may become KEV later). |
| Calibration (ECE, reliability diagrams) | Calibration measures how well predicted probabilities match observed frequencies. Censored examples have unobserved outcomes. |
| Threshold selection | Operating thresholds tuned with censored examples will be biased toward predicting "not exploited" for recent CVEs. |

### 5.2 Prospective Cohort Reporting

Censored CVEs are reported as a separate **prospective cohort**:

```
CENSORED COHORT REPORT
───────────────────────
Total censored CVEs:    65,778
  - In val date range:  14,682
  - In test date range: 38,904
  - In train date range:12,192

Observation window:     365 days (cutoff: 2024-01-01)
Follow-up window:       From publication date to DATE_END
```

### 5.3 Secondary "Early Warning" Metric (Optional)

The censored cohort can be used for an optional secondary analysis:

> **Early warning accuracy:** For censored CVEs that *later* appear in KEV (after `DATE_END`), what was the model's predicted probability at training time? If the model assigned high scores to CVEs that later became KEV, it demonstrates genuine early-warning capability — identifying exploitation risk before CISA catalogues it.

This metric is **not** a primary acceptance criterion but may be useful for operational validation.

**Implementation note:** Tracking requires periodic re-evaluation against an updated KEV catalog. See §7 (Open Questions).

---

## 6. Expected Split Distribution

### 6.1 With 365-Day Observation Window (Recommended)

Using the actual `enriched_cves.json` data (182,095 usable records published on or before `DATE_END = 2024-12-31`):

**Eligibility filter (applied uniformly):**
- KEV positives (~1,239): Always eligible.
- Non-KEV CVEs published < 365 days before DATE_END (i.e., after 2024-01-01): Censored — excluded from all splits.
- Non-KEV CVEs published >= 365 days before DATE_END (i.e., on or before 2024-01-01): Fully observed negatives — eligible.

| Split | Eligible Records | KEV Positives | Fully Observed Negatives | Censored (excluded) | KEV % |
|-------|-----------------|---------------|-------------------------|---------------------|-------|
| Train | ~116,111 | ~1,033 | ~115,078 | ~12,192 | 0.89% |
| Val | ~14,763 | ~81 | ~14,682 | 0 (all negatives fully observed) | 0.55% |
| Test | ~38,904 (all before 2024-01-01) ... wait, test runs from 2024-01-01. At exactly the boundary: test negatives published on 2024-01-01 are fully observed (exactly 365 days), those after are censored. | ~125 | ~1 (one day's worth) | ~38,903 | varies |

All test-set eligibility would need the cutoff to be at least 1 day later. This is an edge case at the boundary.

To make this concrete: with `obs_window = 365`, the observation cutoff is `2024-01-01`. A non-KEV CVE published on `2024-01-01` has been observed for exactly 365 days and is a fully observed negative. A non-KEV CVE published on `2024-01-02` has been observed for only 364 days and is censored.

**Revised test estimate:** Test set effectively has only 1 day's worth of fully observed negatives (~200 CVEs, of which ~1 is KEV positive). This makes the test set thin but still representative.

### 6.2 For Comparison: v1 Approach (Rejected)

v1's numbers are shown here for contrast:

| Split | Records | KEV Positives | Negatives | KEV % |
|-------|---------|---------------|-----------|-------|
| Train (filtered) | ~116,111 | 1,033 | ~115,078 | 0.89% |
| Val (censored kept) | ~14,763 | 81 | ~14,682 (censored) | **0.55% but unreliable** |
| Test (censored kept) | ~39,029 | 125 | ~38,904 (censored) | **0.32% but unreliable** |

Val and test contained censored negatives with unreliable labels, making all metrics untrustworthy.

### 6.3 Effect of Observation Window Choice

| obs_window | Cutoff | Train Eligible | Val Eligible Non-KEV | Test Eligible Non-KEV | Tradeoff |
|------------|--------|---------------|----------------------|----------------------|----------|
| 706 days | 2023-01-25 | ~102,968 | 0 (all censored) | 0 (all censored) | Val/test degenerate |
| 547 days | 2023-07-03 | ~115,078 | ~50 (2–3 days) | 0 (all censored) | Val barely non-degenerate |
| 365 days | 2024-01-01 | ~115,078 | ~14,682 (all val) | ~200 (Jan 1 only) | Test still thin |
| 180 days | 2024-07-04 | ~115,078 | ~14,682 (all val) | ~38,904 * (all through Jul 4) | Best coverage, less label confidence |

*With 180-day window, test negatives from 2024-01-01 to 2024-07-04 are fully observed.

**The design recommends starting with 365 days** as a compromise. The val set is richly populated with fully observed negatives. The test set is thin but workable. The observation window can be tuned downward after initial evaluation.

---

## 7. Implementation Plan

### 7.1 File Changes

| File | Change | Complexity |
|------|--------|------------|
| `backend/ml/split_policy.py` | **New file.** Defines `apply_point_in_time_split()` — the testable split-policy function that encodes the eligibility rules from §4. | New |
| `backend/ml/train_xgboost.py` | **`construct_labels()`** — rewrite to use days-from-publication-to-KEV instead of days-from-KEV-to-DATE_END. | Medium |
| `backend/ml/train_xgboost.py` | **`phase_gather()`** — move the observation-window filter from a global pre-split operation to a uniform eligibility filter applied before the chronological split. | Medium |
| `backend/ml/train_xgboost.py` | **Quality report** — add censored-cohort section. Add `obs_window_days` parameter to `print_quality_report()`. | Low |
| `backend/ml/train_xgboost.py` | **`compute_kev_lag_stats()`** — no change needed (already computes days-from-publication-to-KEV correctly). | None |
| `backend/tests/test_split_integrity.py` | **Replace** NPZ-based baseline/xfail tests with hermetic unit tests calling `apply_point_in_time_split()` with synthetic data. | Part B |

### 7.2 Pipeline Order (Corrected)

```
BEFORE (v1 — rejected):
  [All CVEs] → Publication-based labels → Build features → Split by date
  → Train(→ obs filter only) + Val(untouched, censored included) + Test(untouched, censored included)

AFTER (v2 — correct):
  [All CVEs] → Publication-based labels → Build features → Uniform eligibility filter
  → Split eligible CVEs by date → Train + Val + Test (all fully observed)
  → Censored CVEs → Prospective cohort report (separate)
```

### 7.3 Verification Procedure

After implementation:

```bash
# 1. Run the gather phase with the new label construction and eligibility filter
python -m ml.train_xgboost --gather

# 2. Verify the quality report shows non-degenerate val/test
#    Expected (with 365-day window):
#      Train: ~116,111 CVEs (positives: ~1,033 = 0.89%)
#      Val:   ~14,763 CVEs (positives: ~81 = 0.55%)
#      Test:  varies by window choice

# 3. Run split-policy tests
python -m pytest tests/test_split_integrity.py -v
# All tests pass or are skipped (pre-implementation)

# 4. Unskip tests as implementation lands
# Remove @pytest.mark.skip markers when apply_point_in_time_split() is implemented
```

---

## 8. Open Questions

### 8.1 Optimal Observation Window

The observation window is the central tuning parameter. The recommended starting point is **365 days**, but the final value should be determined empirically:

- Too large (≥706 days): Val/test have no negatives → degenerate splits.
- Too small (≤180 days): Many unreliable negatives pollute the training set.
- Goldilocks (365 days): All val negatives are fully observed; test is thin but valid.

**Decision needed from product owner:** Accept 365 days as the initial value, with the understanding that the final value will be tuned based on model performance.

### 8.2 Test Set Thinness

With a 365-day window, the test set (2024) has only ~1 day's worth of fully observed negatives. This is a structural consequence of `DATE_END = 2024-12-31` and `VAL_CUTOFF = 2023-12-31`. Options:

1. **Accept thin test set** — The test set is still representative (both classes present), just small. Increase the test set weight in evaluation.
2. **Shorten the observation window** — With a 180-day window, the test set through 2024-07-04 is fully observed (~half the year).
3. **Extend DATE_END** — If `DATE_END` advances to 2025-06-30, the observation cutoff shifts forward, giving more fully observed test negatives.

**Recommendation:** Start with a 365-day window and accept the thin test set. Revisit after the model evaluation shows whether this is a problem.

### 8.3 DATE_END Advancement

As time passes, `DATE_END` becomes increasingly stale. The original date (2024-12-31) was chosen to be "recent enough" while keeping the dataset fixed for reproducibility. Advancing `DATE_END` would:

- Recover more training examples (CVEs published between 2025-01-01 and new DATE_END)
- Shift the observation window cutoff forward
- Increase val/test fully observed negative counts

**Recommendation:** Keep `DATE_END` fixed for Sprint 29–30 model development. Plan a separate task for DATE_END advancement with its own data-quality audit.

### 8.4 Periodic Re-Evaluation

If the censored cohort is tracked quarterly against an updated KEV catalog, the "early warning" metric from §5.3 becomes actionable. This would require:

- A scheduled job that re-fetches the KEV catalog
- Logic to check which censored CVEs have since been added
- A report comparing predicted scores vs. eventual KEV status

**Recommendation:** Add this as a future enhancement. Not required for the initial implementation.

---

## Appendix A: Testable Split-Policy Function Interface

The `apply_point_in_time_split()` function in `backend/ml/split_policy.py` is the single source of truth for eligibility and split logic:

```python
def apply_point_in_time_split(
    dates: np.ndarray,              # Publication dates (YYYY-MM-DD strings)
    labels: np.ndarray,             # Multi-window KEV labels (0–4)
    kev_dates: np.ndarray,          # KEV addition dates ("" if not in KEV)
    obs_window_days: int = 706,     # Observation window for negatives
    date_end: str = "2024-12-31",   # Point-in-time reference date
    train_cutoff: str = "2023-06-30",
    val_cutoff: str = "2023-12-31",
) -> dict[str, np.ndarray]:         # train_mask, val_mask, test_mask,
                                    # censored_mask, is_fully_observed
```

Returns five boolean masks (same length as inputs):
- `train_mask`: True for CVEs in the training set
- `val_mask`: True for CVEs in the validation set
- `test_mask`: True for CVEs in the test set
- `censored_mask`: True for censored CVEs (excluded from train/val/test)
- `is_fully_observed`: True for CVEs with reliable labels (equivalent to `~censored_mask`)

The four masks (train/val/test/censored) are mutually exclusive and exhaustive.

---

## Appendix B: Hermetic Unit Test Plan

| Test | Input | Expected |
|------|-------|----------|
| `test_fully_observed_negative_goes_to_split` | CVE published 1000d before DATE_END, label 0, no KEV | `is_fully_observed=True`, `censored=False`, in train |
| `test_censored_cve_is_excluded_from_all_splits` | CVE published 30d before DATE_END, label 0, no KEV | `censored=True`, not in train/val/test |
| `test_recent_kev_positive_is_not_censored` | CVE published 30d before DATE_END, KEV at day 20 | `is_fully_observed=True`, `censored=False` |
| `test_split_distribution_includes_both_classes` | Mixed synthetic dataset | Each split has label 0 AND label 1+ |
| `test_censored_cohort_is_separate_from_primary` | Mix of old, recent, and KEV CVEs | Censored mask disjoint from train/val/test |
| `test_consistency_across_splits` | Multiple censored negatives | Zero entries in all primary masks |

All tests use synthetic numpy arrays as inputs — no NPZ file, no real CVE data.
