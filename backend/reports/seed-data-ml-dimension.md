# Seed Data ML Dimension Verification Report

**Date:** 2026-07-08
**Task:** Item D — Verify `ml_exploitation_contribution` in seed data demo rows

---

## 1. Column Definition

| Attribute | Value |
|---|---|
| **Column name** | `ml_exploitation_contribution` |
| **Migration** | `backend/alembic/versions/005_add_ml_exploitation.py` |
| **Type** | `INTEGER` |
| **Default** | `0` |
| **Purpose** | Stores the ML Exploitation Probability Contribution dimension of the 6-dimensional priority score (0–100). Represents the XGBoost model's exploitation probability (0–1) mapped to a 0–10 scale. |

### Formula (from `backend/scoring.py` lines 57–63)

```python
ml_exploitation = 0
if tier_1_result and tier_1_result.get("exploitation_probability") is not None:
    ml_exploitation = _round_half_up(tier_1_result["exploitation_probability"] * 10)
```

Where `_round_half_up(x)` = `int(x + 0.5)` (always rounds .5 up, no banker's rounding).

**Key rule:** If Tier 1 was not executed (e.g., auto-resolved at Tier 0), the value MUST be 0.

---

## 2. Seed Data Population

`backend/seed_data.py` **does** populate `ml_exploitation_contribution` for all 7 demo rows. Each row has a hardcoded value that should match the formula `_round_half_up(tier_1_exploitation_prob * 10)` for rows where Tier 1 ran, or 0 where it did not.

---

## 3. Actual Values Found in Database

After re-seeding, the following values were confirmed:

| # | CVE | CVSS | Tier 1 Executed? | T1 Exploit Prob | ML Contribution Expected | ML Contribution Stored | Match? |
|---|---|---|---|---|---|---|---|
| 1 | CVE-2023-34362 | 9.8 | No (auto-resolved) | `None` | 0 | 0 | ✓ |
| 2 | CVE-2023-4966 | 9.4 | No (auto-resolved) | `None` | 0 | 0 | ✓ |
| 3 | CVE-2023-27350 | 9.8 | Yes | 0.83 | 8 | 8 | ✓ |
| 4 | CVE-2024-1709 | 10.0 | Yes | 0.71 | 7 | 7 | ✓ |
| 5 | CVE-2023-36884 | 7.8 | Yes | 0.65 | 7 | **7** | ✓ |
| 6 | CVE-2023-22515 | 10.0 | Yes | 0.72 | 7 | 7 | ✓ |
| 7 | CVE-2022-47966 | 9.8 | Yes | 0.63 | 6 | 6 | ✓ |

> **Note:** Row 5 was initially stored as 6 but has been corrected to 7 (see §5).

### Plausibility Assessment

- **Rows 1–2** (auto-resolved at Tier 0): `ml_exploitation_contribution = 0`. Correct — Tier 1 was not executed, per `scoring.py` line 59 comment.
- **Rows 3–7** (Tier 1 executed): Values range from 6–8, correlating with exploitation probabilities of 0.63–0.83. These are all within plausible bounds (0–10 scale mapped from 0–1 probability).
- **Correlation with CVSS:** The values are driven by the ML model's probability prediction, not directly by CVSS. The range 6–8 is consistent for CVSS scores 7.8–10.0.

---

## 4. Bug Found and Fix Applied

### Bug Description

**Row 5 (CVE-2023-36884):** `ml_exploitation_contribution` was set to **6** in seed data, but the scoring formula `_round_half_up(0.65 × 10)` = `_round_half_up(6.5)` = `int(6.5 + 0.5)` = **7**.

The value `6` was off by 1 from the correct formula output.

### Scope

| Affected field | Old value | New value |
|---|---|---|
| `ml_exploitation_contribution` (column) | 6 | 7 |
| `scoring_weights_json` → ML Exploitation → `awarded` | 6 | 7 |

### Fix Applied

Two changes in `backend/seed_data.py`:

1. **Line 764:** Changed `"ml_exploitation_contribution": 6` → `"ml_exploitation_contribution": 7` for the CVE-2023-36884 row.
2. **Line 843:** Changed `"awarded": 6` → `"awarded": 7` in the corresponding `scoring_weights_json` entry to keep the display metadata in sync with the column value.

### Post-Fix Verification

After re-seeding, all 7 rows now pass the formula check:
```
CVE-2023-34362       | None     | 0  | 0  | ✓
CVE-2023-4966        | None     | 0  | 0  | ✓
CVE-2023-27350       | 0.83     | 8  | 8  | ✓
CVE-2024-1709        | 0.71     | 7  | 7  | ✓
CVE-2023-36884       | 0.65     | 7  | 7  | ✓  ← fixed
CVE-2023-22515       | 0.72     | 7  | 7  | ✓
CVE-2022-47966       | 0.63     | 6  | 6  | ✓
```

---

## 5. Files Modified

| File | Change |
|---|---|
| `backend/seed_data.py` | Corrected `ml_exploitation_contribution` from 6 → 7 for CVE-2023-36884; updated `scoring_weights_json` `awarded` field accordingly |

**No other files were modified.**

---

## 6. Conclusion

The `ml_exploitation_contribution` column is now correctly populated across all 7 seed data rows. A single off-by-one bug in Row 5 was identified and fixed. All values match the scoring formula `_round_half_up(exploitation_prob × 10)` and are within plausible ranges (0–8 on a 0–10 scale).
