# Synthetic Data Validation Report

**Date:** 2026-07-08
**Total rows checked:** 3442
**Rows with failures:** 0
**Checks passed:** 10/10
**Checks failed:** 0/10
**Overall:** **PASSED**

---

## Per-Check Breakdown

| # | Check | Rows Failed | Status |
|---|---:|---:|:---:|
| 1. | 1. Duplicate hostnames | 0 | ✅ PASS |
| 2. | 2. Required fields | 0 | ✅ PASS |
| 3. | 3. Label validity | 0 | ✅ PASS |
| 4. | 4. Feature extraction | 0 | ✅ PASS |
| 5. | 5. Feature vector diversity | 0 | ✅ PASS |
| 6. | 6. Hostname format | 0 | ✅ PASS |
| 7. | 7. Label distribution | 0 | ✅ PASS |
| 8. | 8. Research traceability | 0 | ✅ PASS |
| 9. | 9. Confidence bounds | 0 | ✅ PASS |
| 10. | 10. Blind holdout integrity | 0 | ✅ PASS |

---

## Check Details

### 1. Duplicate hostnames

**Status:** ✅ PASS

**Detail:** Found 0 duplicate hostnames.

### 2. Required fields

**Status:** ✅ PASS

**Detail:** Found 0 rows with missing required fields.

### 3. Label validity

**Status:** ✅ PASS

**Detail:** Found 0 rows with invalid label values.

### 4. Feature extraction

**Status:** ✅ PASS

**Detail:** Found 0 hostnames that failed feature extraction.

### 5. Feature vector diversity

**Status:** ✅ PASS

**Detail:** Most common vector appears 26/3442 times (threshold: 344). Unique vectors: 2456.

### 6. Hostname format

**Status:** ✅ PASS

**Detail:** Found 0 rows with invalid hostname format.

### 7. Label distribution

**Status:** ✅ PASS

**Detail:** Distribution — MP: {'Peripheral': 794, 'Core': 1655, 'Support': 993}, WI: {'Minimal': 1285, 'Moderate': 966, 'Severe': 1191}. Threshold (80%): 2754.

### 8. Research traceability

**Status:** ✅ PASS

**Detail:** Checked 3442 rows with references. Found 0 orphan references.

### 9. Confidence bounds

**Status:** ✅ PASS

**Detail:** Found 0 rows with out-of-bounds confidence values.

### 10. Blind holdout integrity

**Status:** ✅ PASS

**Detail:** Holdout: 660/3442 (19.2%). Target range: 15-25%.


---

### Label Distribution

| Dimension | Value | Count | % |
|---|---|---:|--:|
| mission_prevalence | Core | 1655 | 48.1% |
| mission_prevalence | Peripheral | 794 | 23.1% |
| mission_prevalence | Support | 993 | 28.8% |
| mission_prevalence | **Total** | **3442** | |

| public_wellbeing_impact | Minimal | 1285 | 37.3% |
| public_wellbeing_impact | Moderate | 966 | 28.1% |
| public_wellbeing_impact | Severe | 1191 | 34.6% |
| public_wellbeing_impact | **Total** | **3442** | |

---

## Overall: **PASSED**
