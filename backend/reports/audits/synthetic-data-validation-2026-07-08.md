# Synthetic Data Validation Report

**Date:** 2026-07-08
**Total rows checked:** 3665
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

**Detail:** Most common vector appears 28/3665 times (threshold: 366). Unique vectors: 2618.

### 6. Hostname format

**Status:** ✅ PASS

**Detail:** Found 0 rows with invalid hostname format.

### 7. Label distribution

**Status:** ✅ PASS

**Detail:** Distribution — MP: {'Peripheral': 847, 'Core': 1784, 'Support': 1034}, WI: {'Minimal': 1351, 'Moderate': 1018, 'Severe': 1296}. Threshold (80%): 2932.

### 8. Research traceability

**Status:** ✅ PASS

**Detail:** Checked 3665 rows with references. Found 0 orphan references.

### 9. Confidence bounds

**Status:** ✅ PASS

**Detail:** Found 0 rows with out-of-bounds confidence values.

### 10. Blind holdout integrity

**Status:** ✅ PASS

**Detail:** Holdout: 708/3665 (19.3%). Target range: 15-25%.


---

### Label Distribution

| Dimension | Value | Count | % |
|---|---|---:|--:|
| mission_prevalence | Core | 1784 | 48.7% |
| mission_prevalence | Peripheral | 847 | 23.1% |
| mission_prevalence | Support | 1034 | 28.2% |
| mission_prevalence | **Total** | **3665** | |

| public_wellbeing_impact | Minimal | 1351 | 36.9% |
| public_wellbeing_impact | Moderate | 1018 | 27.8% |
| public_wellbeing_impact | Severe | 1296 | 35.4% |
| public_wellbeing_impact | **Total** | **3665** | |

---

## Overall: **PASSED**
