# Scoring Weight Design

**Status:** CURRENT (10 July 2026)
**Source:** `backend/scoring.py`

## Weight Summary

| Dimension | Max Points | Rationale |
|-----------|-----------|-----------|
| CVSS Base Score | 40 | Severity of the vulnerability itself (CVSS v3.1 / 10 × 40) |
| EPSS Exploitability | 20 | Real-world exploitation probability (score × 20, may be substituted by sector-aware model) |
| Asset Criticality | 20 | Data classification + mission prevalence + public wellbeing impact |
| Exposure & Network Position | 12 | Internet-facing vs internal + lateral reachability |
| Patch/Remediation | 5 | Patch available + applied status |
| ML Exploitation Probability | 10 | XGBoost model prediction (only when Tier 1 runs) |
| **Total** | **107** | Clamped to 0–100 |

Note: Security Context was removed as a scored dimension in Sprint 21. It is now a proportional multiplier (see below).

## Design Rationale

**CVSS heaviest (40 pts):** The CVSS base score is the most mature and standardized vulnerability severity signal in the industry. It provides a consistent 0–10 scale backed by FIRST/CVSS SIG governance, making it the natural anchor for the scoring system. Converting CVSS 0–10 → 0–40 gives the dimension enough dynamic range to differentiate between CVSS 9.8 and CVSS 9.1 (39 vs 36 points).

**EPSS second (20 pts):** EPSS captures real-world exploitation probability, which is orthogonal to CVSS severity. Many high-CVSS vulnerabilities are never exploited, and some low-CVSS vulnerabilities are weaponised in-the-wild. EPSS weights the score toward actionable risk. When the raw EPSS is missing or unreliable, the sector-aware EPSS substitution model (v4 → v3 → v2 → v1 → heuristic rule engine) fills in.

**Asset Criticality (20 pts):** Ties the score to WA government data classification (WAICP) and mission context. "Core" government services handling OFFICIAL Sensitive data with severe public wellbeing impact should score higher than a peripheral system with OFFICIAL data, even if both have the same CVE. The 12/4/0 spread for OFFICIAL Sensitive/OFFICIAL/unclassified is an operational policy choice, not mandated by WAICP itself.

**Exposure (12 pts):** Internet-facing systems are at much higher risk of discovery and exploitation than internal-only assets. The code produces 12 points for internet-facing and 3 for internal, reflecting this gap.

**ML Exploitation Probability (10 pts):** The XGBoost model (419-dim, ROC-AUC 0.9459) provides a nuanced exploitation probability prediction. This dimension only contributes when Tier 1 runs — auto-resolved CVEs at Tier 0 bypass it. The 10-point allocation reflects that the ML signal is powerful but supplementary to the mature CVSS/EPSS signals.

**Patch/Remediation (5 pts):** A small modifier recognising that patch status matters but should not dominate the score. Full remediation (patch available + applied) earns 5 points. A patch available but not applied scores 0 (overdue). No patch available scores 0 (neutral, not punitive — the vulnerability is unmitigated but not due to negligence).

## Context Multiplier (Sprint 21)

Replaces the old additive Security Context dimension (0–5 points) with a proportional multiplier applied to the total base score.

### Multiplier Levels

| Level | Multiplier | Condition |
|-------|-----------|-----------|
| Active Threat + Code Loaded | × 1.20 | telemetry_threat_score ≥ 3.0 AND vulnerable_code_loaded == True |
| Partial Evidence | × 1.10 | telemetry_threat_score ≥ 3.0 XOR vulnerable_code_loaded == True |
| Neutral (default) | × 1.00 | No evidence either way |
| Confirmed Mitigated | × 0.85 | confirmed_mitigated == True |
| Confirmed False Positive | × 0.70 | confirmed_false_positive == True |

### Decision Matrix

The multiplier is evaluated in order (first match wins):
1. `confirmed_false_positive` → 0.70
2. `confirmed_mitigated` → 0.85
3. `telemetry_threat_score >= 3.0 AND vulnerable_code_loaded == True` → 1.20
4. `telemetry_threat_score >= 3.0 XOR vulnerable_code_loaded == True` → 1.10
5. Default → 1.00 (neutral, no penalty for missing data)

### Design Notes

- `network_blast_radius` was explicitly excluded. Blast radius is a static network property already captured in the Exposure dimension. Only dynamic threat evidence (telemetry + code load status) drives the multiplier.
- The multiplier is applied **before** Tier 2 LLM adjustment. The rationale: the multiplier reflects deterministic environmental context, and Tier 2 should have the final say on top of the context-adjusted score.
- The telemetry active threshold of 3.0 is on a 0–10 threat score scale.

### Order of Operations

```
total = sum(base dimensions)  → e.g., 60
total = round(60 × 1.20)     → 72 (multiplier applied)
total = 72 + 10               → 82 (Tier 2 adjustment applied)
total = clamp(82, 0, 100)    → 82
```

## Clamping

The raw sum of all 6 dimensions can reach 107, but the final score is clamped to 0–100. This means:
- Scores > 100 are rare (require top marks in every dimension)
- The 7-point overflow provides headroom for future dimensions without rescaling
- A Tier 2 LLM adjustment (±20) is applied after the multiplier and before clamping

## Score Bands

| Band | Range |
|------|-------|
| Low | 0–25 |
| Medium | 26–50 |
| Critical | 51–75 |
| Very Critical | 76–100 |

## Demo CVE Scores (Sprint 23)

As verified by `backend/tests/test_model_versions.py` and `backend/seed_data.py`:

| CVE | Score | Band |
|-----|-------|------|
| CVE-2023-34362 | 99 | Very Critical |
| CVE-2023-4966 | 97 | Very Critical |
| CVE-2023-27350 | 74 | Critical |
| CVE-2024-1709 | 91 | Very Critical |
| CVE-2023-36884 | 82 | Very Critical |
| CVE-2023-22515 | 97 | Very Critical |
| CVE-2022-47966 | 80 | Very Critical |

## Modification Rules

- Any weight change requires re-validation of all 7 demo CVEs
- The total sum (before clamping) should remain >= 100 to preserve headroom
- Security Context was removed in Sprint 21 and replaced by the multiplier above
- Multiplier thresholds (`TELEMETRY_ACTIVE_THRESHOLD = 3.0`) are defined in `backend/pipeline/config/scoring.py`
- See also: `backend/scoring.py:_determine_context_multiplier()`, `backend/scoring.py:calculate_final_score()`