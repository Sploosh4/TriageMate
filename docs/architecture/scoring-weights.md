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
| Security Context | 5 | Telemetry threat score (×3) + network blast radius (×2) |
| **Total** | **112** | Clamped to 0–100 |

## Design Rationale

**CVSS heaviest (40 pts):** The CVSS base score is the most mature and standardized vulnerability severity signal in the industry. It provides a consistent 0–10 scale backed by FIRST/CVSS SIG governance, making it the natural anchor for the scoring system. Converting CVSS 0–10 → 0–40 gives the dimension enough dynamic range to differentiate between CVSS 9.8 and CVSS 9.1 (39 vs 36 points).

**EPSS second (20 pts):** EPSS captures real-world exploitation probability, which is orthogonal to CVSS severity. Many high-CVSS vulnerabilities are never exploited, and some low-CVSS vulnerabilities are weaponised in-the-wild. EPSS weights the score toward actionable risk. When the raw EPSS is missing or unreliable, the sector-aware EPSS substitution model (v4 → v3 → v2 → v1 → heuristic rule engine) fills in.

**Asset Criticality (20 pts):** Ties the score to WA government data classification (WAICP) and mission context. "Core" government services handling OFFICIAL Sensitive data with severe public wellbeing impact should score higher than a peripheral system with OFFICIAL data, even if both have the same CVE. The 12/4/0 spread for OFFICIAL Sensitive/OFFICIAL/unclassified is an operational policy choice, not mandated by WAICP itself.

**Exposure (12 pts):** Internet-facing systems are at much higher risk of discovery and exploitation than internal-only assets. The code produces 12 points for internet-facing and 3 for internal, reflecting this gap.

**ML Exploitation Probability (10 pts):** The XGBoost model (419-dim, ROC-AUC 0.9459) provides a nuanced exploitation probability prediction. This dimension only contributes when Tier 1 runs — auto-resolved CVEs at Tier 0 bypass it. The 10-point allocation reflects that the ML signal is powerful but supplementary to the mature CVSS/EPSS signals.

**Patch/Remediation (5 pts):** A small modifier recognising that patch status matters but should not dominate the score. Full remediation (patch available + applied) earns 5 points. A patch available but not applied scores 0 (overdue). No patch available scores 0 (neutral, not punitive — the vulnerability is unmitigated but not due to negligence).

**Security Context (5 pts):** Added in Sprint 17 as the 7th dimension. Combines telemetry threat score (synthetic Sentinel/EDR incidents — is the vulnerable code loaded?) with network blast radius (how many peers can be reached from this host?). The composite formula `threat_score × 3 + blast_radius × 2` is clamped to 0–5. This is intentionally the smallest dimension because telemetry context is the newest and least-proven signal.

## Clamping

The raw sum of all 7 dimensions can reach 112, but the final score is clamped to 0–100. This means:
- Scores > 100 are rare (require top marks in every dimension)
- The 12-point overflow provides headroom for future dimensions without rescaling
- A Tier 2 LLM adjustment (±20) is applied before clamping, so the LLM can influence but not break the 0–100 bound

## Score Bands

| Band | Range |
|------|-------|
| Low | 0–25 |
| Medium | 26–50 |
| Critical | 51–75 |
| Very Critical | 76–100 |

## Demo CVE Scores (Sprint 18)

As verified by `backend/tests/test_model_versions.py`:

| CVE | Score | Band |
|-----|-------|------|
| CVE-2023-27350 | 98 | Very Critical |
| CVE-2023-34362 | 91 | Very Critical |
| CVE-2024-1709 | 73 | Critical |
| CVE-2021-44228 | 66 | Critical |
| CVE-2024-6387 | 58 | Critical |
| CVE-2023-3519 | 44 | Medium |
| CVE-2023-22527 | 26 | Medium |

## Modification Rules

- Any weight change requires re-validation of all 7 demo CVEs
- The total sum (before clamping) should remain >= 100 to preserve headroom
- Security Context (5) was added in Sprint 17; it was the 7th dimension
- See also: `backend/scoring.py:calculate_final_score()`