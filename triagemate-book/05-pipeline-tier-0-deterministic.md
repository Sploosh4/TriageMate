# Chapter 5: Tier 0 — The Deterministic Rule Engine

**Classification:** Infrastructure / Pipeline  
**File:** `backend/pipeline/tier_0.py` (96 lines)  
**Podcast Length:** ~20 minutes  

---

## Intro

Every pipeline needs a front door. Tier 0 is TriageMate's front door — the first decision point a vulnerability hits when it enters the system. The question Tier 0 answers is simple: *Can we confidently auto-resolve this vulnerability right now, with zero machine learning?*

If yes, we stamp it **Very Critical** or **Low** and move on. If the answer isn't obvious, we do the only smart thing — escalate to Tier 1 (the XGBoost model) for deeper analysis.

Tier 0 is designed to be production-ready from day one. No training data. No model weights. No external ML dependencies. Just three deterministic rules that encode the kind of decision-making any seasoned SOC analyst would make instinctively.

---

## The Three Rules

Tier 0's logic lives in a single function, `evaluate_tier_0()`, which takes five parameters:

```
cvss_score: float       — CVSS v3.1 base score (0.0 – 10.0)
cisa_kev: bool          — Is the CVE in the CISA KEV catalog?
epss_score: float       — EPSS probability (0.0 – 1.0)
data_classification: str — PRIS Act label
internet_facing: bool   — Is the asset exposed to the internet?
```

The function returns a dict with two keys: `routing` (`"auto_resolved"` or `"escalated"`) and `resolution` (`"very_critical"`, `"low"`, or `"ambiguous"`).

### Rule 1 — KEV + High CVSS + Internet-Facing → Very Critical

```
IF cisa_kev == True
   AND cvss_score >= 9.0
   AND internet_facing == True
THEN → auto_resolved / very_critical
```

This is the worst-case scenario: a CVE that attackers are already exploiting in the wild, with a near-maximum severity score, sitting on a box that anyone on the internet can reach. There is no ambiguity here — this needs an immediate response. Tier 0 short-circuits the pipeline and flags it.

**Why this matters:** CISA's KEV catalog is essentially a list of "patch these now" vulnerabilities. When you combine that with a CVSS of 9.0 or higher (Critical/Near-Critical) and an internet-facing asset, you have a combination that no SOC should waste time debating. The rule fires instantly.

### Rule 2 — KEV + High EPSS + OFFICIAL Sensitive → Very Critical

```
IF cisa_kev == True
   AND epss_score >= 0.90
   AND data_classification == "OFFICIAL Sensitive"
THEN → auto_resolved / very_critical
```

Not every critical asset lives on the internet. Internal systems handling **OFFICIAL Sensitive** data (PRIS Act Category 3 or 4 — the most sensitive tiers) demand the same urgency. If a vulnerability is in KEV and has an EPSS score of 0.90 or higher (meaning a 90%+ probability of exploitation within 30 days), it doesn't matter whether it's internet-facing or not — the data it threatens is too valuable to risk.

The EPSS threshold here (0.90) is deliberately high. We only auto-resolve with this rule when exploitation is all but guaranteed. Everything below that threshold gets escalated to Tier 1 for more nuanced analysis.

### Rule 3 — NOT KEV + Low CVSS + Low EPSS → Low

```
IF cisa_kev == False
   AND cvss_score < 4.0
   AND epss_score < 0.10
THEN → auto_resolved / low
```

The mirror image of Rule 1: no known exploits, low severity, low exploitation probability. This is the safe dismissal — vulnerabilities that realistically will never be exploited and don't warrant human attention.

The CVSS threshold of 4.0 corresponds to the boundary between "Low" and "Medium" severity. The EPSS threshold of 0.10 means there's less than a 10% chance of exploitation in the next 30 days. Combined with no KEV entry, this is as close to "ignore with confidence" as the data allows.

### Default → Escalated

```
ELSE → escalated / ambiguous
```

Everything that doesn't match one of the three rules falls into the **ambiguous middle**. This is the zone where judgment is required — medium CVSS, moderate EPSS, vulnerabilities that might or might not be KEV-listed but whose other signals don't line up clearly.

These cases are escalated to Tier 1 (XGBoost), which can weigh subtle interactions between features that a simple rule engine can't capture. The key insight: Tier 0 never makes a wrong decision — it only makes confident ones. If it's not sure, it passes the buck.

---

## Threshold Constants

The four threshold values are plain module-level constants in `tier_0.py`:

```python
KEV_CVSS_THRESHOLD = 9.0    # Rule 1 CVSS floor
KEV_EPSS_THRESHOLD = 0.90   # Rule 2 EPSS floor
LOW_CVSS_THRESHOLD = 4.0    # Rule 3 CVSS ceiling
LOW_EPSS_THRESHOLD = 0.10   # Rule 3 EPSS ceiling
```

No config file, no database lookup, no environment variable indirection. Just four lines at the top of the file. This is intentional — when a SOC analyst says "we're seeing too many false positives from Rule 2, bump the EPSS threshold to 0.95," the change is a one-line edit, a code review, and a deploy. No model retrain, no config pipeline, no YAML spelunking.

**Planned tuning:** Based on operational experience, the team expects these values to drift. Potential changes include:
- Lowering `KEV_CVSS_THRESHOLD` to 8.0 to catch more KEV + internet-facing cases
- Lowering `LOW_CVSS_THRESHOLD` to 3.0 if too many borderline cases are being dismissed
- Raising `LOW_EPSS_THRESHOLD` to 0.05 for a more conservative dismissal policy

---

## SSVC Alignment

The rules map to the **Stakeholder-Specific Vulnerability Categorization (SSVC)** framework adopted by CISA, FIRST, and CERT/CC. SSVC evaluates vulnerabilities along four dimensions — **Exploitation**, **Utility**, **Mission Impact**, and **Automatable** — to produce one of four actions: Track, Track*, Attend, or Act.

| SSVC Dimension | Tier 0 Proxy | Threshold |
|---|---|---|
| Exploitation | CISA KEV membership | Present / Absent |
| Utility | CVSS base score | >= 9.0 or < 4.0 |
| Mission Impact | PRIS Act data classification | OFFICIAL Sensitive (Cat 3-4) |
| Autonomable | (Planned — not yet implemented) | — |

The four SSVC actions correspond directly to Tier 0 outcomes:

- **Act** → **Very Critical** (Rules 1 & 2). The vulnerability requires immediate action. The combination of active exploitation, significant impact, and high utility leaves no room for deferral.
- **Track** → **Low** (Rule 3). The vulnerability should be noted but does not require action. Monitor for changes in KEV status or EPSS score.
- **Track*** / **Attend** → **Escalated / Ambiguous**. These map to the middle zone where SSVC itself says the decision is context-dependent. Tier 1 provides that context.

This alignment isn't cosmetic — it means TriageMate's outputs are directly defensible against an SSVC-based audit. If a CISO asks "why did you classify this CVE as Very Critical?", the answer can reference the SSVC dimensions Tier 0 checked and the thresholds applied.

---

## Re-check Logic

Low-severity auto-resolutions are not permanent. The `requires_recheck()` function at the bottom of `tier_0.py` determines whether a case needs to be re-evaluated:

```python
def requires_recheck(tier_0_result: dict, created_at_days_ago: int) -> bool:
    return (
        tier_0_result["routing"] == "auto_resolved"
        and tier_0_result["resolution"] == "low"
        and created_at_days_ago >= 7
    )
```

Any vulnerability classified as **Low** that is 7 or more days old gets flagged for re-evaluation. The re-check re-runs the three rules with fresh CISA KEV and EPSS data. This handles the scenario where a vulnerability wasn't in the KEV catalog at the time of first analysis but gets added later — or where its EPSS score has risen above the 0.10 threshold.

This runs as a daily background task in the pipeline. The 7-day window is a balance between being responsive to new threat intelligence and avoiding excessive re-computation. If a vulnerability's EPSS score spikes on day 3, there's a 4-day lag before re-evaluation — but in practice, EPSS scores change daily and the delta from day 3 to day 7 is usually negligible. The next-day check will catch it.

---

## Why Tier 0 is Production-Ready

1. **Zero ML.** No training data, no model files, no feature engineering, no inference latency. The rules are textbook SOC logic expressed as Python conditionals.

2. **Zero external dependencies.** Beyond the EPSS and KEV data feeds (which the pipeline already ingests), Tier 0 needs nothing. No database, no cache, no API calls.

3. **Predictable performance.** Each evaluation is five parameter lookups and at most three boolean checks. Worst-case path is the three conditions for Rule 3 plus the default fallback. Throughput is bounded by function call overhead.

4. **Auditable.** Every decision is logged at `INFO` level with a structured `tier_0_resolve` event, recording which rule fired and the input parameters. This produces an exact audit trail of why every vulnerability was auto-resolved or escalated.

5. **Fail-safe.** The default behavior is escalation. If Rule 1, 2, and 3 all miss, the vulnerability goes to Tier 1. Tier 0 cannot accidentally drop a vulnerability — it can only pass it on. The only way a vulnerability gets dismissed is through Rule 3's explicit safe-dismissal criteria, which require all three conditions (not KEV, low CVSS, low EPSS) to be met simultaneously.

---

## What's Planned (MVP+)

Tier 0 was deliberately kept small — three rules, 96 lines — because the team believes the rule engine should grow organically with operational experience, not be designed upfront by guesswork. Nevertheless, several extensions are on the roadmap:

- **Threshold tuning** — The first round of SOC feedback will likely adjust one or more constants. The most common candidate is lowering `KEV_CVSS_THRESHOLD` to 8.0 to capture more internet-facing KEV vulnerabilities.

- **CWE-based rules** — Specific CWE classes (e.g., CWE-94: Improper Control of Code Generation, AKA RCE) could trigger auto-resolution when combined with certain data classifications or asset roles. For example: KEV + RCE on a domain controller → Very Critical regardless of CVSS.

- **Critical infrastructure rules** — Rules that check an asset's sector tag (energy, healthcare, finance) and auto-escalate based on sector-specific policies.

- **Automatable dimension** — The fourth SSVC pillar (Automatable) is not yet used. If integrated, it would add another axis: a vulnerability that is automatable (can be exploited via a worm or script) would be more likely to trigger Very Critical, especially if combined with internet-facing status.

---

## Summary

Tier 0 is TriageMate's deterministic front door. It handles the easy cases confidently and passes everything else to the ML pipeline. Three rules, four constants, 96 lines of Python. Production-ready from the first deploy.

The design philosophy: **make the easy decisions fast, and never pretend to make a decision you're not confident in.**

---

*Next: Chapter 6 — Tier 1: XGBoost Classification*
