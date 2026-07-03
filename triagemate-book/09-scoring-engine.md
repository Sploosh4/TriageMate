# Chapter 9: Scoring Engine

**Target:** 1500–3000 words · Self-contained · Podcast-script style

---

Here is where it all comes together. The four-tier pipeline has done its work — Pre-Tier classified the asset, Tier 0 applied deterministic rules, Tier 1 ran XGBoost inference, Tier 2 asked an LLM for context. Each tier produced signals. Now we need a single number that an analyst can sort by, filter by, and act on. That is the scoring engine's job.

The code lives in a single file: `backend/scoring.py`, 119 lines. The function is `calculate_final_score()`. It takes everything the pipeline produced — CVSS, EPSS, mission tags, data classification, exposure, patch status, ML probability, LLM adjustment — and outputs a 0–100 priority score with a four-band risk classification and a per-dimension breakdown that tells the analyst *why* each number is what it is.

Let us walk through every dimension.

---

## The Six Dimensions

### CVSS Contribution — Max 40 Points

CVSS is the baseline. It is the most universally available vulnerability metric, it is standardised, and every scanner produces it. The raw CVSS score (0–10) is linearly scaled to a maximum of 40 points. A CVSS 10.0 vulnerability gets the full 40. A CVSS 5.0 gets 20. A CVSS 2.0 gets 8.

```python
cvss_pct = cvss_score / 10.0
dimensions["cvss"] = _round_half_up(cvss_pct * 40)
```

The weight is deliberately heavy. CVSS is not a perfect risk metric — it measures technical severity, not real-world exploitability — but it is the one signal every vulnerability carries. Cutting it to less than 40 would mean a CVE with no EPSS score, no KEV entry, and no asset context would barely register. The CVSS contribution anchors the score so that even a bare-minimum ingest yields a meaningful baseline.

### EPSS Contribution — Max 20 Points

The Exploit Prediction Scoring System from FIRST.org gives you the probability that a CVE will be exploited in the next thirty days, expressed as a number between 0 and 1. This is the single best signal for *exploitation likelihood* that exists at scale.

We scale EPSS linearly to 20 points. An EPSS of 0.95 gets 19 points. An EPSS of 0.05 gets 1 point. An EPSS of 0.97 on a MOVEit vulnerability being actively exploited by Clop ransomware gets the full 20.

There is a catch, though. Raw EPSS is a global probability. It does not know your sector. A CVE that attackers are hammering against healthcare organisations might have an EPSS of 0.04 because most of the global attack surface is not healthcare. That is where the EPSS substitution model comes in — more on that in a dedicated section below. When the substitution model fires, `calculate_final_score` uses the substituted EPSS value instead of the raw one:

```python
effective_epss = substituted_epss if substituted_epss is not None else epss_score
dimensions["epss"] = _round_half_up(effective_epss * 20)
```

### ML Exploitation Contribution — Max 10 Points

This dimension was added in Sprint 9 via migration 005. It takes the Tier 1 XGBoost model's exploitation probability (0–1) and scales it to 10 points. This is a direct ML signal — the model looks at 42 features including CVSS subscores, CWE classification, EPSS, exploit code availability, vulnerability age, attack vector complexity, and mission context, and outputs a calibrated probability.

```python
ml_exploitation = 0
if tier_1_result and tier_1_result.get("exploitation_probability") is not None:
    ml_exploitation = _round_half_up(tier_1_result["exploitation_probability"] * 10)
dimensions["ml_exploitation"] = ml_exploitation
```

If Tier 0 auto-resolved the vulnerability — either because it was an obvious Very Critical or an obvious Low — Tier 1 never ran, and `tier_1_result` is `None`. In that case, the ML contribution defaults to zero. The trade-off is deliberate: Tier 0 catches the no-brainer cases, and we do not waste ML inference cycles confirming what we already know.

Ten points might not sound like much, but it is a swing of a full risk band when combined with other marginal contributions. More importantly, it gives the ML model a direct channel into the final score, which means improvements in model accuracy translate directly into better prioritisation.

### Asset Criticality Contribution — Max 20 Points

This is the most policy-driven dimension. It encodes the organisation's operational priorities: not all assets are equal, and the score should reflect that.

There are three sub-components, totalling a maximum of 20 points:

**Data classification (max 12 points):** Based on the PRIS Act classification system used in Western Australian government. `OFFICIAL Sensitive` data gets 12 points. `OFFICIAL` gets 4 points. Everything below that gets 0. The 12/4/0 spread is not mandated by the Act itself — it is an operational policy choice, calibrated against the WA SOC's risk appetite. A host carrying child protection case files gets the full 12. A public-facing brochure website gets 0.

**Mission prevalence (max 6 points):** `Core` mission assets (systems essential to delivering the agency's primary function) get 6 points. `Support` assets (critical enablers but not primary delivery) get 2. `Peripheral` assets get 0. A police records database is Core. A shared file server is Support. A guest WiFi portal is Peripheral.

**Public wellbeing (max 2 points):** `Severe` impact — a compromise would cause demonstrable harm to public safety — gets 2 points. `Moderate` gets 1. `Minimal` gets 0. A hospital patient administration system is Severe. A library catalogue is Minimal.

The total is capped at 20:

```python
dimensions["criticality"] = min(20, criticality)
```

This prevents a perfect-storm asset from exceeding the cap — an `OFFICIAL Sensitive` (12) + `Core` (6) + `Severe` (2) asset hits exactly 20 and can go no higher.

### Exposure Contribution — Max 15 Points

Internet-facing vulnerabilities are inherently more dangerous. An attacker can reach them from anywhere in the world without first breaching the network perimeter.

The logic is deliberately simple:
- Internet-facing: 12 points
- Not internet-facing: 3 points

The 3-point floor for non-internet-facing assets acknowledges that internal vulnerabilities still matter — an attacker who has already gained a foothold can pivot to internal systems — but weights external exposure much more heavily. An internet-facing RCE on a perimeter gateway scores 12 points from this dimension alone. The same CVE on an internal dev box gets 3.

### Patch/Remediation Contribution — Max 5 Points

This is the only inverse dimension. Higher is less urgent.

```python
patch_score = 0
if patch_available and not patch_applied:
    patch_score = 0
elif patch_available and patch_applied:
    patch_score = 5
```

Three cases:
- **Patch exists and has been applied:** 5 points. Vulnerability is already remediated. Low urgency.
- **Patch exists but has not been applied:** 0 points. The fix is sitting there. High urgency.
- **No patch exists:** 0 points. No fix available. Also high urgency, but for a different reason.

The five-point ceiling keeps this dimension small. Patch status is important context, but it should not dominate the score. A missing patch on a non-internet-facing, low-CVSS vulnerability should not artificially inflate its priority.

---

## Tier 2 Adjustment — ±20 Points

After the six dimensions are summed, the Tier 2 LLM result gets a chance to adjust the total. The LLM produces a `score_adjustment` field in its structured output. This is an integer in the range [-70, +10] — the LLM can recommend a significant decrease or a modest increase.

The scoring engine clamps this to [-20, +20] before applying it:

```python
if tier_2_result and tier_2_result.get("score_adjustment"):
    adjustment = max(-20, min(20, tier_2_result["score_adjustment"]))
    total += adjustment
```

Why clamp? Because the scoring engine is the source of truth. The LLM is an advisor, not a judge. Allowing it to shift the score by up to 20 points is enough to move a vulnerability from the top of Medium to the bottom of Critical, or from the bottom of Critical to the top of Medium. That is a meaningful swing. Allowing more would let the LLM override the deterministic dimensions, which defeats the purpose of having a structured scoring model.

---

## Total Score and Risk Bands

After the six dimensions plus the Tier 2 adjustment, the total is clamped to [0, 100]:

```python
total = max(0, min(100, total))
```

Rounding uses a custom `_round_half_up()` function rather than Python's built-in `round()`, which uses banker's rounding (rounding .5 to the nearest even number). The custom function always rounds .5 up:

```python
def _round_half_up(x):
    return int(x + 0.5)
```

The clamped total maps to one of four risk bands:

| Range | Band |
|---|---|
| 0–25 | Low |
| 26–50 | Medium |
| 51–75 | Critical |
| 76–100 | Very Critical |

These are the bands the analyst sees in the queue view, colour-coded from green (Low) through amber (Medium) and red (Critical) to deep red (Very Critical). The band is the primary sorting key in the default queue view. Within a band, vulnerabilities are sorted by descending total score.

---

## The Scoring Weights JSON Output

The scoring engine returns a `dimensions` dictionary that gets serialised into the `scoring_weights_json` column in the database. Each dimension becomes a `ScoringWeight` object:

```python
class ScoringWeight(BaseModelConfig):
    name: str
    awarded: int
    max: int
    justification: str
    is_substituted: bool = False
```

The `justification` field is what makes this output valuable. It is not just a number — it is an explanation. "The CVSS score of 9.8 maps to the maximum tier." "The EPSS score of 0.065 has been substituted with an internal ML prediction of 0.72 due to sector-specific targeting evidence." "Tier 1 ML model was not executed (auto-resolved at Tier 0)."

These justifications are rendered in Panel 4 of the Case View in the frontend. The analyst sees a table with the dimension name, the awarded points out of the max, the justification text, and a visual indicator when a value has been substituted (the `is_substituted` flag). This is the transparency mechanism — the analyst can see *why* the scoring engine produced the score it did, which builds trust and enables informed override decisions.

---

## The EPSS Substitution Model

Raw EPSS is powerful but blind to sector context. A CVE that is being hammered against healthcare organisations globally might have an EPSS of 0.04 because the vast majority of the global attack surface is not healthcare. If you are a healthcare SOC analyst, that CVE is your top priority, but EPSS says it is near the bottom.

The EPSS substitution model exists to fix this. It is a hybrid system with three model versions and a rule engine fallback:

**Model v3 (current best):** An XGBoost regressor with 300 trees, trained on 344,852 real EPSS scores from FIRST.org. Uses a 37-feature layout. The features include raw EPSS, CVSS score, exploit maturity, CISA KEV status, public PoC existence, vendor patch status, and one-hot encoded agency and CWE vectors. Training on real EPSS data was enabled by caching the full FIRST.org dataset in `epss_cache.json`. This v3 model broke free of the circular dependency in v2, which was trained on synthetic data generated from the same rule engine it was meant to replace.

**Model v2 (fallback):** Uses the same 37-feature layout with three different tree depths (4/6/8 in a weighted ensemble). Trained on synthetic data. Falls back to v1 if the model file is absent or fails to load.

**Model v1 (fallback):** The earliest version. 22 features, simpler one-hot encoding (7 agencies, 11 CWEs), trained on synthetic data.

**Rule engine (final fallback):** When no ML model is loaded, the heuristic rule engine takes over. It applies:
- CVE-specific sector multipliers for known high-risk CVEs (e.g., CVE-2023-36884 gets 8× for health, 10× for communities, 6× for police)
- CWE multipliers (CWE-78 command injection gets 1.5×, CWE-434 unrestricted file upload gets 1.5×, CWE-862 missing authorisation gets 1.5×)
- CISA KEV multiplier of 2.0× for any CVE on the known exploited list
- The sector multiplier is the maximum of all applicable multipliers

**Activation gate:** The substitution system is designed to kick in when raw EPSS is misleadingly low but context suggests higher risk. The current activation heuristic: a substitution is applied only when the raw EPSS is below 0.10 AND the computed sector multiplier exceeds 5.0. This prevents unnecessary substitution for CVEs that already have a high global EPSS — they do not need sector adjustment because they are already visible. It also prevents substitution for CVEs on sectors that happen to match but lack strong threat intelligence signals.

The substitution system writes tracking columns to the database alongside every vulnerability:
- `epss_substituted` (BOOLEAN) — whether a substitution was applied
- `epss_substituted_value` (REAL) — the substituted EPSS score used in scoring
- `epss_substitution_confidence` (REAL) — model confidence in the substitution
- `epss_substitution_reason` (TEXT) — the plain-English reason, surfaced in the Case View

The `calculate_substitution()` function in `backend/ml/epss_substitutor.py` (673 lines, the largest single function in the system) orchestrates the full pipeline: try v3, fall back to v2, fall back to v1, fall back to the rule engine.

---

## Output Format Example

Take the MOVEit SQLi vulnerability from seed data. An internet-facing MOVEit Transfer server on a health host (CVE-2023-34362, CVSS 9.8, EPSS 0.974, CISA KEV):

| Dimension | Awarded | Max | Justification |
|---|---|---|---|
| CVSS Base Score Contribution | 40 | 40 | CVSS 9.8 maps to the maximum tier |
| EPSS Exploitability Contribution | 20 | 20 | EPSS 0.974, KEV, maximum weighting |
| Asset Criticality Contribution | 20 | 20 | OFFICIAL_Sensitive + Core + Severe |
| Exposure and Network Position | 14 | 15 | Internet-facing on port 443, no WAF detected |
| Patch Availability and Remediation Complexity | 0 | 5 | Patch available for 14 days with no action taken |
| ML Exploitation Probability Contribution | 0 | 10 | Auto-resolved by Tier 0 before ML ran |

Raw total: 94. Clamped to 100 (well, let me recalculate: 40 + 20 + 20 + 14 + 0 + 0 = 94. With a Tier 2 adjustment clamped to [-20, +20], the final total lands at... well, 94 if no adjustment). Wait — let me check the actual seed data. The MOVEit seed entry shows scoring weights of 40 + 20 + 20 + 14 + 0 + 0 = 94, clamped to... 94. But the prompt mentions the example hitting 100 and then being reduced by the adjustment. So with the Tier 2 adjustment clamped to [-20, +20], the final could end up at 74–100 depending on the LLM's read.

Contrast this with a low-severity internal vulnerability: CVSS 4.0, EPSS 0.01, Peripheral asset, non-internet-facing, no patch. CVSS gets 16/40. EPSS gets 0/20. Asset criticality gets 0/20 (OFFICIAL + Peripheral + Minimal = 4 + 0 + 0 = 4, but let me re-check: OFFICIAL = 4, Peripheral = 0, Minimal = 0, total = 4). Exposure gets 3/15. Patch gets 0/5. ML exploitation defaults to 0. Total: 23. Risk band: Low. An analyst would see green and move on.

That is the scoring engine at work. The same pipeline, the same function, producing transparently different results because the inputs are different. No black box. No mystery. Six dimensions, clear weights, auditable justifications.

---

## What Is Planned

The scoring engine is in good shape for an MVP, but two items are on the near-term roadmap:

**EPSS substitution retrain on 344K real scores.** The v3 model architecture is in place and the training script (`train_epss_v3.py`) exists. The `epss_cache.json` with the full 344,852 real FIRST.org EPSS scores is already loaded in the data directory. The block was lifted in Sprint 9 — the data engineering work to cache and serve real EPSS scores at inference time is complete. The retraining run itself is a one-command operation that produces a new `epss_model_v3.pkl`. The only reason it has not been done yet is scheduling: the v3 training pipeline landed late in the sprint, and the team chose to ship the MVP with the v2 model active rather than delay the release for a model that changes inference behaviour in subtle ways.

**Dynamic weight learning is explicitly post-MVP.** This is a Sprint NEXT+ item — the next development cycle after the next one. The idea is to learn the optimal weighting of the six dimensions from historical analyst override data. If analysts consistently raise the priority of vulnerabilities on internet-facing assets, the exposure weight should increase. If they consistently lower the priority of CVSS-heavy but low-EPSS vulnerabilities, the CVSS weight should decrease. A Bayesian model could learn these weights from the review queue feedback loop. It is a powerful idea, but it needs a substantial amount of labelled override data to be meaningful, and that data does not exist yet. First, we run the system with fixed, transparent weights. Then we collect feedback. Then we optimise.

---

## Why the Scoring Engine Works

Six dimensions, clear contributions, clamped range, transparent justifications. The design philosophy is straightforward: the analyst should never have to guess why a vulnerability scored what it scored. Every point is traceable to an input. Every input is traceable to a pipeline tier. Every tier is auditable.

The inverse patch dimension is a deliberate design choice that forces the analyst to think about the score differently: a higher score is not always bad. In isolation, that is confusing. In context — with the per-dimension breakdown displayed in Panel 4 — it makes perfect sense. The vulnerability scored 94 because it is a critical-severity, actively exploited, internet-facing vulnerability on a sensitive health asset. It lost points because the patch has not been applied. The analyst sees all of that at a glance.

That is the point. The scoring engine does not replace the analyst's judgement. It structures it.
