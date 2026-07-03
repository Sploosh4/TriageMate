# Chapter 8: Pre-Tier — Asset Mission Classification

**Target:** 1500–3000 words · Self-contained · Podcast-script style

---

You have heard the four-tier pipeline mentioned in almost every chapter so far, but we have danced around the first station every time. Let us fix that. Pre-Tier runs before anything else. Before the deterministic rules in Tier 0, before the XGBoost model in Tier 1, before the LLM in Tier 2. It is the gatekeeper. Its job is simple to describe but surprisingly subtle to implement: look at the affected asset and answer two questions. How critical is this host to the organisation's mission? And if this host were compromised, how much would public wellbeing suffer?

Why does this matter? Because a vulnerability is never just a vulnerability. Context is everything. A critical-severity RCE in a print server in a back office is bad, but the same CVE on a police dispatch system or a hospital EMR server is a completely different category of problem. The CVSS score is the same. The EPSS probability is the same. But the real-world impact is worlds apart. Pre-Tier is how TriageMate tells the difference.

The implementation lives in a single file: `backend/pipeline/pre_tier.py`, clocking in at exactly 201 lines. It is one of the smallest files in the pipeline. Do not let the line count fool you — the logic packed into those 201 lines is the difference between a triage system that understands context and one that just shuffles numbers.

Let us walk through how it works, what is already built, what is waiting in the wings, and why a 201-line stub is actually the responsible engineering choice for a production MVP that has not yet seen real government data.

## The Return Contract

Before we talk about implementation details, we need to talk about the API contract, because it never changes. That is a hard rule. Every function that calls Pre-Tier knows exactly what shape it will get back. The return dictionary has four keys:

- `mission_prevalence`: one of three strings — `"Core"`, `"Support"`, or `"Peripheral"`
- `mission_prevalence_confidence`: a float from 0.0 to 1.0
- `public_wellbeing_impact`: one of three strings — `"Severe"`, `"Moderate"`, or `"Minimal"`
- `public_wellbeing_confidence`: a float from 0.0 to 1.0

That is it. Two classifications, each with a confidence score. Every other component in the pipeline depends on this contract. The scoring engine reads `mission_prevalence` to decide how many points to add for asset criticality. The queue view displays the classification as a badge. The drift dashboard tracks whether classifications are shifting over time. If this contract ever changes, it ripples through the entire system. So it stays stable.

## Phase 0: The KNOWN_TAGS Dictionary

The current implementation has three resolution phases, and the first one is a dictionary. `KNOWN_TAGS` is a hardcoded mapping of 31 fully qualified hostnames to their mission and wellbeing tags. Each entry is a tuple of four values: mission label, mission confidence, wellbeing label, wellbeing confidence.

Here is the full set of 31 demo hosts that ship with the MVP:

**The original seven (from the earliest demo):**
- `per-PRD-MOVEIT-WEB01.health.wa.gov.au` → Core / Severe
- `per-PRD-CITRIX-ADC01.transport.wa.gov.au` → Core / Moderate
- `per-PRD-PRINT-SVR05.education.wa.edu.au` → Support / Minimal
- `per-PRD-RMM-GW01.sharedservices.wa.gov.au` → Support / Moderate
- `per-PRD-FILE-STORE02.communities.wa.gov.au` → Core / Severe
- `per-PRD-WIKI-CORE01.police.wa.gov.au` → Core / Moderate
- `per-PRD-ITSM-TOOL01.finance.wa.gov.au` → Support / Minimal

**The twenty-four expansion hosts (added during Sprint six):**
Health gets the most entries — EMR, SQL cluster, file SAN, Exchange CAS — all Core with Severe wellbeing impact. Transport gets marine documentation, the TEMIS application system, and fleet management. Education gets student database and identity management. Communities gets case management. Police gets CAD dispatch. Finance gets budget database and SAP. Justice gets court file management and jury database. Water Corporation gets SCADA. DFES gets fire communications and emergency services dispatch. Shared Services gets the SSC proxy. Parliament gets its web server. DPIRD gets the AQIS database.

Every known hostname returns at 1.0 confidence (well, the stored confidence varies — the values range from 0.85 to 0.96, reflecting the original human-assigned certainty). The important thing is that if the hostname is in this dictionary, the lookup is instant. No model loading. No feature extraction. Just a hash table lookup and a return.

## Phase 1: The ML Model

This is where things get interesting. Sitting in `backend/ml/pre_tier_model.pkl` is a fully trained machine learning model. It is a `MultiOutputClassifier` wrapping a `RandomForestClassifier` with 200 trees (the user specification says 150, but the actual training script uses 200 — we will get to that discrepancy in a moment). It was trained on a combined dataset of 242 original records from `pretier_training_data.json` plus 300+ supplemental synthetic records from `generate_supplemental_hostnames.py`, giving us roughly 542 total training examples after deduplication.

The feature extraction lives in `backend/ml/pretier_features.py`, which is 425 lines of careful hostname parsing. It takes a WA Government hostname like `per-PRD-PATIENT-EMR01.health.wa.gov.au` and produces a 55-dimensional feature vector. Here is what each dimension captures:

- **Environment code** (ordinal): PRD=1, STG=2, DEV=3, TST=4, other=0
- **Agency one-hot** (14 dimensions): one boolean per WA Government department — health, transport, education, communities, police, finance, sharedservices, justice, dfes, watercorporation, elections, dpird, countryhealth, parliament
- **Role keywords** (19 dimensions): binary indicators for web, app, api, gateway, database, domain controller, file, print, backup, logging, mail, DNS, infrastructure, security, VMware, Citrix, wiki, PACS/imaging, EMR, identity, ITSM, SAP, scheduling, CAD/dispatch
- **Data classification code** (ordinal 1-4): derived heuristically from hostname keywords — Category 4 keywords include patient, police, emergency, water, scada, election, biosecurity, child protection; Category 2 includes HR, payroll, finance, procurement; Category 1 includes print, DNS, NMS, WSUS; everything else defaults to Category 3 (Protected)
- **Internet-facing flag** (binary): heuristic — PRD environment plus web/api/gateway/portal indicators
- **Network zone** (one-hot, 4 dimensions): dmz, restricted, protected, mgmt — extracted from subdomain segments
- **DC indicator** (binary): detects pdc1, pdc2, bdc1 in subdomain
- **Extended lifecycle** (4 binary): is_eol, is_sun, is_mig, is_act
- **OS platform** (3 binary): Windows, Linux, Solaris
- **Role suffix** (6 binary): ap, db, web, fe, be, rpt — detected from hostname parts ending with these prefixes followed by "01"
- **Known system indicator** (binary): detects any of 43 real WA Government system names like B2G, CHARS, DCPIMS, GARS, HSM, iPHIS, WebPAS, TEMIS, SCADA, LEO, eCourts, etc.

That is a lot of feature engineering for a 201-line pipeline file. And that is exactly the point. The heavy lifting is not in `pre_tier.py` — it is in `pretier_features.py`. The pipeline file itself is thin. It calls `extract_features`, converts the dict to a fixed-order array, and feeds it to the model.

The training pipeline in `train_pre_tier.py` uses 5-fold StratifiedKFold cross-validation, which means the data is split into five folds while preserving the distribution of label combinations. Each fold trains on 80% and validates on 20%. The cross-validation reports accuracy for each fold along with mean and standard deviation. After cross-validation, the final model is trained on the full dataset and exported via joblib.

Now, about that tree count discrepancy. The chapter outline says 150 trees. The actual training script uses 200. The correct answer is 200 — that is what the code does. The 150 figure was from an earlier specification that was updated during implementation. This kind of drift between spec and code is normal in an active project. The code is the source of truth. When you read `train_pre_tier.py`, you see `n_estimators=200`, `min_samples_leaf=2`, `class_weight="balanced"`. That is what is in the pickle file.

## Phase 2: The Default Fallback

If the hostname is not in `KNOWN_TAGS` and the model is not loaded or fails to produce a prediction, the system falls back to a conservative default:

```python
DEFAULT_RESPONSE = {
    "mission_prevalence": "Support",
    "mission_prevalence_confidence": 0.60,
    "public_wellbeing_impact": "Minimal",
    "public_wellbeing_confidence": 0.60,
}
```

Support mission, Minimal wellbeing impact, 0.60 confidence. The confidence is deliberately below 1.0 — it signals to downstream consumers that this is an uncertain classification. The scoring engine can weigh this appropriately. The default says, in effect, "we do not know what this host is, so we are assuming it is a run-of-the-mill support server with no public wellbeing implications." This is the safest possible default for a government security context. Better to under-prioritise an unknown critical system than to over-prioritise an unknown non-critical system. The analyst will catch the misclassification in the review queue.

## The Resolution Order

The `predict_mission_tags(hostname, ip)` function at line 166 of `pre_tier.py` implements a three-layer fallback chain:

1. Check `KNOWN_TAGS` — if the hostname is in the dictionary, return hardcoded values immediately. This is the fastest path and handles the 31 known demo hosts.

2. Try the ML model — call `_predict_with_model(hostname)`. This function lazy-loads the model on first invocation (thread-safe with a double-checked locking pattern), runs `extract_features` and `feature_vector_to_array` to build the 55-dimensional feature vector, calls `model.predict` and `model.predict_proba` to get both class labels and confidence scores, and returns the result.

3. Fall back to `DEFAULT_RESPONSE` — if neither phase 1 nor phase 2 produces a result, return the conservative default.

The lazy-loading pattern is worth noting. The model is not loaded at import time or at application startup. It is loaded on first demand, with a threading lock to prevent duplicate loads. If the model file does not exist or fails to load, the system logs a warning and continues without it. This means the application starts fast and degrades gracefully. You can run the entire pipeline without the ML model installed — it just means every unknown host gets the conservative default.

## Why the Stub Exists

Here is the honest answer: the ML model is already trained and sitting in `backend/ml/pre_tier_model.pkl`. It works. You can call `predict_mission_tags("some-random-host.wa.gov.au", "")` and it will return a prediction. So why does the dictionary still take priority?

Because the model was trained on synthetic data.

The 31 real hosts in `mock_cmdb.json` were expanded to 242 original training records through manual labelling, then further expanded to 500+ via the supplemental generator. But "supplemental" is a polite word for "synthetic." The generator in `generate_supplemental_hostnames.py` uses rules and heuristics to create plausible hostnames and label them. It knows that `SCADA` should be Core/Severe. It knows that `EOL` hosts should be Support/Minimal. It knows that `DEV` hosts should be Peripheral/Minimal. The rules are carefully designed and based on real WA Government naming conventions, but they are still rules, not ground truth.

The problem is that synthetic data can only take you so far. The model might learn spurious correlations that exist only in the synthetic distribution. It might generalise beautifully to similar patterns and fail catastrophically on edge cases that the generator never thought of. Until real WA Government hostnames with verified mission classifications arrive, the team cannot validate that the model is making correct predictions.

So the stub is the safe choice. For the 31 known demo hosts, the hardcoded values are guaranteed correct — they were assigned by humans who knew what those systems do. For unknown hosts, the model runs, but its output is not yet trusted enough to override the dictionary. The plan is that once real validation data arrives, the team will flip the priority: model first, dictionary as fallback when confidence is low.

## Planned MVP Work

The road map for Pre-Tier has several items, none of which are urgent enough to block the MVP but all of which are important for production readiness.

**Flip the resolution priority.** The model should become the primary prediction path. The dictionary should be a fallback for cases where the model confidence falls below a threshold (say, 0.70). This requires running the model against a validation set of real hostnames to confirm its accuracy is acceptable.

**Generate SMOTE-augmented training data.** The current 542 records are enough to train a functional model, but a Random Forest with 200 trees can handle much more data. SMOTE (Synthetic Minority Oversampling) can generate additional synthetic records that fill in gaps in the label distribution — for example, the "Peripheral" mission class is likely underrepresented compared to "Core" and "Support." A SMOTE pass could produce another 500-1000 balanced records.

**Add per-class logging.** The pipeline should log which resolution path was taken for each prediction — dictionary, model, or default — and at what confidence. This telemetry feeds into the drift dashboard and helps the team understand whether the model is being used or ignored in practice.

**Add confidence threshold configuration.** The fallback threshold should be configurable, ideally through an environment variable or a settings file. Different deployments may have different tolerance for uncertainty. A small SOC with limited analyst bandwidth might want a higher threshold (more defaults, fewer false positives). A well-staffed SOC might want a lower threshold (more model predictions, more edge cases to review).

**Cross-validate on real data.** The ultimate validation is to take a batch of real WA Government hostnames with verified classifications, run the model against them, and measure precision and recall per class. If accuracy is above 0.90 for both mission and wellbeing labels, the model is ready for prime time. If not, the feature extraction may need tuning, or the synthetic training data may need to be adjusted to better match reality.

## What the Stub Gets Right

It is worth appreciating what the current implementation does well, because it is easy to dismiss a 201-line file with a hardcoded dictionary as "not real ML." That misses the point.

**The stub handles every demo scenario.** All seven demo rows that ship with the application get correct classifications. The demo works. The pipeline flows. The scoring engine gets real asset criticality data.

**The stub returns something for everything.** Because of the three-layer fallback, `predict_mission_tags` is total — it never returns None, never raises an exception, never leaves a caller hanging. This property is essential for a pipeline component. If Pre-Tier fails, everything downstream stops. So Pre-Tier never fails.

**The ML path is production-ready.** The model is trained, saved, and loadable. The `_predict_with_model` function is wrapped in proper error handling. If the model file is missing, it logs and moves on. If feature extraction hits an unexpected hostname format, it logs and returns None. The lazy-loading pattern is thread-safe and idempotent.

**The feature extraction is thorough.** Fifty-five dimensions from a hostname string is not trivial. The system extracts agency, role, lifecycle, operating system, network zone, data classification heuristics, and known system names from a single string. This is genuine domain engineering — someone sat down with WA Government naming conventions and turned them into a feature vector.

## The Bigger Picture

Pre-Tier is the component that answers the question nobody asks in a CVSS-only triage system: "What is this thing?" A vulnerability scanner tells you a host has a CVE. It does not tell you whether that host is a police dispatch server or a printer in a storage closet. Pre-Tier bridges that gap.

In production, Pre-Tier would also consume data from a real CMDB — not just the hostname, but the actual asset record with data classification, business owner, network zone, and patch cycle. The current implementation only uses hostname because that is what is available from the vulnerability scanner alone. A future enhancement could take an optional `asset_record` parameter that enriches the prediction with true CMDB fields.

But even without a CMDB integration, Pre-Tier already gives the pipeline a crucial capability: it can distinguish between a vulnerability on `per-PRD-FIRE-COMMS01.dfes.wa.gov.au` (Core mission, Severe wellbeing impact) and the same vulnerability on `per-PRD-PRINT-SVR05.education.wa.edu.au` (Support mission, Minimal wellbeing impact). That distinction is what makes the scoring engine's job possible. Without it, every vulnerability looks the same. With it, the pipeline can rank intelligently.

And that is why Pre-Tier runs first. Before the rules, before the ML, before the LLM — classify the asset. Everything else depends on it.
