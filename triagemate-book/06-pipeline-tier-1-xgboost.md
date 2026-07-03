# TriageMate Book — Chapter 6: Tier 1 — The XGBoost Exploitation Probability Model

This is Tier 1, the machine learning heart of TriageMate. When Tier 0's deterministic rules cannot confidently resolve a vulnerability — the ambiguous middle — Tier 1 takes over. It uses an XGBoost classifier with eight hundred decision trees to predict the probability a vulnerability will be exploited in the wild. Two files make this work. `backend/ml/xgboost_predictor.py` (227 lines) is the inference engine: it loads the model, runs the Tier-0 fast-path pre-check, constructs the feature vector, calls the model, calibrates the output, computes ensemble variance, and routes the result. `backend/pipeline/tier_1.py` (103 lines) is the pipeline wrapper: it calls the predictor, catches errors, and falls back to a heuristic formula if the model is missing.

---

## Feature Architecture

The model sees each vulnerability as a vector of 419 numbers. Thirty-five are tabular features engineered from CVSS, EPSS, asset context, threat intel, and CVE metadata. Three hundred and eighty-four are text embedding dimensions from Sentence-BERT (all-MiniLM-L6-v2) encoding the CVE description.

The thirty-five tabular features break down as follows. **CVSS vector components** (eight features): attack vector, attack complexity, privileges required, user interaction, scope, and the three CIA impact dimensions. These are the raw CVSS building blocks, kept separate so the model can learn interactions the CVSS formula misses. **EPSS score** (one feature): the Exploit Prediction Scoring System probability, which captures signals CVSS cannot — exploit code chatter, dark web discussion, observed scanning. **Asset context** (eight features): internet-facing, domain-joined, data classification (OFFICIAL/OFFICIAL Sensitive/Category 1), mission prevalence (Core/Support/Peripheral), public wellbeing impact, lateral reachability, boundary reachability, downstream asset count. These come from the CMDB adapter via `build_feature_vector()` in `ingest_helpers.py`. **Patch status** (three features): patch available (from NVD reference tags), patch applied (synthetic estimate from age and severity), patch lag in days. **Threat intelligence** (eight features): ExploitDB PoC presence, Metasploit payload presence, AlienVault OTX pulse count, NVD reference count (proxy for researcher attention), MITRE Top-25 CWE membership, and four description-signature flags (RCE, privilege escalation, bypass, DoS, path traversal — regex-matched from the description). **Vendor and metadata** (seven features): vendor popularity index, CVSS exploitability subscore, CVSS impact subscore, vulnerability age, and the remaining flags.

A critical design decision: we removed PCA in v2.5. We had been reducing the 384 SBERT dimensions to 50 via PCA, but the PCA transform was fitted on the entire dataset before the train-val-test split — data leakage. XGBoost handles the full 384-dim space with built-in regularization (`colsample_bytree=0.8`, `max_depth=4`). Performance numbers are now honest.

The feature vector contract at `build_feature_vector()` level enforces 42 keys. Thirty-five go to XGBoost. The remaining seven are metadata for other tiers (`cvss_score` for the scoring engine, `osv_fixed_versions` for the patching dashboard, `internet_scan_detected` for Tier 0, `threat_intel_status` for the case view) plus `description` for the SBERT encoder. Total to the model: 35 + 384 = 419.

---

## Model Architecture

Algorithm: XGBoost classifier with `binary:logistic` objective. Eight hundred trees (`n_estimators=800`), each with `max_depth=4` — shallow enough to prevent memorisation, numerous enough to capture complex relationships. Learning rate 0.03. Subsample 0.8 (each tree sees 80% of data). Column subsample 0.8 (each tree sees 80% of features). Tree method `hist` (histogram-based binning for speed). Scale positive weight computed dynamically as `n_negative / n_positive` to address the ~15:1 class imbalance — positive errors cost fifteen times more than negative errors in the loss function.

---

## Training Data Strategy

Getting the data right was the hardest part. The evolution across sprints tells a story of finding and fixing subtle biases.

**Sprint 7 — 93K records, 18 hardcoded features.** Eighteen of the thirty-five tabular features were constants: patch_available=1, exploitdb_has_poc=0, metasploit_has_payload=0, internet_facing=1, domain_joined=1, data_classification=2, and so on. Zero variance, zero feature importance. Seventeen features carried the entire load. The text embeddings did heavy lifting, but the tabular pipeline was dead weight.

**Sprint 9 — 144K records, temporal bias fix.** CISA KEV has a median lag of ~190 days from publication to KEV addition. A naive "in KEV = exploited, not in KEV = not exploited" label strategy creates two problems: CVEs published six months ago get labelled negative when they may simply not be catalogued yet, and CVEs added to KEV after the training cutoff get labelled positive (future leakage). The fix was point-in-time labels: a CVE is exploited only if `dateAdded <= cutoff_date`. And a dynamic observation window equal to the median KEV lag: any CVE published within that window before the cutoff is excluded from training if it is negative (unreliable signal), but kept if it is positive (genuine fast-moving threat). This dropped ~19,500 unreliable entries but dramatically improved label quality.

**Sprint NEXT — 186K records, version two corpus.** Built by `backend/scripts/build_training_corpus.py`. All 35 features now come from real data distributions. Patch availability from NVD reference tags. ExploitDB/Metasploit sampled from realistic EPSS/CVSS correlations. Asset context sampled from WA-government distributions with fixed seed 42. The output is `training_data_v2.npz`: 186K records, 67 construction columns (35 tabular + metadata), 419 features after SBERT concatenation.

**Chronological split.** Train ≤ 2023-06-30. Validation 2023-07-01 to 2023-12-31. Test > 2023-12-31. Random splits leak future information into training. Chronological splits approximate real-world use: predicting exploitation for unseen vulnerabilities from older patterns.

---

## Calibration

XGBoost raw probabilities are not perfectly calibrated. A raw 0.7 may not mean 70% of such cases are exploited. We apply Platt scaling — logistic regression fitted on the validation set's raw probabilities — saved to `xgboost_calibrator.pkl`. Expected Calibration Error (ECE) is computed before and after: we have seen 60-70% ECE improvements. After calibration, we scan 200 thresholds from 0.001 to 0.50 on the calibrated validation probabilities, picking the threshold that maximizes F1 score.

---

## Performance Metrics

ROC-AUC ranges from 0.9677 to 0.9946 across training runs and mission categories. ROC-AUC of 0.99 means the model ranks a random exploited CVE above a random non-exploited CVE 99% of the time. Variation by mission category: corporate (0.9946), critical infrastructure (0.9789), health (0.9677). Even the weakest performance is excellent discrimination.

---

## Ensemble Variance Routing

The model does not just output a probability — it outputs an uncertainty signal. The predictor computes predictions from eight 100-tree checkpoints across the 800-tree ensemble. The standard deviation of these eight probabilities is the ensemble variance. Early trees capture broad patterns; later trees refine edge cases. If they agree, confidence is high. If they diverge, the signal is ambiguous.

Routing: if ensemble std > 0.15, escalate to Tier 2 (trees disagree, need LLM). If std ≤ 0.15, auto-resolve (trees agree, answer trustworthy). This captures what raw probability cannot: a probability of 0.35 with low variance is a confident moderate; 0.35 with high variance is a confused toss-up.

---

## Routing Thresholds

- exploitation_prob < 0.20 → auto-resolve (Low/Medium)
- exploitation_prob ≥ 0.20 + ensemble_std > 0.10 → escalate to Tier 2
- exploitation_prob ≥ 0.40 → escalate (regardless of variance)
- exploitation_prob ≥ 0.50 → escalate (high confidence)

Defined in `xgboost_predictor.py` as module-level constants: `LOW_PROB_THRESHOLD`, `MID_PROB_THRESHOLD`, `HIGH_PROB_THRESHOLD`, `UNCERTAINTY_THRESHOLD`.

---

## Tier-0 Fast Path

Before model inference, `_tier_zero_check()` catches obvious cases. First: KEV + EPSS ≥ 0.30 → immediate exploitation_probability = 0.95, confidence = 0.90, routing = escalated. CISA has confirmed exploitation and EPSS agrees — no model needed. Second: CWE-stratified EPSS thresholds. Eight CWEs have custom thresholds derived from empirical KEV analysis — CWE-22 (path traversal) at 0.085, CWE-78 (OS command injection) at 0.515, CWE-787 (out-of-bounds write) at 0.716, CWE-79 (XSS) at 0.600, CWE-89 (SQL injection) at 0.500, CWE-416 (use-after-free) at 0.550, CWE-20 (input validation) at 0.400, CWE-843 (type confusion) at 0.300. Default threshold is 0.84. If EPSS exceeds the CWE threshold, escalate with probability = min(0.99, EPSS + 0.10).

---

## Heuristic Fallback

If the model file is absent (first deployment before training, or corruption), `tier_1.py` catches `FileNotFoundError` and falls back to a weighted formula: `(CVSS / 10.0) * 0.4 + EPSS * 0.3 + environment adjustments`. Environment adjustments are rules of thumb: not internet-facing (-0.15), lateral reachability > 20 (+0.15), domain-joined + privileged account (+0.12), Core mission (+0.08), Severe wellbeing (+0.10). Probability clamped to [0, 1]. Confidence defaults to 0.85 with downward adjustments for high-reachability cases.

Known bug #14: the heuristic always escalates. The formula pushes probabilities above 0.50 for any moderate-severity CVE, and the routing logic escalates anything above 0.30 with confidence below 0.80. Trivial in practice — the fallback path is never reached once the model is present.

---

## What Is Planned — Sprint NEXT

The single highest-impact improvement: XGBoost retrain on `training_data_v2.npz` (186K records, all 35 features with real distributions instead of hardcoded constants). The current model had 18 features with zero importance because the training data gave them no variance. The retrained model will learn meaningful weights across all features — patch status, asset context, threat intel signals that were previously dead weight. Text embeddings remain strong and unchanged.

Verification: 7 demo row scores must fall within ±3 of expected values [94, 87, 71, 63, 55, 41, 22]. If they do not, the feature construction or training pipeline has a bug. Additional Sprint NEXT items: make routing thresholds configurable via environment variables, add a model version identifier to prediction output for audit traceability, and integrate retraining into the CI/CD pipeline.

---

The current XGBoost model works — ROC-AUC above 0.96, calibrated probabilities, ensemble variance routing, Tier-0 fast path. But it is running on five of six cylinders. The v2 retrain closes that gap. Every feature will contribute. Every signal will be heard.
