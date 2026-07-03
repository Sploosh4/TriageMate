# Chapter 15: Data Corpus and Training

**Target:** 1500–3000 words · Self-contained · Podcast-script style

---

We have spent the last fourteen chapters describing a system that makes predictions. TriageMate looks at a CVE, computes features, runs them through an XGBoost model, scores the result, and decides whether to alert a human. But we have been skirting around a foundational question the entire time: what did we train that model on? Where did the data come from, how was it labelled, and how do we know we are not just feeding the model garbage?

This chapter is the answer. The training data that powers TriageMate's ML models was built during what the team called the Data Supremacy sprint — Sprint 9. The corpus is the single most important asset in the entire system. Without it, the XGBoost model is a random-number generator. With it — and with the care we took to avoid data leakage — we get a model that can predict exploitation with genuine signal.

The code lives in `backend/scripts/` and the data lives in `backend/data/`. Let us walk through every piece.

## The NVD Corpus — 186,102 CVEs

At the centre of everything is a file called `nvd_corpus.json`. It is 145 megabytes on disk and contains structured records for 186,102 CVEs spanning from 1999 to the end of 2024. This is not just a list of CVE IDs — it is a parsed, enriched, deduplicated knowledge base that serves as the backbone for both training and inference.

The corpus is built by `fetch_nvd_corpus.py`, which operates in two modes. The primary mode uses the NVD API 2.0, but there is a feed-based fallback — if the API rate-limits you or goes down, it falls back to the old JSON feed files. This dual-mode design was a lesson learned after the NVD API briefly went dark mid-ingestion.

The fetch is chunked into quarterly intervals from 2019-01-01 to 2024-12-31. A quarter is the sweet spot between too many small requests and one giant request that times out.

The script saves progress to `nvd_checkpoint.json` as it goes. If the fetch is interrupted, it resumes from the last checkpoint instead of starting from scratch. A full NVD fetch takes multiple hours even with the API, so checkpointing is essential.

What does the corpus store per CVE? The full CVSS v3 vector and parsed metrics (base score, exploitability sub-score, impact sub-score, and all eight components: AV, AC, PR, UI, S, C, I, A). The CWE classification. The description text, later fed through SBERT. The full list of references. Publication and last-modified dates. And the vendor information.

Speaking of vendors: there is a companion script called `build_vendor_index.py` that walks the entire NVD corpus and extracts every unique vendor it can find. The result is `vendor_popularity.json`, which indexes 17,100 vendors by how frequently they appear in CVEs. This matters for the vendor popularity feature — a CVE from Microsoft or Apache gets treated differently than one from an obscure vendor with three CVEs in twenty years. It is not a judgement call; it is a pure frequency signal. The model learns that popular vendors get more researcher attention, which influences exploitation likelihood.

## The KEV Cache — The Positive Class

Next piece: `kev_cache.json`. This is a much smaller file — 1,631 entries — but it is arguably the most important one. It comes from the CISA Known Exploited Vulnerabilities catalogue.

Every entry in the KEV catalogue has a CVE ID, the date CISA added it to the list, and some metadata about the known exploitation activity (ransomware use, APT use, whether it is a zero-day, and so on). This is as close to ground truth as we get in vulnerability exploitation data. When CISA says a vulnerability is being exploited in the wild, it is not a prediction — it is a confirmed observation.

The KEV cache is refreshed by `refresh_caches.py`, which simply hits the CISA KEV API and downloads the latest set. This is a small, fast operation — the KEV catalogue is only a few thousand entries — so it can run on every pipeline deployment without slowing anything down.

Why does KEV matter for training? Because KEV entries form the positive class for the XGBoost exploitation model. If a CVE appears in KEV within the observation window, it gets label 1 (exploited). If it does not, it gets label 0 (not exploited). The entire training signal depends on KEV being authoritative and up to date. This is both a strength and a limitation — we will talk about the limitation in the Temporal Bias section.

## The EPSS Cache — Scoring Signal

Next: `epss_cache.json`. This file contains 344,852 scores from FIRST.org's Exploit Prediction Scoring System. The scores are downloaded from a public data URL: `https://epss.cyentia.com/epss_scores-current.csv.gz`. Each entry has a CVE ID, an EPSS score between 0 and 1, and a percentile rank.

EPSS is interesting because it is itself a model. FIRST trains a separate model that predicts the probability that a CVE will be exploited in the next 30 days. TriageMate uses EPSS in three ways.

First, as a scoring dimension. The scoring engine reads the EPSS score and adds it directly to the composite score. A CVE with EPSS 0.9 is obviously more urgent than one with EPSS 0.001. Second, in Tier 0 deterministic rules. Some Tier 0 rules fire based on EPSS thresholds — a CVE with EPSS above 0.5 automatically escalates regardless of other features. Third — and most relevant to this chapter — EPSS is a training feature. The XGBoost model includes EPSS score and percentile as two of its input features.

The EPSS cache is also refreshed by `refresh_caches.py`. FIRST updates EPSS scores daily, so the cache can get stale. The refresh script is designed to be run as a cron job.

## The ExploitDB CSV — Exploit Existence Signal

The ExploitDB integration lives in `exploitdb.py` and loads a file called `files_exploits.csv`. This file contains 47,089 exploit entries, of which 25,037 have direct CVE mappings. The rest are either mapped to other identifiers (EDB-ID only, OSVDB, etc.) or are not mapped at all.

This data feeds two features in the vector: `exploitdb_has_poc` which is a boolean indicating whether a public PoC exists on ExploitDB for this CVE, and `metasploit_has_payload` which indicates whether a Metasploit module exists. These are strong signals — a CVE with a public exploit and a Metasploit module is far more likely to be used in actual attacks than one with neither.

The ExploitDB data is loaded into a process-lifetime in-memory cache. It is not written to a separate cache file like KEV and EPSS because it changes infrequently — ExploitDB does not update as often as EPSS or KEV, so there is less value in persisting the cache to disk.

## Training Data v2 — The Unified Corpus

Now we get to the main event: `training_data_v2.npz`. This is the file that the XGBoost model actually trains on. It contains 186,000 feature vectors, each with 68 columns. It is built by `build_training_corpus.py`, which is the unification script — it loads the NVD corpus, merges in EPSS scores, KEV labels, ExploitDB features, and vendor popularity, then computes the full feature vector for every CVE.

What are those 68 columns? Let us break them down by category.

**CVSS metrics (8):** The eight vector components — Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability. Each is one-hot encoded from its CVSS string value. A CVE with `AV:N` gets a 1 in the network column, 0 in the others.

**CVSS sub-scores (2):** The CVSS Base Score and the Exploitability Sub-Score. These are continuous values from the CVSS calculation.

**EPSS (2):** EPSS score and EPSS percentile.

**Patch status (4):** Whether a patch is available, whether the vendor has acknowledged the issue, whether there are workarounds documented, and whether the CVE is in a known vendor's disclosed-but-unpatched state.

**Asset context (6):** These are computed at inference time from the affected asset, but during training they are simulated using the Pre-Tier classification. Mission prevalence (core/support/peripheral mapped to 2/1/0), public wellbeing impact (severe/moderate/minimal mapped to 2/1/0), asset type, network zone, operating system family, and whether the asset is internet-facing.

**Network metrics (3):** Reachability from the internet, whether the CVE has known weaponised exploits for the asset's architecture, and whether the CVE affects a commonly scanned service (HTTP, SSH, RDP, SMB, SQL).

**Exploit intel (4):** ExploitDB PoC exists, Metasploit module exists, number of GitHub PoCs, and a boolean for highly cited CVEs in security advisories.

**CVE metadata (4):** CVE age in days from publication to cutoff, days since last modification, whether it is a disputed CVE, and the number of references.

**Signature patterns (5):** Indicators of specific exploit patterns — ransomware association, APT association, whether the CVE is in CISA's "known to be used in ransomware campaigns" list, whether the vulnerability type frequently appears in exploit kits, and a "low-hanging fruit" flag based on Attack Vector + Attack Complexity + Privileges Required combinations that are commonly exploited.

Then there is the SBERT embedding. Each CVE's description is run through Sentence-BERT, producing a 384-dimensional vector that captures semantic similarity between descriptions. If a CVE's description sounds like other exploited CVEs — keywords like "remote code execution," "no authentication required," "critical" — the embedding will place it closer to exploited ones in the semantic space. This gives the model a way to generalise to novel CVEs that share language patterns with historically exploited ones.

That brings the total to 35 tabular features plus 384 embedding dimensions, plus the CVE ID string, publication date, and the label. Hence: 186K records, 68-ish conceptual columns.

## Temporal Bias Fixes — The Hard Part

If you build a training corpus naively — take all CVEs, compute features using today's data, split randomly — your model will look amazing in evaluation and fall apart in production. This is the single most common mistake in ML for cybersecurity: temporal leakage. TriageMate was designed from the ground up to avoid it.

The problem: a CVE published in 2023 might not appear in KEV until 2025. If you train in 2026 using the 2025 KEV label, the model learns patterns that were not available to a predictor in 2023. The model looks great on the test set because the test set also uses future labels. But in production, you need to predict exploitation before it happens.

TriageMate handles this with five strategies.

**First: chronological split.** Training set contains CVEs published on or before 2023-06-30. Validation is 2023-07-01 to 2023-12-31. Test is everything after 2023-12-31. The model is always predicting future CVEs from past ones — exactly the production scenario.

**Second: point-in-time labels.** A CVE is positive if it has a KEV entry dated within ~190 days of its publication. A CVE published in January 2023 that enters KEV in June 2024 is labelled 1 because the KEV event fell within the observation window. The training cutoff determines split membership, not the label. A CVE published in November 2023 goes to the validation set; if it enters KEV in April 2024 (within the window), it gets label 1 — but the model never sees that label during training.

**Third: observation window filters.** CVEs published within the median KEV lag (~190 days) before the split cutoff are excluded if unlabelled. A CVE published on 2023-05-01 with a cutoff of 2023-06-30 has only had 60 days to appear in KEV. The median lag is 190 days. We cannot label it "not exploited" — we just do not know yet. Excluding it prevents the model from learning that "not seen in KEV yet" means "not exploited."

**Fourth: no look-ahead on EPSS or KEV.** EPSS scores are snapshotted at the cutoff date, not the current date. KEV status is determined by entries that existed before the cutoff.

**Fifth: PCA was removed in v2.5.** The original pipeline used PCA to reduce the 384-dim SBERT embedding to 50 dimensions, but PCA was fitted on all data including the test set before the split — a data leakage source. XGBoost handles the full 384-dim space with built-in regularisation. No dimensionality reduction needed.

The core principle: every feature must be computable using only information available at prediction time. Violate this once and your evaluation metrics are meaningless.

## Labeling Strategy

The labeling strategy is straightforward but defensible. The positive class is exploitation = 1, assigned to CVEs that appear in CISA KEV with a dateAdded within the observation window (approximately 190 days of publication). The rationale is simple: KEV is the most authoritative exploitation signal we have. If CISA has confirmed exploitation, it is real. Not theoretical, not predicted — confirmed.

The negative class is exploitation = 0, assigned to CVEs with zero KEV entry where the publication date is early enough that they would have appeared in KEV if exploited. This means the CVE must have been published at least 190 days before the evaluation date. If a CVE is six months old and not in KEV, it is almost certainly not being widely exploited. If a CVE is one week old and not in KEV, that tells us nothing — it is too early.

The class imbalance is approximately 15 to 1, negative to positive. This is handled by XGBoost's `scale_pos_weight` parameter, which is set to `n_negative / n_positive`. This tells the model to weight positive examples 15 times more heavily than negative ones during training. No SMOTE oversampling is needed. SMOTE can introduce synthetic examples that do not correspond to real exploitation patterns, and XGBoost handles class imbalance natively if you set the weight parameter correctly.

## The Corpus Scripts — A Tour

Let us walk through each script in the corpus pipeline.

**`fetch_nvd_corpus.py`:** The bulk NVD fetcher. It has two modes — API mode and feed mode — and uses checkpoint/resume to handle interruptions. It writes `nvd_corpus.json` and `nvd_checkpoint.json`. Run it when you need a fresh corpus, or run it with the `--incremental` flag to pick up new CVEs since the last checkpoint.

**`refresh_caches.py`:** Refreshes the KEV and EPSS caches. This is the script you add to your cron jobs. It is fast and idempotent — running it twice in a row produces the same result. It writes `kev_cache.json` and `epss_cache.json`.

**`build_training_corpus.py`:** The unification script. This is the most complex script in the pipeline. It loads the NVD corpus, merges in EPSS scores, KEV labels, ExploitDB features, and vendor popularity. It computes all 35 tabular features. It runs SBERT on every CVE description to produce the 384-dimensional embedding. It applies the temporal split and the observation window filter. It applies point-in-time labelling. And it writes `training_data_v2.npz`. This script takes about 45 minutes to run end to end, mostly because of the SBERT embedding generation.

**`build_vendor_index.py`:** Creates `vendor_popularity.json` from the NVD corpus. It indexes 17,100 vendors by their frequency in CVEs. This is a fast script — it runs in under a minute.

**`build_cwe_hierarchy.py`:** Parses the CWE weakness hierarchy to support the MITRE Top 25 check feature. It builds a mapping of CWE IDs to their parent categories, which allows the feature vector to include whether a CVE's weakness type is in the MITRE Top 25 list.

## What's Planned

The training data pipeline is built, but not everything has been run to completion yet. Here is what is still pending.

The XGBoost model retrain on `training_data_v2.npz` has not been executed yet. The command is `python -m ml.train_xgboost --train --data-file ml/training_data_v2.npz`. This is intentional — the corpus was built first, then validated, and the retrain is the final step. The v1 model was trained on `training_data_v1.npz`, which had fewer features and a less sophisticated temporal split. The v2 retrain will use the full 68-column feature set with the proper temporal bias fixes.

The EPSS substitution model retrain is also pending. The original EPSS substitution model (used when the real EPSS score is not available for recently published CVEs) was trained on a small surrogate dataset. The block on using real EPSS data has been lifted — 344,852 real EPSS scores are now available — so the substitution model can be retrained on actual EPSS data. This will improve the accuracy of EPSS predictions for novel CVEs that have not yet received their official EPSS score from FIRST.

And finally, the corpus needs ongoing updates. New CVEs are published every day. The incremental fetch via the checkpoint/resume mechanism handles this — `fetch_nvd_corpus.py --incremental` will pick up everything since the last checkpoint. The `refresh_caches.py` script updates KEV and EPSS. But the training corpus (`training_data_v2.npz`) is a snapshot. Retraining the model on fresh data is not automated yet. That is a natural next step — a weekly or monthly pipeline that fetches new data, rebuilds the corpus, and retrains the model.

## The Bottom Line

The training data corpus is the foundation of TriageMate's ML predictions. It is not a toy dataset — 186,102 CVEs, 344,852 EPSS scores, 1,631 KEV entries, 47,089 exploits, 17,100 vendors, 384-dimensional semantic embeddings, and 68 features per vector. The pipeline handles these with careful attention to temporal bias, point-in-time labeling, and observation window filtering. The result is a training dataset that reflects the real-world prediction problem: given a CVE at publication time, can we predict whether it will be exploited in the next six months?

The Data Supremacy sprint built the corpus. The model retrain is the next step. But the corpus itself is the lasting contribution — it is the asset that makes every ML prediction in TriageMate possible, and it was built with the rigour that cybersecurity ML demands.
