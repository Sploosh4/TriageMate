# TriageMate ML Research Prompt

## Your Role

You are a principal machine learning engineer and cybersecurity data scientist. Your task is to research and recommend the most practical, minimal-effort implementation path for the three machine learning components of the TriageMate vulnerability prioritization platform. TriageMate is currently an MVP with stub implementations at each ML stage. The goal is to replace each stub with a real model that can run on a single developer machine without GPU clusters, cloud APIs, or enterprise infrastructure.

The platform's pipeline architecture and API contracts are already defined. Your job is exclusively the ML layer. Do not propose architectural changes to the application. Work within the existing interfaces described below.

---

## What You Are Researching

You must provide detailed, implementable answers for four components. For each component, answer every sub-question. Cite specific libraries, model names, training datasets, and parameter values where possible. If a definitive answer does not exist in the public literature, recommend a pragmatic starting point and explain your reasoning.

---

## Component 1: Tier 1 — XGBoost Exploitation Probability Model

### Context

Tier 1 receives a vulnerability record after Tier 0 has determined it is ambiguous. The model must predict the probability that this vulnerability will be exploited against this specific asset within the next 30 days. It outputs a probability score and a confidence value. If the confidence is mid-range (Shannon entropy of the prediction exceeds 0.35), the case is escalated to Tier 2.

The model uses a hybrid feature matrix: 37 tabular features concatenated with compressed SBERT text embeddings of the CVE description. The platform documentation states that the SBERT embeddings are projected to a lower-dimensional space using PCA or UMAP to prevent coordinate-wise tree partitioning failures.

### Questions

**1a. Feature Engineering: The 37 Features**

The platform spec says "37 temporally safe features" combining CVSS vector breakdown, asset metrics, and internal exposure logs. Research and propose the exact 37 features. Your answer must include:

- The specific 8 CVSS v3.1 base metric values (AV, AC, PR, UI, S, C, I, A) as ordinal-encoded features.
- The EPSS score as a continuous feature.
- Binary features: CISA KEV status, patch available, patch applied, internet-facing, domain-joined.
- Ordinal features: data classification level (1-4), mission prevalence (Core=3, Support=2, Peripheral=1), public wellbeing impact (Severe=3, Moderate=2, Minimal=1).
- Continuous environmental features: lateral movement reachability count, cross-boundary reachability count, downstream asset count, patch lag in days.
- Any additional features you identify from the vulnerability prioritization literature that are predictive and obtainable without live threat intelligence feeds.

Explain why each feature is temporally safe — meaning it does not create look-ahead bias when the model is deployed. For example, "days since publication" is temporally safe at inference time, but "was exploited within 30 days" is a label, not a feature.

**1b. Text Embedding Integration**

Research how to integrate text embeddings into an XGBoost model without causing tree partitioning failures. Specifically:

- What dimension should the SBERT embeddings be reduced to? Research the trade-off between information retention and XGBoost performance. Is 16 dimensions sufficient? 32? 64?
- Is PCA or UMAP preferred for this specific use case (high-dimensional text embeddings concatenated with low-dimensional tabular features)? Research whether UMAP's preservation of local structure matters for vulnerability text, or whether PCA's linearity is sufficient and more stable at inference time.
- What SBERT model is appropriate? `all-MiniLM-L6-v2` (384 dimensions) is lightweight. `all-mpnet-base-v2` (768 dimensions) is higher quality. Which is the right trade-off for an MVP that must run on CPU?

**1c. Training Data**

The model needs labeled data: vulnerability records with known outcomes (exploited within 30 days vs. not exploited). Research and recommend:

- Public datasets that can serve as training data. Consider: NVD API for CVSS vectors and descriptions, FIRST.org EPSS API for exploitation probability scores, CISA KEV catalog for known-exploited labels, ExploitDB for proof-of-concept availability, GreyNoise for internet-wide scanning data, and the AlienVault OTX pulse data for exploitation indicators.
- How to construct the positive class (exploited) and negative class (not exploited) from these sources. The positive class is relatively small — CISA KEV has approximately 1,200 entries. How do you handle class imbalance? Research whether SMOTE, class weighting, or undersampling is appropriate for tree-based models.
- How to make the labels asset-specific. The model predicts exploitation probability *for a specific asset*, not globally. Research whether any public datasets include asset-level exploitation data, or whether the model must be trained on global exploitation data and then adjusted at inference time using the environmental features.

**1d. Model Training and Export**

- What XGBoost hyperparameters are a reasonable starting point for a dataset of 5,000-20,000 records with 37+ features? Research typical parameters for imbalanced binary classification with XGBoost: `scale_pos_weight`, `max_depth`, `learning_rate`, `subsample`, `colsample_bytree`.
- How should the model output be calibrated? Raw XGBoost probabilities are known to be poorly calibrated. Research whether Platt scaling or isotonic regression is preferred for vulnerability exploitation prediction, and whether the calibration should happen inside the model or as a post-processing step.
- The model must output both a probability and a confidence value. The confidence is derived from prediction entropy: `H(p) = -p*log2(p) - (1-p)*log2(1-p)`. At what entropy threshold should the model escalate to Tier 2? Research whether 0.35 is a reasonable threshold for vulnerability prediction or whether the literature suggests a different value.

---

## Component 2: Tier 2 — Small Language Model for Text Conflict Resolution

### Context

Tier 2 receives cases that Tier 1 could not confidently resolve. These cases typically involve a text conflict: the CVE description and threat intelligence say the vulnerability is severe, but the vendor advisory contains a mitigating constraint (e.g., "only exploitable if a non-default setting is enabled"). The SLM must:

1. Classify the CVE description into a Common Weakness Enumeration (CWE) class using a 125M parameter encoder.
2. Run an adversarial force-reflection loop using a 7B-8B parameter decoder:
   - Step A: Formulate a primary exploitability assessment.
   - Step B: Generate a plausible counter-argument based on negative text constraints in the advisory.
   - Step C: Query internal documentation via RAG to verify asset configuration.
   - Step D: Produce a final determination and a structured JSON output.

### Questions

**2a. Encoder Model Selection**

- Between ModernBERT and RoBERTa-base (both approximately 125M parameters), which is better suited for CWE classification of short CVE description texts? Consider that CVE descriptions are technical, structured, and relatively short (50-300 words). Research whether ModernBERT's efficiency improvements (FlashAttention, rotary embeddings) provide meaningful gains for this task, or whether RoBERTa-base's maturity and available fine-tuning resources make it more practical.
- Is there a pre-existing model fine-tuned on CWE classification that can be used off-the-shelf? Research on Hugging Face Hub and academic literature.
- If no off-the-shelf model exists, what is the training dataset? The NVD maps CVEs to CWEs. Approximately 200,000 CVE-to-CWE mappings exist. Is this sufficient for fine-tuning? What train/val/test split is appropriate?

**2b. Decoder Model Selection**

- Between Mistral 7B, Llama 3 8B, Qwen 2.5 7B, and DeepSeek 7B, which model performs best on tasks requiring structured reasoning from technical text with explicit counter-argument generation? Research whether any of these models have been evaluated on cybersecurity-specific reasoning benchmarks.
- The model must run on a single consumer GPU (8-16GB VRAM) or CPU for the MVP. Research 4-bit and 8-bit quantization options: AWQ vs. GPTQ vs. bitsandbytes NF4. Which quantization method preserves reasoning quality best for 7B-8B models?
- What is the minimum viable prompt template for the force-reflection loop? Research prompt engineering for adversarial reasoning. The template must:
  - Accept a CVE description, CWE classification, EPSS score, CVSS vector, and asset context.
  - Generate the primary assessment.
  - Generate the counter-argument.
  - Generate the final determination.
  - Output structured JSON with fields: `text_conflict` (boolean), `conflict_note` (string), `resolution` (string), `confidence` (float, 0-1), `score_adjustment` (integer).

**2c. RAG Implementation**

- What embedding model is appropriate for indexing internal documentation (Confluence pages, SharePoint documents, application runbooks, configuration files)? The documents are technical, domain-specific, and potentially long. Research whether `all-MiniLM-L6-v2` is sufficient or whether a domain-adapted model like `BAAI/bge-large-en-v1.5` is worth the additional compute.
- What vector database is appropriate for MVP scale (hundreds to low thousands of documents, single-machine deployment)? Compare ChromaDB, FAISS, and LanceDB on: ease of setup, query latency on CPU, memory footprint, and Python API ergonomics.
- What is the chunking strategy for technical documentation? Research whether fixed-size chunking (e.g., 512 tokens with 128-token overlap) is appropriate for application runbooks and configuration files, or whether semantic chunking (splitting on section boundaries) produces better retrieval quality.
- How does the RAG query get constructed at runtime? The SLM decoder generates a query based on the asset hostname and the CWE class. Research typical RAG query patterns for technical documentation search.

**2d. Fallback Strategy**

- The stub currently returns hardcoded resolutions for three known CVEs (CVE-2023-36884, CVE-2023-22515, CVE-2022-47966) and a neutral default for anything else. Research whether maintaining a curated knowledge base of known conflict resolutions is a viable long-term strategy alongside the SLM, or whether all cases should eventually go through the model.
- If the SLM returns a low-confidence resolution, what should happen? Should the case be escalated to a human analyst (Tier 3), or should the system fall back to the Tier 1 probability score?

---

## Component 3: Pre-Tier — Mission Prevalence and Public Well-Being Multi-Label Classifier

### Context

Before any tier processes a vulnerability, the Pre-Tier stage predicts two tags for the affected asset: Mission Prevalence (Core, Support, Peripheral) and Public Well-Being Impact (Severe, Moderate, Minimal). These are used as features in Tier 0, Tier 1, and the final scoring engine. The current stub uses a dictionary lookup of 7 known hostnames with hardcoded values.

### Questions

**3a. Feature Engineering**

- What features are predictive of an asset's mission criticality and public impact? Research features that are obtainable from typical agency CMDB exports and network scans:
  - Organizational Unit path in Active Directory (e.g., `OU=Child Protection,OU=Communities,DC=wa,DC=gov,DC=au`).
  - VLAN or subnet membership (e.g., DMZ vs. internal server VLAN vs. user workstation VLAN).
  - Installed applications (e.g., MOVEit Transfer suggests health data exchange; Confluence suggests knowledge management).
  - Service account privileges (domain admin vs. local system vs. dedicated service account).
  - Agency type derived from hostname (e.g., `.health.wa.gov.au` vs. `.finance.wa.gov.au` vs. `.wapol.internal.wa.gov.au`).
  - Inbound and outbound connection counts from network flow logs.
- How should these features be encoded? Agency type and OU path are categorical with high cardinality. Research whether target encoding or binary indicator encoding (one column per agency type) is more appropriate for a small training dataset.

**3b. Model Architecture**

- The task is multi-label classification with two labels, each having 3 classes. Research whether a single `MultiOutputClassifier` wrapping a `RandomForestClassifier` is sufficient, or whether a more sophisticated architecture (e.g., classifier chain, neural network with shared embeddings) is warranted.
- What is a reasonable model capacity given that training data will be small (200-500 labeled assets)? A Random Forest with 100 trees and max_depth of 10? A Gradient Boosting classifier with early stopping?
- How should class imbalance be handled? In a typical agency, most assets are Support/Minimal. Core/Severe assets are rare. Research whether class weighting is sufficient or whether oversampling techniques like SMOTE-NC (for mixed categorical/numerical data) are needed.

**3c. Training Data**

- How to construct the training dataset. The plan says 200-500 assets labeled by a security analyst. Research whether any public sector asset classification frameworks (e.g., NIST SP 800-60, Australian ISM, UK GovS 007) can bootstrap the labeling process by providing rules-based mappings from asset function to criticality.
- Is active learning appropriate here? Given that labeling requires analyst time, research whether uncertainty sampling (labeling the assets where the model is least confident) would reduce the number of labels needed.

---

## Component 4: EPSS Substitution Model

### Context

Row 5 of the demo dataset (CVE-2023-36884) has an EPSS score of 0.065 — the lowest in the dataset — but the vulnerability is actively weaponized against government social services agencies. The system substitutes an internal ML prediction of 0.72 with model confidence 0.79, trained on 47,000 CVEs with sector-weighted exploitation labels. The frontend renders this with a greyed-out container and a "TriageMate Internal Alternate Metric Substituted" label.

### Questions

**4a. Model Design**

- What type of model produces a sector-adjusted EPSS score? Research approaches:
  - A simple re-scorer: take the raw EPSS score and multiply by a sector-specific weight derived from historical targeting data.
  - A meta-model: train a model that takes the raw EPSS score, the CVE's sector relevance features, and outputs an adjusted score.
  - A separate prediction model that ignores EPSS entirely when sector targeting data is available.
- The demo says the model was trained on "47,000 CVEs with sector-weighted exploitation labels." Research where sector-weighted exploitation labels can be obtained. Do threat intelligence platforms (Mandiant, CrowdStrike, Recorded Future) publish sector-specific exploitation data? Are there public datasets?

**4b. Integration**

- Should the substitution model run on every vulnerability, or only when the raw EPSS score is below a threshold (e.g., below 0.10) AND the sector targeting data suggests higher risk?
- The substitution must be transparent to the analyst. Research best practices for presenting substituted metrics in security tools. Should the raw EPSS still be visible alongside the substituted value, or should the substitution completely replace it?

---

## Output Format

Answer each question under its component heading. For each answer, provide:

1. The recommendation.
2. The research basis (cite papers, blog posts, documentation, or benchmarks).
3. If no definitive answer exists, the pragmatic starting point and your reasoning.
4. Concrete implementation details: library name, version, function call, parameter values, file path.

At the end, provide a consolidated implementation priority list, ranked from "can implement today with zero external data" to "requires significant data collection before implementation."

---

## Constraints

- The MVP uses Python with FastAPI. All ML libraries must be Python-compatible.
- The frontend is a separate static HTML/JS application. The ML layer communicates only through the defined API contracts. Do not propose changes to the API response shape.
- The existing 7-row demo dataset must be perfectly reproducible. The ML models, when fed the inputs for those 7 rows, must produce scores within 3 points of the demo values.
- Training datasets must be publicly obtainable or constructable from public sources. Assume the team has access to NVD API, FIRST.org EPSS API, CISA KEV, ExploitDB, and common Hugging Face models, but not to commercial threat intelligence feeds.


## Addendum: Cloud API Adaptation for Tier 2

The original prompt assumes Tier 2 runs a locally-hosted 7B-8B model. The decision
has been made to use a cloud-hosted LLM API for the MVP instead. This changes the
research questions for Component 2 as follows.

### Replacement for Question 2b (Decoder Model Selection)

The original question about local model quantization and GPU requirements is replaced with:

**2b-revised: Cloud LLM Provider Selection**

- Between OpenAI (gpt-4o-mini, gpt-4o), Anthropic (claude-3-haiku, claude-3-5-sonnet), and Together AI (hosted Llama 3 8B, Mistral 7B, DeepSeek 7B), which provider and model combination produces the best structured JSON output for the adversarial force-reflection loop task? Evaluate on:
  - JSON schema adherence: does the model reliably output valid JSON with all six required fields?
  - Conflict detection accuracy: does the model correctly identify text conflicts in cybersecurity advisories?
  - Counter-argument quality: are the generated counter-arguments grounded in the actual advisory text or are they hallucinated?
  - Latency: what is the median and P99 response time for a prompt of approximately 1,000 input tokens?
  - Cost: what is the per-analysis cost at current pricing?

- Research whether any of these providers offer "structured output" or "JSON mode" features that guarantee valid JSON responses. OpenAI's `response_format: { type: "json_object" }` and Anthropic's tool-use-based structured output are examples. Does structured output mode improve reliability for this task, or does it constrain the model's reasoning quality?

- For the fallback cache (`KNOWN_CONFLICTS` dictionary), research whether there is a public dataset of CVE conflict resolutions, or whether the cache must be built entirely from internal analyst validations. If a public dataset exists, what is its coverage and quality?

### Replacement for Question 2c (RAG Implementation)

The RAG question is partially modified. The embedding model and vector database questions remain unchanged. Add:

**2c-supplement: RAG with Cloud LLM**

- When using a cloud LLM, should the RAG-retrieved documents be included in the prompt as context, or should the RAG query happen before the LLM call and only the summarized findings be passed? Research the trade-off between prompt length (cost) and retrieval quality.
- What is the maximum prompt size that makes economic sense? At gpt-4o-mini pricing, a prompt with 5,000 tokens of RAG context costs approximately $0.00075. Is this acceptable, or should the RAG context be truncated to a fixed window (e.g., 1,000 tokens)?

### Replacement for Question 2d (Fallback Strategy)

The original question is replaced with:

**2d-revised: Graceful Degradation with Cloud APIs**

- Research patterns for handling cloud API failures in ML pipelines. When the LLM API is unreachable, what is the best practice: retry with exponential backoff, fail open (return neutral assessment), or fail closed (escalate to human)? 
- The current plan fails open with a cache-first, neutral-default strategy. Research whether this is consistent with vulnerability management best practices, where a missed critical vulnerability is more costly than a false positive.
- Research whether any cloud LLM providers offer a "fallback endpoint" or multi-region deployment that reduces the risk of a single-point-of-failure. For the MVP, is it worth configuring two providers (e.g., OpenAI primary, Together AI fallback) or is this over-engineering at this stage?

### Replacement for Question 2a (Encoder Model Selection)

This question is unchanged. The encoder (125M parameter model for CWE classification) remains a locally-run model because it is small, fast, and does not benefit from a cloud API. The encoder runs locally regardless of where the decoder runs.

### New Question 2e: Prompt Caching and Cost Optimization

**2e: Prompt Caching**

- Research prompt caching strategies for the force-reflection loop. The prompt template is largely static — only the CVE description, asset context, and upstream scores change between calls. Do any cloud providers support prompt caching (e.g., Anthropic's prompt caching, OpenAI's automatic caching) that would reduce costs for repeated analyses with the same template prefix?
- If prompt caching is available, how should the prompt be structured to maximize cache hits? Should the static template come first, followed by the variable data, or vice versa?

## Implementation Priority (Cloud-Adjusted)

### Can Implement Today (Zero External Data)
1. Tier 0 deterministic rules — already real, no changes needed.
2. Tier 2 cloud LLM stub — the `tier_2.py` file above is production-ready.
   Requires only an API key in `.env`.

### Can Implement This Week (Public Data Only)
3. Tier 1 XGBoost model — train on public NVD + EPSS + CISA KEV data.
   Requires feature engineering work but zero proprietary data.
4. Tier 2 encoder (CWE classifier) — fine-tune ModernBERT on NVD CWE mappings.
   Public dataset of 200,000 labeled examples exists.

### Requires Data Collection (1-4 Weeks)
5. Pre-Tier multi-label classifier — requires 200-500 internally labeled assets.
   Can start with rules-based heuristics as a bridge.
6. EPSS substitution model — requires sector-weighted exploitation data.
   A simple heuristic sector multiplier can serve as interim solution.
7. RAG document store — requires indexing internal Confluence/SharePoint.
   Start with a small pilot of 50-100 documents.
