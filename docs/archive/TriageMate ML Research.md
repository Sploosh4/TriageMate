# ARCHIVED — Machine Learning Architecture and Implementation Roadmap

> **Status:** ARCHIVED — this document is the raw research output with references to a local 7B-8B decoder approach that was later rejected in favor of cloud LLM.  
> **Superseded by:** `TriageMate ML Implementation Plan — Final.md` (which corrects errors from this source, e.g., RRF ensemble → Standard XGBoost, local decoder → cloud LLM).  
> **Date archived:** 30 June 2026

---

# Machine Learning Architecture and Implementation Roadmap for the TriageMate Vulnerability Prioritization Platform

## Component 1 — XGBoost Exploitation Probability Model

### Feature Engineering and Temporal Safety Analysis

To implement the Tier 1 predictive layer, the TriageMate platform constructs a hybrid feature matrix consisting of exactly 37 tabular features concatenated with a compressed representation of security text embeddings. These features capture the dimensional relationships between vulnerability severity, global threat posture, and local network topologies.  
To prevent model degradation and look-ahead bias, every metric must be strictly "temporally safe" at the moment of evaluation. Temporal safety dictates that no information regarding post-evaluation events (such as subsequent exploitation or delayed patch details) is leaked into the training set.  
The tabular component of the hybrid matrix contains the 37 features defined in the schema below:

| Feature ID | Feature Name | Dimension Type | Representation and Encoding Scheme | Temporal Safety Rationale and Bounds |
| :---- | :---- | :---- | :---- | :---- |
| **1** | cvss\_av | Ordinal | Attack Vector: Network=3, Adjacent=2, Local=1, Physical=01 | Static property established at vulnerability disclosure2. |
| **2** | cvss\_ac | Ordinal | Attack Complexity: Low=1, High=01 | Static property established at vulnerability disclosure2. |
| **3** | cvss\_pr | Ordinal | Privileges Required: None=2, Low=1, High=01 | Static property established at vulnerability disclosure2. |
| **4** | cvss\_ui | Ordinal | User Interaction: None=1, Required=01 | Static property established at vulnerability disclosure2. |
| **5** | cvss\_s | Ordinal | Scope: Changed=1, Unchanged=01 | Static property established at vulnerability disclosure2. |
| **6** | cvss\_c | Ordinal | Confidentiality Impact: High=2, Low=1, None=01 | Static property established at vulnerability disclosure2. |
| **7** | cvss\_i | Ordinal | Integrity Impact: High=2, Low=1, None=01 | Static property established at vulnerability disclosure2. |
| **8** | cvss\_a | Ordinal | Availability Impact: High=2, Low=1, None=01 | Static property established at vulnerability disclosure2. |
| **9** | epss\_score | Continuous | Floating-point probability range ![][image1] \[cite: 3, 4\] | Reflects the daily global exploitation prediction3. |
| **10** | cisa\_kev\_status | Binary | Listed in CISA Known Exploited Vulnerabilities=1, None=03 | Evaluated at runtime using the active catalog state3. |
| **11** | patch\_available | Binary | Remediation code published by vendor=1, No patch=06 | Static historical state available at evaluation time6. |
| **12** | patch\_applied | Binary | Mitigation applied to target asset=1, Unmitigated=03 | Local configuration snapshot at the millisecond of evaluation. |
| **13** | internet\_facing | Binary | Asset resides on public IP or has active DMZ route=1, Private=05 | Dynamic routing state captured at inference time5. |
| **14** | domain\_joined | Binary | Asset belongs to enterprise Active Directory domain=1, Isolated=0 | Local domain-membership status at evaluation. |
| **15** | data\_classification | Ordinal | Restricted/PII=4, Confidential=3, Internal=2, Public=1 | Asset classification at evaluation time. |
| **16** | mission\_prevalence | Ordinal | Core Operational=3, Support=2, Peripheral=15 | Criticality metric defined prior to inference5. |
| **17** | wellbeing\_impact | Ordinal | Severe=3, Moderate=2, Minimal=17 | Organizational risk metric assigned prior to inference8. |
| **18** | lateral\_reachability | Continuous | Integer count of downstream hosts reachable via local subnet9 | Evaluated using current network adjacency metrics9. |
| **19** | boundary\_reachability | Continuous | Integer count of inbound routes crossing security zones9 | Structural network parameter calculated at evaluation. |
| **20** | downstream\_assets | Continuous | Integer count of dependent application and system nodes | Calculated using internal dependency logs. |
| **21** | patch\_lag\_days | Continuous | Integer difference: ![][image2] | Measured dynamically at inference run-time. |
| **22** | exploitdb\_has\_poc | Binary | Functional proof-of-concept exists in ExploitDB=1, None=05 | Verified against the live ExploitDB index at evaluation. |
| **23** | metasploit\_has\_payload | Binary | Active target module exists in Metasploit framework=1, None=05 | Structural threat capability state at evaluation5. |
| **24** | greynoise\_active\_scan | Binary | Systematic scanning activity observed in last 30 days=1, None=03 | Threat telemetry captured prior to inference3. |
| **25** | otx\_threat\_pulses | Continuous | Integer count of distinct AlienVault OTX pulse associations | Real-time community threat indicator volume. |
| **26** | nvd\_reference\_count | Continuous | Total reference hyperlinks listed in NVD entry | Measure of public vulnerability visibility. |
| **27** | cve\_desc\_tokens | Continuous | Absolute character length of official CVE text description10 | Static text attribute of the vulnerability. |
| **28** | vulnerability\_age\_days | Continuous | Integer difference: ![][image3] | Baseline age metric, calculated at evaluation. |
| **29** | vendor\_popularity\_index | Continuous | Normalized frequency index ![][image1] of vendor products | Historical representation of target platform footprint. |
| **30** | cvss\_exploitability\_sub | Continuous | CVSS v3.1 Exploitability sub-score range ![][image4] \[cite: 11\] | Mathematical derivation of static metrics. |
| **31** | cvss\_impact\_sub | Continuous | CVSS v3.1 Impact sub-score range ![][image5] \[cite: 12\] | Mathematical derivation of static metrics. |
| **32** | is\_top\_25\_cwe | Binary | Categorized under the current MITRE Top 25 CWE list=1, None=0 | Determined by matching CWE-ID at evaluation. |
| **33** | is\_rce\_signature | Binary | Word sequence matches remote code execution patterns=1, None=012 | Binary string parsing of vulnerability class. |
| **34** | is\_privesc\_signature | Binary | Word sequence matches privilege escalation patterns=1, None=0 | Binary string parsing of vulnerability class. |
| **35** | is\_bypass\_signature | Binary | Word sequence matches authorization bypass patterns=1, None=013 | Binary string parsing of vulnerability class. |
| **36** | is\_dos\_signature | Binary | Word sequence matches denial of service patterns=1, None=014 | Binary string parsing of vulnerability class. |
| **37** | is\_traversal\_signature | Binary | Word sequence matches directory traversal patterns=1, None=0 | Binary string parsing of vulnerability class. |

Each category of tabular metrics is designed to prevent "look-ahead bias" during training. Features related to vulnerability metadata are static values assigned at disclosure, while environmental parameters represent the configuration state of the asset at the exact millisecond of evaluation. This ensures that the model relies exclusively on historical and contemporary indicators, rather than future outcomes.

### Text Embedding Integration and Dimensionality Reduction

Integrating raw high-dimensional text embeddings directly into gradient boosted trees causes significant coordinate-wise tree partitioning failures15. Because tree-based split selection evaluates orthogonal boundaries along single dimensions, a 384- or 768-dimensional space is highly sparse, leading to computational inefficiency, a high risk of overfitting, and split-evaluation failures on limited datasets15.  
For the text embedding component, the all-MiniLM-L6-v2 SBERT model (384 dimensions) is recommended16. In resource-constrained developer environments running strictly on CPU, this model executes approximately 1.66x faster than larger options such as all-mpnet-base-v2 (768 dimensions), while retaining nearly equivalent downstream semantic capture17.  
To compress the SBERT embeddings before concatenating them with the 37 tabular features, Principal Component Analysis (PCA) is preferred over Uniform Manifold Approximation and Projection (UMAP)18. Although UMAP preserves local topological structures14, its out-of-sample projection is computationally intensive, non-linear, and mathematically unstable during real-time inference on a CPU18. In contrast, PCA is a deterministic, linear projection18. Benchmarks show that PCA achieves comparable downstream classification accuracy to UMAP while running up to 54x faster18.  
Projecting the 384-dimensional SBERT vectors down to 32 dimensions preserves more than 85% of the textual variance18. This reduction maintains a compact feature space, allowing the combined feature matrix (37 tabular features + 32 PCA text dimensions = 69 features) to be processed efficiently by a gradient boosting engine15.

### Training Data Construction and Class Alignment

The primary challenge in building an exploitation probability model is aligning public threat feeds with asset-specific states. A robust, open-source dataset can be constructed through structured data ingestion:

* **Target Label Construction**: The target variable represents whether a vulnerability was exploited in the wild within 30 days of disclosure3. The positive class (![][image6]) is defined as any CVE listed in the CISA KEV catalog3, or recorded by GreyNoise as having "active scanning" or "observed in the wild" status within a 30-day window following its initial publication3. The negative class (![][image7]) is defined as any CVE with zero exploitation activity across CISA KEV, GreyNoise, and AlienVault OTX during the same observation window21.  
* **Handling Class Imbalance**: With only approximately 1,200 entries in the CISA KEV catalog compared to over 200,000 total CVEs21, the dataset exhibits an extreme class imbalance (![][image8]). Resampling techniques like SMOTE can distort high-dimensional text structures if applied prior to dimensionality reduction19. The recommended path is cost-sensitive learning implemented directly within the XGBoost loss function using the scale\_pos\_weight parameter21. This parameter is set to the ratio of negative to positive samples, penalizing false negatives on the minority class without introducing synthetic data distortion21.  
* **Asset-Level Probability Adjustment**: No public dataset contains specific enterprise internal asset exploitation records4. Therefore, the core model must be trained on global exploitation outcomes utilizing NVD, EPSS, and threat indicators27. Asset customization is achieved at runtime by including the 11 asset-specific environmental features (Features 11–21 in the feature table) within the feature matrix. At inference time, the tree splits naturally adjust the global exploitation probability based on asset parameters, such as whether the system is internet-facing or missing a critical patch5.

### Model Training, Calibration, and Entropy-Based Escalation

For a dataset containing 5,000 to 20,000 records, the baseline hyperparameters for the XGBoost binary classifier are configured to prevent overfitting on the PCA-projected text dimensions:

Python  
import xgboost as xgb  
from sklearn.calibration import CalibratedClassifierCV

\# Base XGBoost hyperparameter initialization  
base\_model \= xgb.XGBClassifier(  
    max\_depth=4,                  \# Restricts tree depth to prevent memorization of sparse features  
    learning\_rate=0.03,           \# Slow learning rate to ensure stable convergence  
    n\_estimators=800,             \# High estimators paired with early stopping  
    subsample=0.8,                \# Row subsampling to add variance robustness  
    colsample\_bytree=0.8,         \# Column subsampling per split  
    scale\_pos\_weight=15.0,        \# Balanced ratio based on the positive-to-negative class distribution  
    tree\_method="hist",           \# Optimized CPU histogram algorithm for speed  
    random\_state=42  
)

Raw probabilities output by boosting trees are typically poorly calibrated21. To address this, Platt scaling (logistic calibration) is implemented using scikit-learn's CalibratedClassifierCV21. For datasets under 20,000 samples, Platt scaling is preferred over Isotonic regression, as it uses a parametric sigmoidal mapping that is less prone to overfitting on sparse regions of the feature space21.  
To determine whether a prediction is ambiguous and requires escalation to Tier 2, the Shannon entropy of the calibrated probability ![][image9] is calculated as follows:  
![][image10]  
To establish the exact escalation boundaries, the roots of the entropy equation must be evaluated where ![][image11]28. Solving this equation yields two symmetric probabilities28:  
![][image12]  
Thus, the escalation rule is defined as:  
![][image13]  
This means that if the calibrated probability of exploitation within 30 days is between ![][image14] and ![][image15], the prediction entropy exceeds ![][image16]28, and the vulnerability must be escalated to the Tier 2 Small Language Model for structural conflict resolution.

## Component 2 — Small Language Model for Text Conflict Resolution

### Local Encoder Selection for CWE Classification

For mapping unstructured CVE descriptions to the MITRE Common Weakness Enumeration (CWE) hierarchy, the local encoder model should be selected based on computational efficiency and task specialization23.  
Between ModernBERT and RoBERTa-base, ModernBERT-base is selected17. Incorporating architectural improvements such as FlashAttention, rotary positional embeddings, GeGLU activations, and the removal of bias terms, ModernBERT achieves a 1.66x increase in CPU inference throughput and a 39% reduction in training sequence encoding time compared to standard RoBERTa17. Additionally, ModernBERT natively supports an 8192-token context window, eliminating sequence truncation issues during the ingestion of dense technical advisories17.  
The optimal off-the-shelf classifier for this task is bziemba/SecureBERT2.0-final1. This is a domain-adapted model trained on cybersecurity text1. Rather than utilizing a single classification head, it features a Multi-Task Learning (MTL) architecture with 12 distinct linear classification heads attached to the pooled outputs1:

* **8 CVSS Heads**: MLPs mapping input text directly to CVSS v3.1 categorical ratings1.  
* **4 CWE Heads**: MLPs mapping mean-pooled token embeddings to the 4-level MITRE CWE taxonomy (Pillar, Class, Base, and Variant)1.

If custom fine-tuning is required, the National Vulnerability Database (NVD) contains over 200,000 labeled CVE-to-CWE mappings, which provides a highly sufficient training set21. The dataset should be partitioned using an 80/10/10 train/validation/test split stratified across the top 50 CWE parent categories to ensure robust representation of rare vulnerability classes23.

### Cloud LLM Provider and Structured Output Selection

For the reasoning and text-conflict resolution phase, hosting a local 7B or 8B parameter model on a developer machine can introduce significant CPU and memory bottleneck issues31. To optimize performance, the MVP utilizes a cloud-based LLM API. The table below details the performance, compliance, and cost characteristics of key cloud providers:

| Provider | Model Name | JSON Compliance Mechanism | Conflict Detection Accuracy | Median Latency (1K Tokens) | Input Cost (per 1M Tokens) | Output Cost (per 1M Tokens) |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **OpenAI** | gpt-4o-mini | Structured Outputs (strict: true) via FSM32 | High | ![][image17] | $0.1534 | $0.6034 |
| **Anthropic** | claude-3-5-sonnet | Tool Use forcing response schema35 | Exceptional | ![][image17] | $3.0037 | $15.0037 |
| **Together AI** | meta-llama/Llama-3-8b | JSON Mode (syntax-only validation)32 | Moderate | ![][image17] | $0.20 | $0.20 |

OpenAI's gpt-4o-mini is recommended as the primary model for the MVP, with Anthropic's claude-3-5-sonnet configured as a secondary high-accuracy fallback34. OpenAI's "Structured Outputs" engine provides a distinct technical advantage for security parsing: when strict: true is enabled, the API compiles the target JSON schema into a Context-Free Grammar or Finite State Machine (FSM) at the decoding layer32. This limits token selection to schema-valid transitions, guaranteeing 100% adherence to the requested data model32. This avoids the validation failures common to standard regex parsing or syntax-only JSON modes32.  
The KNOWN\_CONFLICTS fallback dictionary is initialized with verified historical CVE mappings to handle known edge cases deterministically. The adversarial prompt is structured to guide the model through a logical "force-reflection" sequence:

Python  
import os  
from openai import OpenAI  
from pydantic import BaseModel, Field

client \= OpenAI(api\_key=os.environ.get("OPENAI\_API\_KEY"))

class ConflictResolution(BaseModel):  
    text\_conflict: bool \= Field(description="True if the vendor advisory contains explicit mitigating controls that contradict raw CVE description severity.")  
    conflict\_note: str \= Field(description="Analysis explaining the contradiction between exploitability claims and vendor constraints.")  
    resolution: str \= Field(description="Final prioritization determination, balancing raw severity against local operational controls.")  
    confidence: float \= Field(description="Numerical evaluation of resolution certainty from 0.0 to 1.0.")  
    score\_adjustment: int \= Field(description="Score modifier in the range \[-20, 20\] based on the severity of the identified conflict.")

def resolve\_vulnerability\_conflict(cve\_desc: str, cwe\_class: str, epss: float, cvss\_vector: str, rag\_context: str) \-\> ConflictResolution:  
    system\_prompt \= (  
        "You are an expert security analyst operating in an automated triage pipeline. "  
        "Your task is to analyze raw vulnerability metrics, vendor advisories, and internal asset configurations "  
        "to resolve text-based risk conflicts. You must follow a strict reasoning chain:\\n"  
        "1. Formulate a primary exploitability hypothesis based on the CVE description.\\n"  
        "2. Formulate a strong counter-argument highlighting negative constraints in the vendor advisory "  
        "(e.g., 'only exploitable if a non-default module is enabled').\\n"  
        "3. Incorporate the provided RAG context to verify whether the asset is configured with these mitigations.\\n"  
        "4. Determine the final risk adjustment and output the result in the required JSON schema."  
    )  
       
    user\_content \= (  
        f"CVE Description: {cve\_desc}\\n"  
        f"Predicted CWE Class: {cwe\_class}\\n"  
        f"EPSS Probability: {epss}\\n"  
        f"CVSS Vector: {cvss\_vector}\\n"  
        f"Internal Asset RAG Context: {rag\_context}"  
    )

    completion \= client.beta.chat.completions.create(  
        model="gpt-4o-mini",  
        messages=\[  
            {"role": "system", "content": system\_prompt},  
            {"role": "user", "content": user\_content}  
        \],  
        response\_format=ConflictResolution, \# Guarantees 100% schema compliance via FSM constraint  
        temperature=0.0                    \# Set to zero to minimize hallucination and ensure output consistency  
    )  
       
    return completion.choices\[0\].message.parsed

### Retrieval-Augmented Generation (RAG) Architecture

To verify asset configurations against vendor-defined mitigations, a local-first RAG pipeline is implemented31.  
The embedding model and vector database selection are optimized for CPU environments using local resources31:

| Vector Database | Architecture Type | Setup Complexity | CPU Query Latency (1K Docs) | Memory Footprint | Python API Integration |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **LanceDB** | Embedded / Columnar | Minimal (No server required)38 | Sub-millisecond38 | Low (Shared via memory-map)39 | Direct Python native package38 |
| **ChromaDB** | Client-Server | Simple (Built-in SQLite option)40 | ![][image18] | Moderate | Heavy Python package16 |
| **FAISS** | In-Memory Library | Complex (Requires index compilation)38 | ![][image19] | High (Fully bound to RAM) | C++ wrapper, limited metadata queries |

LanceDB is selected as the primary vector store38. Running as an embedded library directly within the FastAPI process, LanceDB requires no separate database server, has a minimal memory footprint, and utilizes the Apache Arrow columnar format to perform zero-copy vector operations38. This architecture achieves sub-millisecond CPU query latency on datasets under 10,000 documents38.  
For document indexing, all-MiniLM-L6-v2 is selected16. Pre-computing embeddings using this model maintains low memory overhead and ensures query-to-document alignment within the same embedding space as the Tier 1 text processor16. If the internal documentation includes highly complex system specifications or security compliance documents, a domain-adapted model like BAAI/bge-large-en-v1.5 is preferred to capture fine-grained technical nuances31.  
Technical documents (such as system runbooks and configuration templates) are parsed using markdown-header chunking42. This preserves the hierarchical path of the document (e.g., \#\# Databases \-\> \#\#\# Production SQL Server Configuration) and prepends it to each extracted text chunk42. Large sections are recursively split at a maximum limit of 512 tokens with a 128-token overlap to prevent splitting configuration blocks across chunk boundaries42.  
At runtime, the retrieval engine queries the vector store using a hybrid search query pattern:

Python  
def retrieve\_asset\_context(hostname: str, predicted\_cwe: str) \-\> str:  
    \# Build a targeted hybrid query combining local hostname and mapped CWE class  
    query\_text \= f"Security configurations, mitigations, default settings, and active hardening parameters for {hostname} to resolve {predicted\_cwe}"  
       
    \# Query LanceDB table using hybrid semantic search  
    table \= db.open\_table("asset\_documentation")  
    results \= table.search(query\_text).limit(3).to\_list()  
       
    return "\\n\\n".join(\[r\["text"\] for r in results\])

Retrieved RAG documents are injected directly into the user prompt as structured context44. To balance inference costs with retrieval quality, context injection is restricted to a maximum window of 2,000 tokens (approximately 4 high-relevance chunks)46. This minimizes API input costs and prevents model attention degradation ("lost in the middle" effects) during processing46.

### Graceful Degradation and API Resilience

To ensure the automated triage pipeline remains resilient during cloud API outages, the platform implements a structured fallback sequence:

1. **Step A — Exponential Backoff Retry**: When a network timeout or connection failure occurs, the pipeline executes three retry attempts with exponential backoff (![][image20] seconds, where ![][image21]).  
2. **Step B — Secondary Provider Fallback**: If the primary OpenAI endpoint remains unreachable, the system automatically redirects the query to a secondary hosted service (e.g., Together AI) using an equivalent model configuration34.  
3. **Step C — Fail Secure and Escalate**: If both cloud connections fail, the system runs the local fallback mode. Instead of failing open (returning a neutral assessment), the pipeline reverts to the conservative Tier 1 exploitation probability score, raises the target asset's risk score, and routes the case directly to the Tier 3 manual security queue3.

This fail-secure strategy ensures that critical vulnerabilities are never missed due to temporary API failures3.

### Prompt Caching and Token Cost Optimization

To minimize operational costs, the prompt structure is optimized for provider-side caching engines, such as Anthropic's prompt caching and OpenAI's automated cache lookups46.  
Because both providers perform cache lookups from the beginning of the prompt sequence46, the prompt is structured hierarchically. The static, high-token instructions (such as the system prompt, output JSON schemas, and structural reasoning guidelines) are placed first to maximize prefix matches across repeated executions46:

1. **Static Segment (Cache Key Prefix)**: Contains the system instructions, operational constraints, and target JSON schema (approx. 1,250 tokens)46. This remains identical across all API calls46.  
2. **Dynamic Segment (Cache Uncached Suffix)**: Contains the retrieved RAG document chunks, target CVE metrics, and specific asset attributes (approx. 1,500 tokens). This changes with each unique vulnerability assessment.

Under this layout, the static segment remains cached in memory46. On OpenAI, cache hits receive a 50% discount46, while Anthropic's explicit cache reads are discounted by up to 90%, significantly reducing the operational cost of the RAG pipeline46.

## Component 3 — Pre-Tier — Mission Prevalence and Public Well-Being Multi-Label Classifier

### Feature Engineering for Asset Classification

To determine an asset's organizational criticality and impact prior to vulnerability triage, the model relies on typical Active Directory (AD) configurations, network scans, and system architecture features50. The table below outlines the extraction and encoding strategies for these high-cardinality and categorical attributes:

| Raw Asset Attribute | Extraction and Parse Pattern | Encoding Strategy | Technical Justification |
| :---- | :---- | :---- | :---- |
| **Active Directory OU Path** | Parses hierarchical string elements (e.g., OU=Child Protection,OU=Communities,DC=wa,DC=gov) | **Target Encoding** (Out-of-fold calculation)50 | Prevents dimension explosion while preserving the operational risk profile of the business unit. |
| **VLAN / Subnet Prefix** | Extracts IP range from local route registers (e.g., 10.142.12.0/24) | **Binary Segment Indicators** (e.g., is\_dmz, is\_core\_vlan)5 | Directly captures exposure boundaries and network isolation parameters9. |
| **Installed Applications (CPE)** | Matches application names using regex matching patterns | **One-Hot Encoding** (Restricted to top 50 application categories) | Directly correlates with specific technical assets (e.g., MOVEit, Confluence)12. |
| **Service Account Privileges** | Evaluates the maximum privilege level of active service accounts | **Ordinal Encoding** (DomainAdmin=3, LocalSystem=2, LowPrivilege=1)51 | Measures the technical blast radius of a credential compromise51. |
| **Hostname Nomenclature** | Extracts subdomains from host strings (e.g., .health.wa.gov.au ![][image22] health) | **Binary Indicators** per designated public sector category | Maps hostnames directly to functional domains like emergency services, finance, or law enforcement. |
| **Connection Counts** | Integrates inbound/outbound edge volumes from network flow logs | **Logarithmic Scaling**: ![][image23] | Compresses heavily skewed network flow metrics to stabilize model training. |

### Model Architecture for Multi-Label Asset Criticality

The classification task requires predicting two distinct multi-class target labels for each asset:

1. **Mission Prevalence**: Core (3), Support (2), Peripheral (1)5.  
2. **Public Well-Being Impact**: Severe (3), Moderate (2), Minimal (1)7.

Because neural networks tend to overfit on small asset datasets (typically 200–500 labeled records), the recommended architecture is a MultiOutputClassifier wrapping a RandomForestClassifier from scikit-learn24. This model is computationally lightweight, interpretable, and less prone to overfitting on low-sample tabular data24.  
The ensemble configures 150 decision trees with max\_depth=6 to restrict model capacity and prevent the memorization of high-cardinality noise52.  
To handle class imbalance—such as the relative scarcity of Core/Severe assets compared to Support/Minimal systems—the classifier uses the balanced\_subsample weighting scheme. This dynamically adjusts the class weights per tree based on the bootstrap distribution, correcting for class imbalance without the computational overhead of synthetic sampling algorithms like SMOTE-NC on mixed data types19.

### Training Data Construction and Active Learning

To bootstrap the training process without an existing labeled corpus, security analysts can define initial rules-based mappings by leveraging public sector cybersecurity standards:

* **NIST SP 800-60 Volume II**: Maps specific federal business functions and data types (e.g., medical records, financial transactions) directly to confidentiality, integrity, and availability impact values50.  
* **Australian Information Security Manual (ISM)**: Defines baseline system security classification models and baseline controls based on classification level54.

These standards are used to write a deterministic heuristics parser that automatically labels an initial set of 200 assets based on active directory path keywords and hostname subdomains50.  
To optimize manual labeling efforts, the platform implements an uncertainty active learning loop44. The active learning engine runs model inference across the unlabeled asset inventory and selects the top 20 assets where prediction entropy is highest (representing maximum classification uncertainty)44. These high-value samples are sent to security analysts for validation44. This loop reduces the total labeling requirement by up to 60% compared to random sampling, establishing a high-accuracy baseline with minimal manual input44.

## Component 4 — EPSS Substitution Model

### Model Design: Sector-Adjusted Meta-Scorer

The standard Exploit Prediction Scoring System (EPSS) calculates global exploitation probabilities, which can fail to reflect risk when vulnerabilities are weaponized against specific industry sectors3. For example, a CVE targeting public administration or social services infrastructure might maintain a low global EPSS score of 0.065, while actively posing a critical threat to specialized public sector systems3.  
To resolve this limitation, the platform implements a meta-scorer that dynamically adjusts the base EPSS score using industry-specific threat signals:

                                  \[FIRST.org API: Raw EPSS Score\]  
                                                 |  
                                                 v  
                                   \[Sector Threat Multiplier (S\_m)\]  
                                                 |  
                                                 v  
                                \[Adjusted EPSS = Raw EPSS \* S\_m\]

The Sector Threat Multiplier (![][image24]) is calculated dynamically using real-time threat data:  
![][image25]  
Where:

* ![][image26] is the proportion of AlienVault OTX pulses and GreyNoise indicators targeting the asset's specific sector relative to global observations3.  
* ![][image27] is an indicator variable set to 1 if the CVE is in the CISA KEV catalog and associated with campaigns targeting the asset's industry sector, and 0 otherwise3.  
* ![][image28] and ![][image29] are scaling parameters set to ![][image30] and ![][image31] based on historical campaign patterns to adjust the final score.

These threat signals can be constructed from public sources:

* **CISA KEV Catalog Metadata**: Profiles the victim industries targeted in documented cyber campaigns3.  
* **GreyNoise and AlienVault OTX Sector Tags**: Captures scanning activity and adversary indicators across specific industry subnets, such as health, finance, or government networks3.

This meta-model architecture provides a highly targeted, sector-specific exploitation probability estimate.

### Pipeline Integration and Visualization

The substitution model is integrated directly within the feature pre-processing pipeline. It runs selectively based on a threshold-based activation rule. It is triggered only when:  
![][image32]  
This ensures that the model only alters global values when there is a significant, sector-specific threat3.  
To maintain transparency, the original EPSS score remains visible within the user interface3. The modified score is presented alongside it, clearly labeled as a "TriageMate Internal Alternate Metric Substituted"3, and includes a structural explanation detailing the sector-based justification:

+-------------------------------------------------------------------------------+  
| \[!\] TRIAGEMATE RISK EXCEPTION: METRIC SUBSTITUTION DETECTED                   |  
|-------------------------------------------------------------------------------|  
| Global EPSS Score (Raw):    0.065  (Low predicted probability)                |  
| Substituted Local Metric:   0.720  (High local sector risk)                   |  
| Model Confidence Value:     0.790                                             |  
|                                                                               |  
| Substitution Justification:                                                   |  
| Active target campaigns detected targeting the government social services    |  
| sector (Sector Threat Multiplier: 11.08x). CVE-2023-36884 is weaponized       |  
| against regional public sector assets.                                        |  
+-------------------------------------------------------------------------------+

## Consolidated Implementation Priority and Technical Specification

The structured implementation roadmap below outlines the deployment priority for each component, organized from immediate, data-independent tasks to long-term data collection efforts.

### 1. Tier 2 Cloud LLM Triage Interface

* **Priority**: High (Can implement today with zero external data).  
* **Technical Objective**: Implement the core fastapi routing structure, connect to OpenAI's structured completions API, and wire up the fallback dictionary for known edge cases33.  
* **File Path**: app/ml/tier\_2.py  
* **Dependencies**: openai\>=1.12.0, pydantic\>=2.6.0, fastapi\>=0.109.0  
* **Implementation Details**:  
  Python  
  from fastapi import FastAPI, HTTPException  
  from pydantic import BaseModel, Field  
  import os

  app \= FastAPI()

  \# Initialize the internal resolution cache for deterministic override rows  
  KNOWN\_CONFLICTS \= {  
      "CVE-2023-36884": {  
          "text\_conflict": True,  
          "conflict\_note": "Office HTML RCE vulnerability mitigated strictly by registry keys.",  
          "resolution": "Override to Attend. Critical if Microsoft Office is not hardened with registry mitigations.",  
          "confidence": 0.95,  
          "score\_adjustment": 15  
      }  
  }

### 2. Embedded Document Store and RAG Core

* **Priority**: High (Can implement today with zero external data).  
* **Technical Objective**: Deploy an embedded, local vector database inside the application process to handle query vector operations and chunk management38.  
* **File Path**: app/ml/vector\_store.py  
* **Dependencies**: lancedb\>=0.5.0, sentence-transformers\>=2.3.0, pyarrow\>=15.0.0  
* **Implementation Details**:  
  Python  
  import lancedb  
  import pyarrow as pa

  \# Setup an embedded LanceDB database on the local developer machine  
  db \= lancedb.connect("/tmp/triagemate\_lancedb")  
  schema \= pa.schema(\[  
      pa.field("vector", pa.list\_(pa.float32(), 384)), \# Sentence-Transformers output  
      pa.field("text", pa.string()),  
      pa.field("metadata", pa.string())  
  \])  
  tbl \= db.create\_table("asset\_documentation", schema=schema, exist\_ok=True)

### 3. Tier 1 SBERT Encoder and Dimensionality Reduction

* **Priority**: Medium (Can implement this week using public data only).  
* **Technical Objective**: Deploy the local text classification engine, configure SBERT encoding, and implement the PCA dimensionality reduction step18.  
* **File Path**: app/ml/encoder.py  
* **Dependencies**: transformers\>=4.37.0, scikit-learn\>=1.4.0, numpy\>=1.26.0  
* **Implementation Details**:  
  Python  
  from sentence\_transformers import SentenceTransformer  
  from sklearn.decomposition import PCA  
  import numpy as np

  \# Load lightweight SBERT model optimized for CPU execution \[cite: 16, 17\]  
  embedder \= SentenceTransformer('all-MiniLM-L6-v2', device='cpu')  
  pca\_reducer \= PCA(n\_components=32, random\_state=42)

### 4. CWE Multi-Head Encoder Classifier

* **Priority**: Medium (Can implement this week using public data only).  
* **Technical Objective**: Configure the local multi-head classifier to resolve CVE descriptions to the CWE taxonomy1.  
* **File Path**: app/ml/cwe\_classifier.py  
* **Dependencies**: torch\>=2.2.0, transformers\>=4.37.0  
* **Implementation Details**:  
  Python  
  from transformers import AutoTokenizer, AutoConfig  
  import torch.nn as nn

  \# bziemba/SecureBERT2.0-final is loaded locally for multi-head inference  
  tokenizer \= AutoTokenizer.from\_pretrained("bziemba/SecureBERT2.0-final")  
  config \= AutoConfig.from\_pretrained("bziemba/SecureBERT2.0-final")

### 5. Tier 1 XGBoost Exploitation Predictor

* **Priority**: Medium (Can implement this week using public data only).  
* **Technical Objective**: Train and export the gradient boosting classifier, utilizing cost-sensitive learning to balance classes21.  
* **File Path**: app/ml/xgboost\_predictor.py  
* **Dependencies**: xgboost\>=2.0.3, scikit-learn\>=1.4.0  
* **Implementation Details**:  
  Python  
  import xgboost as xgb  
  from sklearn.calibration import CalibratedClassifierCV

  model \= xgb.XGBClassifier(  
      max\_depth=4,  
      learning\_rate=0.03,  
      scale\_pos\_weight=15.0, \# Adjusts for positive-to-negative class imbalance  
      tree\_method="hist"  
  )

### 6. Pre-Tier Asset Criticality Model

* **Priority**: Low (Requires 1–4 weeks of internal asset data collection).  
* **Technical Objective**: Train a multi-label classification model on analyst-labeled assets, using AD and network configuration features50.  
* **File Path**: app/ml/pre\_tier.py  
* **Dependencies**: scikit-learn\>=1.4.0, pandas\>=2.2.0  
* **Implementation Details**:  
  Python  
  from sklearn.ensemble import RandomForestClassifier  
  from sklearn.multioutput import MultiOutputClassifier

  pre\_tier\_classifier \= MultiOutputClassifier(  
      estimator=RandomForestClassifier(  
          n\_estimators=100,  
          class\_weight="balanced\_subsample", \# Optimizes for rare class imbalance  
          random\_state=42  
      )  
  )

### 7. EPSS Dynamic Substitution Engine

* **Priority**: Low (Requires 1–4 weeks of threat intelligence feed integration).  
* **Technical Objective**: Implement the dynamic adjustment module to modify global EPSS scores based on sector-specific threat activity3.  
* **File Path**: app/ml/epss\_substitutor.py  
* **Dependencies**: pandas\>=2.2.0, numpy\>=1.26.0  
* **Implementation Details**:  
  Python  
  import numpy as np

  def compute\_sector\_epss(raw\_epss: float, sector\_multiplier: float) \-\> float:  
      \# Scales raw EPSS score dynamically  
      adjusted\_epss \= raw\_epss \* sector\_multiplier  
      return float(np.clip(adjusted\_epss, 0.0, 1.0))

#### Works cited

1. bziemba/SecureBERT2.0-final \- Hugging Face, [https://huggingface.co/bziemba/SecureBERT2.0-final](https://huggingface.co/bziemba/SecureBERT2.0-final)  
2. Severity prediction of software vulnerabilities using convolutional neural networks | Information and Computer Security \- Emerald Insight, [https://www.emerald.com/ics/article/33/4/613/1249850/Severity-prediction-of-software-vulnerabilities](https://www.emerald.com/ics/article/33/4/613/1249850/Severity-prediction-of-software-vulnerabilities)  
3. KEV, EPSS, SSVC: Prioritise Exploitable Vulnerabilities \- Hard2bit, [https://hard2bit.com/en/blog/kev-epss-ssvc-prioritise-exploitable-vulnerabilities/](https://hard2bit.com/en/blog/kev-epss-ssvc-prioritise-exploitable-vulnerabilities/)  
4. What is the Exploit Prediction Scoring System (EPSS)? \- Safe Security, [https://safe.security/resources/insights/what-is-epss-epss-vs-cvss/](https://safe.security/resources/insights/what-is-epss-epss-vs-cvss/)  
5. A Guide to Automating Vulnerability Prioritization Using SSVC Decision Trees \- Nucleus Security, [https://nucleussec.com/wp-content/uploads/SSVC-Decision-Tree-Example-1.pdf](https://nucleussec.com/wp-content/uploads/SSVC-Decision-Tree-Example-1.pdf)  
6. SSVC: How to make decisions about IT vulnerabilities \- Tarlogic Security, [https://www.tarlogic.com/blog/ssvc/](https://www.tarlogic.com/blog/ssvc/)  
7. Actioning the Stakeholder-Specific Vulnerability Categorization (SSVC) Model | FOSSA Blog, [https://fossa.com/blog/actioning-stakeholder-specific-vulnerability-categorization-ssvc-model/](https://fossa.com/blog/actioning-stakeholder-specific-vulnerability-categorization-ssvc-model/)  
8. Stakeholder-Specific Vulnerability Categorization (SSVC) \- CISA, [https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)  
9. What is SSVC? \- SSVC: Stakeholder-Specific Vulnerability Categorization \- CERT Coordination Center on github.io, [https://certcc.github.io/SSVC/tutorials/ssvc\_overview/](https://certcc.github.io/SSVC/tutorials/ssvc_overview/)  
10. An empirical analysis of zero-day vulnerabilities disclosed by the zero day initiative \- arXiv, [https://arxiv.org/pdf/2512.15803](https://arxiv.org/pdf/2512.15803)  
11. Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits \- USENIX, [https://www.usenix.org/system/files/sec22summer\_suciu.pdf](https://www.usenix.org/system/files/sec22summer_suciu.pdf)  
12. An Empirical Analysis of Zero-Day Vulnerabilities Disclosed by the Zero Day Initiative (January–April 2024\) \- arXiv, [https://arxiv.org/html/2512.15803](https://arxiv.org/html/2512.15803)  
13. Predicting Cyber Vulnerability Exploits with Machine Learning \- ResearchGate, [https://www.researchgate.net/publication/389247484\_Predicting\_Cyber\_Vulnerability\_Exploits\_with\_Machine\_Learning](https://www.researchgate.net/publication/389247484_Predicting_Cyber_Vulnerability_Exploits_with_Machine_Learning)  
14. Recent Developments on Industrial Control Systems Resilience \[1st ed. 2020\] 978-3-030-31327-2, 978-3-030-31328-9 \- DOKUMEN.PUB, [https://dokumen.pub/recent-developments-on-industrial-control-systems-resilience-1st-ed-2020-978-3-030-31327-2-978-3-030-31328-9.html](https://dokumen.pub/recent-developments-on-industrial-control-systems-resilience-1st-ed-2020-978-3-030-31327-2-978-3-030-31328-9.html)  
15. Combining XGBoost and Embeddings: Hybrid Semantic Boosted Trees? \- MachineLearningMastery.com, [https://machinelearningmastery.com/combining-xgboost-and-embeddings-hybrid-semantic-boosted-trees/](https://machinelearningmastery.com/combining-xgboost-and-embeddings-hybrid-semantic-boosted-trees/)  
16. chunking \- LLMOps Database \- ZenML, [https://www.zenml.io/llmops-tags/chunking](https://www.zenml.io/llmops-tags/chunking)  
17. Daily Papers \- Hugging Face, [https://huggingface.co/papers?q=ModernBERT-based%20classifiers](https://huggingface.co/papers?q=ModernBERT-based+classifiers)  
18. Multi-Modal Model for Embedding Network and Audit Data for IoT Anomaly Detection \- SciTePress, [https://www.scitepress.org/Papers/2026/144703/144703.pdf](https://www.scitepress.org/Papers/2026/144703/144703.pdf)  
19. An empirical evaluation of dimensionality reduction and class balancing for medical text classification \- PMC, [https://pmc.ncbi.nlm.nih.gov/articles/PMC12780033/](https://pmc.ncbi.nlm.nih.gov/articles/PMC12780033/)  
20. Dimensionality Reduction and Machine Learning Methods for COVID-19 Classification Using Chest CT Images \- MDPI, [https://www.mdpi.com/2079-9292/15/6/1235](https://www.mdpi.com/2079-9292/15/6/1235)  
21. An Improved Vulnerability Exploitation Prediction Model with Novel Cost Function and Custom Trained Word Vector Embedding \- MDPI, [https://www.mdpi.com/1424-8220/21/12/4220](https://www.mdpi.com/1424-8220/21/12/4220)  
22. Early and Realistic Exploitability Prediction of Just-Disclosed Software Vulnerabilities: How Reliable Can It Be? \- FABIO PALOMBA, [https://fpalomba.github.io/pdf/Journals/J64.pdf](https://fpalomba.github.io/pdf/Journals/J64.pdf)  
23. Fine-tuning RoBERTa for CVE-to-CWE Classification: A 125M Parameter Model Competitive with LLMs \- arXiv, [https://arxiv.org/html/2603.14911v1](https://arxiv.org/html/2603.14911v1)  
24. Interpretability study of earthquake-induced landslide susceptibility combining dimensionality reduction and clustering \- Frontiers, [https://www.frontiersin.org/journals/earth-science/articles/10.3389/feart.2025.1577165/full](https://www.frontiersin.org/journals/earth-science/articles/10.3389/feart.2025.1577165/full)  
25. An Improved Vulnerability Exploitation Prediction Model with Novel Cost Function and Custom Trained Word Vector Embedding \- PMC, [https://pmc.ncbi.nlm.nih.gov/articles/PMC8235709/](https://pmc.ncbi.nlm.nih.gov/articles/PMC8235709/)  
26. Stakeholder-Specific Vulnerability Categorization (SSVC) \- Waterfall Security Solutions, [https://waterfall-security.com/ot-insights-center/ot-cybersecurity-insights-center/stakeholder-specific-vulnerability-categorization-ssvc-episode-102/](https://waterfall-security.com/ot-insights-center/ot-cybersecurity-insights-center/stakeholder-specific-vulnerability-categorization-ssvc-episode-102/)  
27. mnemonic-no/VEPS \- GitHub, [https://github.com/mnemonic-no/VEPS](https://github.com/mnemonic-no/VEPS)  
28. [unknown\_url](http://docs.google.com/unknown_url)  
29. AI datasets and VLAI models \- Vulnerability-Lookup, [http://www.vulnerability-lookup.org/user-manual/ai/](http://www.vulnerability-lookup.org/user-manual/ai/)  
30. ModernBERT or DeBERTaV3? Examining Architecture and Data Influence on Transformer Encoder Models Performance \- arXiv, [https://arxiv.org/html/2504.08716v1](https://arxiv.org/html/2504.08716v1)  
31. Llama Jobs, Employment \- Freelancer, [https://www.freelancer.com/job-search/llama/](https://www.freelancer.com/job-search/llama/)  
32. Reliable JSON from Any LLM: Pydantic \+ Zod (2026) | TECHSY, [https://techsy.io/en/blog/llm-structured-outputs-guide](https://techsy.io/en/blog/llm-structured-outputs-guide)  
33. Introducing Structured Outputs in the API \- OpenAI, [https://openai.com/index/introducing-structured-outputs-in-the-api/](https://openai.com/index/introducing-structured-outputs-in-the-api/)  
34. OpenAI vs Anthropic Pricing 2026: Real Cost Per Task Compared \- CostLens, [https://costlens.dev/blog/openai-vs-anthropic-cost-comparison](https://costlens.dev/blog/openai-vs-anthropic-cost-comparison)  
35. effect/ai-anthropic: Use Anthropic's native Structured Outputs instead of tool-call emulation · Issue \#6091 \- GitHub, [https://github.com/Effect-TS/effect/issues/6091](https://github.com/Effect-TS/effect/issues/6091)  
36. Enforcing JSON Outputs in Commercial LLMs \- DataChain | AI, [https://datachain.ai/blog/enforcing-json-outputs-in-commercial-llms](https://datachain.ai/blog/enforcing-json-outputs-in-commercial-llms)  
37. Anthropic vs OpenAI: Comparing Direct API Costs \- Vantage, [https://www.vantage.sh/blog/anthropic-vs-openai-api-costs](https://www.vantage.sh/blog/anthropic-vs-openai-api-costs)  
38. Best Vector Databases in 2026: A Complete Comparison Guide \- Firecrawl, [https://www.firecrawl.dev/blog/best-vector-databases](https://www.firecrawl.dev/blog/best-vector-databases)  
39. note4yaoo/lib-ai-app-community-rag.md at main \- GitHub, [https://github.com/uptonking/note4yaoo/blob/main/lib-ai-app-community-rag.md](https://github.com/uptonking/note4yaoo/blob/main/lib-ai-app-community-rag.md)  
40. awesome-mcp-servers/README.md at main \- GitHub, [https://github.com/punkpeye/awesome-mcp-servers/blob/main/README.md](https://github.com/punkpeye/awesome-mcp-servers/blob/main/README.md)  
41. 5 Lightweight Vector Databases for Gen-AI Apps in 2025 | Cybergarden, [https://cybergarden.au/blog/5-lightweight-vector-databases-gen-ai-2025](https://cybergarden.au/blog/5-lightweight-vector-databases-gen-ai-2025)  
42. The Complete Guide to Document Chunking for RAG | by Kaustav Mukherjee | Medium, [https://kaustavmukherjee-66179.medium.com/the-complete-guide-to-document-chunking-for-rag-ac312e6d635f](https://kaustavmukherjee-66179.medium.com/the-complete-guide-to-document-chunking-for-rag-ac312e6d635f)  
43. RAG and LangChain \- Webparadox, [https://webparadox.com/technologies/rag-langchain/](https://webparadox.com/technologies/rag-langchain/)  
44. Agent-Orchestrated Adaptive RAG: A Comparative Study on Structured and Multi-Hop Retrieval \- arXiv, [https://arxiv.org/html/2606.05658v1](https://arxiv.org/html/2606.05658v1)  
45. RAG Development Services | AI Retrieval Pipelines \- AlphaCorp AI, [https://alphacorp.ai/services/rag-development](https://alphacorp.ai/services/rag-development)  
46. Prompt Caching in 2026: Anthropic, OpenAI, Azure Compared \- Technspire, [https://technspire.com/blog/prompt-caching-2026-real-cost-wins](https://technspire.com/blog/prompt-caching-2026-real-cost-wins)  
47. Prompt Caching for Anthropic and OpenAI Models: Building Cost-Efficient AI Systems, [https://www.digitalocean.com/blog/prompt-caching-with-digital-ocean](https://www.digitalocean.com/blog/prompt-caching-with-digital-ocean)  
48. chatbot \- LLMOps Database \- ZenML, [https://www.zenml.io/llmops-tags/chatbot](https://www.zenml.io/llmops-tags/chatbot)  
49. Prompt Caching Infrastructure: Reducing LLM Costs and Latency \- Introl, [https://introl.com/blog/prompt-caching-infrastructure-llm-cost-latency-reduction-guide-2025](https://introl.com/blog/prompt-caching-infrastructure-llm-cost-latency-reduction-guide-2025)  
50. Integrating Physical Security Systems with a Security Operations Center, [https://securitysystemsauthority.com/security-operations-center-soc-integration/](https://securitysystemsauthority.com/security-operations-center-soc-integration/)  
51. Workato Hardening Guide, [https://howtoharden.com/guides/workato/](https://howtoharden.com/guides/workato/)  
52. Artificial Intelligence-Driven Supervised Classification Algorithm for Website Vulnerability Detection Using MITRE NVD CVE Scores \- Preprints.org, [https://www.preprints.org/manuscript/202602.0475](https://www.preprints.org/manuscript/202602.0475)  
53. BD Pro, [http://www.bdpro.ca/wp-content/uploads/2016/02/NIST800-53r4\_CSE-ITSG33\_mapping-20Feb16p.pdf](http://www.bdpro.ca/wp-content/uploads/2016/02/NIST800-53r4_CSE-ITSG33_mapping-20Feb16p.pdf)  
54. The "4W+1H" of Software Supply Chain Security Checklist for Critical Infrastructure \- arXiv, [https://arxiv.org/html/2510.26174v1](https://arxiv.org/html/2510.26174v1)  
