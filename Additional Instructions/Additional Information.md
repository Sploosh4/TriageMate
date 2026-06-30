# **Following a Piece of Data: The TriageMate Pipeline Journey**

## Phase 1: Pre-Tier Ingestion and Validation

### 1\. Data Entry and State

* **Incoming Payload:** Data enters the system as a raw vulnerability record pulled from an automated vulnerability scanner export.  
* **Accompanying Data:** At this entry point, the record should consist of:  
  1. Raw text description  
  2. Target IP address  
  3. Base CVSS severity score  
  4. Detected software versions

### 2\. Processing and Transformations

* **Event-Driven Schema Check:** The record passes through an event-driven validation layer that checks the log structure for malformed formatting or schema drift.  
  1. If it is considered malformed, the log is noted as malformed and TriageMate attempts to recover the CVSS score & raw text description by accessing a CVE database (updated daily).  
* **CMDB / Asset Registry Confirmation:** TriageMate then attempts to match the IP address found in the organisation's CMDB / Asset Registry. If it cannot be found, it is tagged, and additional processing happens:  
  1. **Gathering Telemetry:** Using the confirmed IP address, TriageMate pulls telemetry from Active Directory for OU paths, system group memberships and network flow logs.  
  2. **Asset Criticality Mapping:** The telemetry is fed into a multi-label machine learning classifier. This model processes the network connections and directory pathways to predict and attach a Mission Prevalence tag (e.g. support) and a Public Well-Being impact tag (e.g. minimal) to the vulnerability payload.

## Phase 2: Tier 0 Deterministic Baseline

### 1\. Data Entry and State

* **The Ingested Payload:** Data at this point can now contain a raw CVE attribute, the newly predicted asset criticality, and environmental scope tags.  
* **Accompanying Data:** The system pulls down external live threat intelligence feeds, pairing the record with its daily recalculated EPSS score and its current binary status in the CISA Known Exploited Vulnerabilities (KEV) catalog.

### 2\. Processing and Transformations

* **Deterministic Metric Check:** Tier 0 runs the record through a zero-cost rule filter to check if it hits automatic execution metrics.  
* **The Evaluation:** Any data marked as low or very critical by the zero-cost rule filter stops here.  
  * For the calculated low severity vulnerabilities, they are marked to be checked within 7 days (to see if the KEV, EPSS score has changed, or more information is given).  
  * For the calculated very critical vulnerabilities, they are automatically routed as top priority, and are put at the top of the list.  
  * For the calculated medium, or critical, they are moved on to the next tier as potentially ambiguous.

## Phase 3: Tier 1 Machine Learning Ensemble

### 1\. Data Entry and State

* **The Ingested Payload:** The record arrives at the ML tier bearing the raw attributes, the Tier 0 evaluations, and live network exposure logs gathered from perimeters like firewalls or web application firewalls (WAFs).

### 2\. Processing and Transformations

* **Embedding Compression:** The raw, unstructured text description is converted into high-dimensional SBERT text embeddings. To prevent coordinate-wise tree partitioning from failing, these high-dimensional vectors are projected onto a lower-dimensional space using PCA or UMAP compression.  
* **Feature Fusion:** These compressed text components are cleanly concatenated with 37 tabular indicators, including the CVSS vector breakdown, asset metrics, and internal exposure logs.  
* **XGBoost Evaluation:** The hybrid feature matrix is evaluated by an in-house XGBoost Reciprocal Rank Fusion (RRF) ensemble model.  
* **Routing Decision:** The model calculates a localized exploitation probability. If the routing confidence score is not high, the case is escalated. If the confidence score is high, it is sorted according to the exploitation probability score.

## Phase 4: Tier 2 Semantic Analysis SLMs

### 1\. Data Entry and State

* **The Ingested Payload:** Data here transitions to a Small Language Model (SLM) tier. The SLM has all upstream statistical probabilities, asset contexts, and raw unstructured source metrics.

### 2\. Processing and Transformations

* **Classification Text Parsing:** Unstructured CVE descriptions are handed to a task-sized 125M parameter encoder model (such as RoBERTa-base or ModernBERT) to map text parameters to severity categories and Common Weakness Enumeration (CWE) classes.  
* **Reasoning & Force-Reflection:** The mapped CWE identity is injected into a templated prompt and evaluated by a 7B–8B parameter reasoning decoder model. The model initiates an adversarial force-reflection loop:  
  * *Step A:* It formulates a primary exploitability assessment based on the description text.  
  * *Step B:* It generates a plausible counter-argument, noting that the text contains a negative constraint (e.g., *"only exploitable if a non-default XML parser is enabled"*).  
  * *Step C:* It crafts a final determination evaluating whether the internal asset meets that condition.  
* **Contextual RAG Enrichment:** The SLM triggers a Retrieval-Augmented Generation (RAG) query against internal documentation repositories (such as Confluence or SharePoint) to read application runbooks and confirm the configuration of that asset.  
* **Routing Decision:** Factors such as internal documentation being unclear result in a lower confidence score for the model. The confidence score, a JSON payload of its findings, the logs viewed in all steps, the scores and all other information is aggregated for an analyst to summarise. This will additionally give the specific model conflicts.

## Phase 5: Tier 3 Human Review

### 1\. Data Entry and State

* **The Ingested Payload:** The record drops into a highly restricted human review queue.  
* **Accompanying Data:** The data packet is completely transparent; the analyst sees the raw logs, predicted asset criticality, upstream ML scores, internal documentation citations, and the SLM's narrative summary.

### 2\. Processing and Transformations

* **Human Determination:** The human analyst reviews the compiled evidence trail without having to investigate the vulnerability from scratch, drastically mitigating context-switching overhead. The analyst makes the final severity score (low, medium, critical, very critical).  
* **Feedback Ingestion:** If the analyst explicitly modifies or overturns the automated severity score, this annotated record is cleanly captured and routed into an isolated dataset earmarked for future model retraining cycles, safely avoiding the trap of rubber-stamped data loops.

Background Process: Continuous Statistical Audit

* **The Decoupled Path:** Had this piece of data successfully achieved a high-confidence auto-approval at Tier 0 or Tier 1, it would exit the live linear cascade immediately.  
* **Asynchronous Sampling:** Upon auto-approval, it enters an asynchronous background pool where it stands a 5% to 10% chance of being randomly selected for a statistical audit.  
* **Audit Purpose:** If selected, it is reviewed independently against calibrated criteria to establish true error rates, safely catching model or concept drift without introducing any latency to the live production pipeline.

