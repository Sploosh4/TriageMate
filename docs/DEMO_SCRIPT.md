# TriageMate — Demo Walkthrough Script

> **Duration:** ~5 minutes
> **Prerequisites:** Docker (recommended) or Python 3.10+ setup complete
> **Target audience:** WA government stakeholder (non-technical)

---

## Step 1: Launch (one command)

**Docker:**
```bash
docker-compose up --build
```
Wait for `Application startup complete` in the logs (~60s first time).

**Without Docker:**
```bash
cd backend
python seed_data.py
uvicorn main:app --host 0.0.0.0 --port 8000
```

**🎯 Say:** *"TriageMate starts with one command. Everything — the ML models, the NVD enrichment pipeline, the vector store — initialises automatically. There's no complex configuration."*

---

## Step 2: Queue View — Show the 7 seed rows

Open **http://localhost:8000** in a browser.

**🎯 Say:** *"This is the analyst Queue. Seven vulnerabilities have been pre-loaded from real-world scenarios relevant to WA government agencies. Notice the columns:"

- **Vulnerability ID** — standard CVE identifier
- **Hostname** — the affected WA government asset (health, transport, education, finance)
- **Priority Score** — 0-100, scored by the ML pipeline
- **Risk Band** — Low / Medium / Critical / Very Critical
- **Detection Tier** — how the pipeline reached the score (Deterministic / ML / SLM)
- **Compliance** — PRIS Act data classification (Category 1-4)
- **Time** — when it was ingested

**Highlight:** The MOVEit Transfer row (score 94, Very Critical) — *"This CVE has active exploitation confirmed by WASOC threat intel. TriageMate auto-escalated it to the top without human review."*

---

## Step 3: Case View — MOVEit Row (Panel 1-4)

Click the MOVEit row (or any row) to open the Case View.

### Panel 1 — Narrative + MITRE
**🎯 Say:** *"Each case opens with an auto-generated narrative summary — it explains what the vulnerability is, what asset it affects, and how the pipeline routed it. Below are the MITRE ATT&CK techniques mapped automatically from the CWE classification."*

### Panel 2 — Accordions
Click the **WASOC Advisory Reference** accordion to expand it.

**🎯 Say:** *"The advisory pane shows a WASOC-formatted security advisory — this is the format WA SOC analysts already use. No new UI to learn."*

Also expand **Scanner Output** and **Weakness Logic Template**.

**🎯 Say:** *"Raw scanner output from the vulnerability scan is preserved, and the detection logic that triggered the alert is shown transparently."*

### Panel 3 — Notes + Score Gauge
**🎯 Say:** *"The investigation notes are auto-populated with a full pipeline trace — which tiers fired, what scores were calculated, any EPSS substitution that occurred. The score gauge gives a quick visual of severity."*

### Panel 4 — Scoring Breakdown + Asset Registry
**🎯 Say:** *"The scoring weights break down how the 0-100 score was calculated: CVSS contribution, EPSS probability, asset criticality (based on PRIS Act classification), exposure, and patch availability."*

**Highlight the Enrichment Stale badge** (only if NVD data is stale — skip this step if badge is not visible).

---

## Step 4: Live Ingest via Tenable Webhook

Open a **second terminal** and run:

```bash
curl -s -X POST http://localhost:8000/api/ingest/tenable \
  -H "Content-Type: application/json" \
  -d '{
    "type": "vuln_found",
    "finding": {
      "asset": {"fqdn": "web-gateway.health.wa.gov.au", "ipv4": ["10.47.22.100"]},
      "plugin": {
        "id": 19506,
        "cve": ["CVE-2024-6387"],
        "cvss3_base_score": 8.1,
        "cvss3_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "A remote attacker may exploit a signal handler race condition in OpenSSH server (regreSSHion) to achieve remote code execution as root on affected hosts.",
        "synopsis": "OpenSSH regreSSHion RCE",
        "exploit_available": true
      },
      "output": "Nessus detected OpenSSH version 9.2 on port 22/tcp — confirmed vulnerable to CVE-2024-6387 (regreSSHion)."
    }
  }'
```

**🎯 Say:** *"This simulates Tenable.io pushing a finding to TriageMate via the webhook. The endpoint accepts the raw Tenable JSON format — no transformation required on the WASOC side."*

---

## Step 5: Show the New Row — Compare Richness

Refresh the Queue page at **http://localhost:8000**.

**🎯 Say:** *"The new CVE-2024-6387 row has appeared. Notice that all columns are populated — including the priority score, risk band, and compliance classification — even though we only sent the raw Tenable export."*

Click the new row and point out:

- **Panel 1** — narrative mentions the hostname `web-gateway.health.wa.gov.au`
- **Panel 4** — asset registry shows the IP, data classification (Category 1 because hostname was unknown to CMDB — explain this honestly)
- **Scoring weights** — show how CVSS 8.1 maps through the pipeline

**🎯 Say:** *"Compare this to the seed rows — the same pipeline ran for both. The Tenable webhook produces the same quality of case enrichment as a hand-crafted ingest."*

---

## Step 6: Filters + Metrics

Back on the Queue page, click the **Filter** button/dropdown.

**🎯 Say:** *"You can filter by risk band, detection tier, compliance category — whatever the analyst needs to triage by."*

Point to the **Metrics boxes** above the queue:

**🎯 Say:** *"The metrics panel shows live counts: critical actions needed, low-confidence cases that need human validation, exposed assets, and cases requiring human review. These update in real-time as new findings come in."*

---

## Step 7: Close — Docker Deploy Pitch

**🎯 Say:** *"TriageMate runs entirely in Docker. The ML model is pre-cached in the image — no internet calls on startup. You can deploy it on your own infrastructure with one command:*

```bash
docker-compose up
```

*"All data persists in a volume-mounted database. The NVD enrichment, MITRE mapping, EPSS substitution, and RAG vector store all run locally. With the optional LLM API key for Tier 2 SLM analysis, CVE descriptions and RAG context are sent to the configured provider (OpenAI/Anthropic/Together AI). The built-in KNOWN_CONFLICTS fallback resolver avoids any external calls for the demo CVEs.*

*"We're ready to deploy a pilot instance for WASOC evaluation."*

---

## Appendix: Key Talking Points

| Feature | What to emphasise |
|---|---|
| One-command deploy | `docker-compose up` — no dependencies beyond Docker |
| Tenable webhook | Accepts raw Tenable.io JSON — no transformation needed |
| PRIS Act compliance | Data classification, Category 1-4, mission tags |
| Offline-capable | SBERT model pre-cached, NVD has 24h TTL cache |
| Scoring transparency | Every score has a weight breakdown with justification |
| ML pipeline | XGBoost exploitation probability + ensemble variance routing |
| Audit trail | Full pipeline trace stored in investigation notes |

## Appendix: If Things Go Wrong

| Failure mode | Recovery |
|---|---|
| Server won't start | Check `triagemate.db` permissions, delete and re-run `seed_data.py` |
| SBERT model loading fails | Check internet connectivity (first run only); after that it's cached |
| NVD enrichment empty | NVD API may be rate-limited without `NVD_API_KEY` — enrichment still works, just returns defaults |
| Tenable webhook returns 400 | Check payload format matches the expected Tenable export structure |
| RAG store empty | LanceDB initialises with demo documents on first startup; wait for `Vector store initialized and seeded` |
