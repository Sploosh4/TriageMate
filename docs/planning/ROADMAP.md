# TriageMate — Roadmap

> **Status: CURRENT** (9 July 2026)
> 
> Previous roadmap archived to `docs/archive/ROADMAP-2026-07-09.md` (Sprints 1–16b complete).

---

## Current State

| Metric | Value |
|---|---|
| Tests | 275 pass, 0 fail |
| Open bugs | 0 (AI_PROBLEMS.md is clean) |
| Sprints completed | 16 + 16b |
| Pipeline stages | Pre-Tier → Tier 0 → Tier 1 → Tier 2 → Tier 3 (Human Review) |
| Enrichment sources | 12 integrations (NVD, OSV, OTX, ExploitDB, Metasploit, Tenable, GreyNoise [deprecated], CMDB [stub], Advisories [stub], MITRE, CWE classifier, Demo generator) |
| Demo rows | 7 CVEs, scores 94/87/71/63/55/41/22 (±3 tolerance) |
| Auth | JWT (disabled by default, env-var-gated) |
| Database | SQLite (default), PostgreSQL (available via DATABASE_URL) |
| CI/CD | `.github/workflows/ci.yml` — full pipeline (matrix test, coverage, lint, Docker) |

### ML Models

| Model | Type | Status | Monitoring |
|---|---|---|---|
| XGBoost (Tier 1) | 419-dim, ROC-AUC 0.9459 | ✅ Active | Tests ✅, Parity ✅, Registry ✅, Calibration ✅, Drift ✅ |
| Pre-Tier RF | 60-dim RandomForest, ~38% holdout acc | ✅ Active | Tests ✅, Parity ✅, Registry ✅, Calibration ❌, Drift ❌ |
| EPSS v4 | 37-dim XGBRegressor, R² 0.99 | ✅ Active (fallback #1) | Tests ✅, Parity ✅, Registry ✅, Calibration ❌, Drift ❌ |
| EPSS v1–v3 | XGBRegressor | Fallback #2–#4 | Tests ✅, Parity ✅, Registry ✅, Calibration ❌, Drift ❌ |

---

## Now — Sprint 17: Demo Integration

> **Priority:** Make the demo more compelling with security telemetry context.

| # | Item | Effort | Description |
|---|---|---|---|
| **1** | **Security Telemetry Module** | 2–3 hrs | Synthetic Sentinel-style incident correlation + EDR-style process/network alerts. Generates realistic demo telemetry based on KEV status, CVSS score, and vulnerability signatures. Plugs into enrichment pipeline. Displays as new accordion panel in case view. |
| **2** | **Network Context Panel** (optional) | 1–2 hrs | Display blast radius / lateral reachability context from existing synthetic_assets data. Shows reachable peers, zone classification, blast radius severity. |
| **3** | **Doc refresh** | 30 min | Update ROADMAP status after integration, correct CI/CD claim, run bookkeeper. |

---

## Soon — Sprint 18: Quick Wins + Monitoring

| # | Item | Effort | Description |
|---|---|---|---|
| **4** | **NVD Reference Count ≥21 Tier 0 rule** | 30 min | CVEs with 21+ NVD references have 9.5× baseline KEV rate. Add deterministic rule to Tier 0. Free signal, catches high-risk CVEs at day 0. |
| **5** | **CWE-stratified EPSS thresholds** | 30 min | Different CWE classes have very different optimal EPSS thresholds (Path Traversal: 0.085, OS Command Injection: 0.515). Stratified fallback outperforms monolithic threshold. |
| **6** | **Pre-Tier RF drift monitoring** | 2–4 hrs | PSI-based drift endpoint for Pre-Tier model. Feature distribution tracking against reference. |
| **7** | **EPSS drift monitoring** | 2–4 hrs | PSI-based drift endpoint for EPSS fallback models. |

---

## Later — Medium-Term Engineering

| # | Item | Effort | Description |
|---|---|---|---|
| **8** | **Scheduled retraining** | TBD | `scheduler.py` currently only does low-severity re-checks. Add model retraining triggers. |
| **9** | **Concept drift monitoring** | TBD | Beyond PSI — accuracy-over-time tracking, ground-truth feedback loop. |
| **10** | **Scoring weight documentation** | 1 hr | Document the 107-sum weight design, rationale for clamping, effect on score ceiling. |
| **11** | **Shared config module** | 3 hrs | Single source of truth for all pipeline constants across training and inference. |
| **12** | **EPSS v4 retrain on real data** | 1–2 days | Retrain EPSS v4 on real (non-synthetic) Tenable scan aggregation data. |
| **13** | **Multi-window labels** | 6 hrs | Replace single binary KEV label with 30/90/365d observation windows. |

---

## Post-MVP — Infrastructure & Platform

| # | Item | Description |
|---|---|---|
| **14** | Cloud deploy + HTTPS + CORS restriction | Docker, reverse proxy, DNS, TLS, restrict `allow_origins=["*"]` |
| **15** | Real Microsoft Sentinel integration | Replace synthetic with actual Azure Sentinel API |
| **16** | Real EDR/SIEM connectors | Defender, SentinelOne, CrowdStrike, Splunk |
| **17** | CMDB real integration | ServiceNow or iTop API replacement for stub |
| **18** | WASOC incident data | Replace 7-CVE advisories.py stub with live feed |
| **19** | RBAC / multi-user | Analyst vs. admin vs. viewer roles |
| **20** | MLflow experiment tracking | Model versioning, A/B testing, experiment registry |
| **21** | Email / Slack notifications | Webhook-driven alerting |
| **22** | PostgreSQL default deployment | Switch default from SQLite to PostgreSQL |
| **23** | `pytest-benchmark` + CI perf gates | Granular performance regression detection |
| **24** | DeepSeek V4 Flash Tier 2 provider | Additional LLM provider for fallback chain |

---

## Quick Start

```bash
cd backend && source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0
# Open http://localhost:8000
```

### Verification

```bash
just test   # 275 tests, 275 pass
just lint   # ruff check + format
just gate   # Full quality gate: lint → test → audit-all
```
