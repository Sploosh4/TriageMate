# Sprint Plan: Research & Synthetic Data Infrastructure

**Date:** 2026-07-08
**Goal:** Build a research-backed synthetic data pipeline that produces 1,500–2,000 WA government hostnames + findings, stored in SQLite, validated, and queryable by AI.

---

## Phase Order

```
Item 1 (Research) ──┬──→ Item 2 (Schema + Storage) ──→ Item 4 (Generator v2)
                    │
                    ├──→ Item 3 (Validation Toolkit) ──↗
                    │
                    └──→ Item 4 (Generator v2) depends on items 2 & 3 being ready
```

Items 2 and 3 can run in parallel once research is complete.

---

## Item 1: WA Government Infrastructure Research

**Agent:** intel
**Expected output:** `backend/reports/intel/wa-gov-infrastructure-research.md`

Research and document with sources:

| Category | What to research |
|---|---|
| **Agencies** | WA government departments, their abbreviations, official domains. At least 10. Include health, justice, transport, education, police, finance, DPIRD, parliament, elections, country health, and any others found. |
| **Enterprise systems** | Software actually run by Australian/WA government: SAP, Oracle, MOVEit, Citrix, SharePoint, WebPAS, iPHIS, eCourts, CIMS, LEO, SCADA/ICS platforms, etc. What does each system do? Which agencies use which? |
| **Hostname conventions** | Build on `docs/reference/hostname-standards.md`. Find real observed patterns — location prefixes, environment codes, role suffixes, OS indicators. Document what's actually seen vs what's theoretical. |
| **Network topology** | DMZ patterns, internal vs management zones, domain controller naming (PDC, BDC, ADC), cloud presence (Azure Australia regions, AWS Sydney/Canberra). What network zones exist in government? |
| **CVE patterns** | What CVEs have historically affected government infrastructure? KEV catalog items relevant to gov software. Common CWE classes in government breaches. EPSS score ranges for gov-relevant CVEs. |

**Quality gate:** Every finding must have a source (URL, official doc, or cited precedent). No unsourced claims. Mark confidence: `confirmed` (official source), `likely` (multiple indirect sources), `assumed` (industry standard, no direct confirmation).

---

## Item 2: SQLite Schema + Storage Pipeline

**Agent:** strike
**Expected output:** Alembic migration + ingestion script + verify queryable

### Schema Design

Three namespaced tables in the main app database:

**`synthetic_assets`** — generated hostnames with labels:
```sql
id, hostname (UNIQUE), ip, agency, agency_domain, system_name,
environment, os_platform, role, network_zone, is_internet_facing,
is_dc, mission_prevalence, public_wellbeing_impact,
confidence_mp, confidence_wi, source_research_ref,
generated_at, validation_status, validation_errors
```

**`synthetic_findings`** — generated CVE/hostname pairs for EPSS training:
```sql
id, cve_id, hostname, cvss_score, epss_score, cisa_kev,
cwe_class, sector, agency, exploit_maturity, has_public_poc,
vendor_patch_status, source_research_ref, generated_at
```

**`research_references`** — traceability from generated data back to research:
```sql
id, ref_id (UNIQUE), category, finding, source_url, confidence, notes
```

### Ingestion Pipeline

- `backend/scripts/ingest_synthetic_to_db.py` — reads generator JSON output, inserts into SQLite
- Deduplication on insert (hostname UNIQUE constraint)
- Updates `validation_status` column as Item 3 validates

### Verify

- Run a query via the db_sqlite MCP tools to confirm AI can read the data
- Example: `SELECT agency, COUNT(*) FROM synthetic_assets GROUP BY agency`

---

## Item 3: Data Validation Toolkit

**Agent:** strike
**Expected output:** `backend/scripts/validate_synthetic_data.py` + validation report

### Validation Checks

| # | Check | What it catches |
|---|---|---|
| 1 | **Duplicate hostnames** | Two rows with same hostname, different labels |
| 2 | **Required fields** | NULL in mission_prevalence, public_wellbeing_impact, hostname, agency |
| 3 | **Label validity** | Values outside allowed enums (Core/Support/Peripheral, Severe/Moderate/Minimal) |
| 4 | **Feature extraction** | Every hostname passes through `extract_features()` without error |
| 5 | **Feature vector diversity** | Not all hostnames produce identical feature vectors |
| 6 | **Hostname format** | Matches expected pattern (components separated by dots/hyphens, valid domain suffix) |
| 7 | **Label distribution** | No single class >80% of total (prevents trivial "always guess majority" models) |
| 8 | **Research traceability** | Every `source_research_ref` exists in `research_references` table |
| 9 | **Confidence bounds** | All confidence values in [0.0, 1.0] |
| 10 | **Blind holdout integrity** | Holdout patterns don't leak into training set |

### Output

- Updates `validation_status` column on each row: `passed` / `failed`
- Writes `validation_errors` column with specific failure reasons
- Produces `backend/reports/audits/synthetic-data-validation-{date}.md` summary
- Exit code: 0 if all pass, 1 if any failures (usable in CI/justfile)

---

## Item 4: Synthetic Data Generator v2

**Agent:** strike
**Expected output:** Rewritten `backend/ml/generate_supplemental_hostnames.py` + retrained model + metrics

### Design Rules

1. **Research-backed:** Every generated hostname must reference a `research_references.ref_id`. No fictional patterns.

2. **Probabilistic labels:** Labels come from weighted random distributions per (agency, system, environment) combination, NOT deterministic if/else chains. Example: a health agency production domain controller has 85% chance Core/Severe, 12% Core/Moderate, 3% Support/Moderate — not 100% Core/Severe. This forces the model to learn patterns, not memorize rules.

3. **Blind holdout (20%):** Reserve specific agencies, system names, or lifecycle variants from training entirely. The model must predict on these at eval time. This catches overfitting.

4. **Target: 1,500–2,000 rows** in `synthetic_assets`. Additional rows in `synthetic_findings` for EPSS training.

5. **Output format:** Writes directly to SQLite via Item 2's pipeline. Also produces JSON backup for reproducibility.

6. **Seeded RNG:** `random.seed(42)` for reproducibility. Different seeds produce different datasets for cross-validation.

### Post-Generation

- Run Item 3's validation. If any checks fail, fix generator and regenerate.
- Retrain `pre_tier_model.pkl` on the new data.
- Persist CV metrics to `backend/ml/pre_tier_metrics.json`.
- Run on blind holdout — report accuracy.
- Run the 7 demo rows through the retrained model — confirm no regression.

---

## Cross-Cutting

- Update `docs/planning/ROADMAP.md`: pre-tier and EPSS moved from "deferred" to "complete with synthetic data"
- Update `docs/reference/AI_PROBLEMS.md` if any new issues found
- Bookkeeper pass at sprint end

---

## Success Metrics

| Metric | Target |
|---|---|
| Rows in `synthetic_assets` | 1,500–2,000 |
| Research references with sources | All (0 unsourced) |
| Validation checks passing | 10/10 |
| Blind holdout accuracy | Above majority-class baseline |
| Demo row regression | All 7 within expected bands |
| MCP queryable | `SELECT COUNT(*) FROM synthetic_assets` works |

---

## Deferred to Victory Lap

- `just retrain-all` command (single CLI to regenerate + retrain everything)
- Pre-tier + EPSS substitution unit tests (directional correctness)
- KNOWN_TAGS migration to JSON config

---

## Assumptions Flagged

**Assumption 1 (SQL MCP):** The `db_sqlite_*` MCP tools connect to the main app database and can query new tables added to it. Verified: existing `vulnerabilities` table is queryable. New `synthetic_*` tables will be queryable the same way.

**Assumption 2 (Tenable data for EPSS v4):** The demo Tenable dataset is too small (7 findings) to train v4. The generator v2 will produce synthetic Tenable findings grounded in research. v4 trains on those. If real Tenable data becomes available later, the pipeline supports it — we just swap the input.

**Assumption 3 (intel research scope):** The intel agent can find sufficient public information about WA government IT infrastructure. If specific details are unavailable (many government IT details are not public), the research report will mark findings as `assumed` with industry-standard reasoning, and the generator will flag those rows accordingly.
