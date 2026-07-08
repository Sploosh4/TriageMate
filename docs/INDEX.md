# TriageMate — Documentation Index

> **For AI agents:** Start here. This file tells you what every document contains and whether it's trustworthy.

## Status Key
| Badge | Meaning |
|---|---|
| `CURRENT` | Up-to-date and authoritative — trust this |
| `OUTDATED` | Historical context, may contradict current state — read with caution |
| `ARCHIVED` | Preserved for reference, do not modify |

---

## Core Documents (read order for new AI agents)

| # | File | Status | Description |
|---|---|---|---|
| 1 | `planning/ROADMAP.md` | CURRENT | **Master status.** What exists, what's broken, what's next. Start here. |
| 2 | `architecture/MVP_SCOPE.md` | OUTDATED | Sprint 1 scope boundaries. Many deferred items are now done. See caution banner. |
| 3 | `reference/AI_PROBLEMS.md` | CURRENT | Bug tracker. 2 open items (pipeline drifts). |
| 4 | `archive/ml-implementation-plan.md` | ARCHIVED | → Replaced by `graphify_output/ml_inventory.md` (auto-generated, run `just graphify`) |

## Architecture

| File | Status | Description |
|---|---|---|
| `architecture/MVP_SCOPE.md` | OUTDATED | Scope authority from Sprint 1. Many deferred items now implemented. ROC-AUC figure updated to 0.9459. |

## Planning

| File | Status | Description |
|---|---|---|
| `planning/ROADMAP.md` | CURRENT | Master roadmap + sprint history + next actions. All sprints tracked (15 completed: Sprints 1–15.5). §Sprint 14 covers synthetic data infrastructure: `synthetic_assets` (1,827 rows), `synthetic_findings` (777 rows), `research_references` (97 refs), Pre-Tier model retrain, EPSS v4 sector-aware model, system name embedding, and `just retrain-all` automation. |
| `planning/HANDOFF-2026-07-08.md` | CURRENT | Handoff document covering ML drift monitoring, Tier 2 LLM query coverage, network topology/Sentinel status, and stress testing status. Answers what was deferred post-MVP. |
| `planning/ai-doc-strategy-2026-07-07.md` | CURRENT | This consolidation plan — how and why docs were restructured. |
| `archive/file-consolidation-plan-2026-07-07.md` | ARCHIVED | Bookkeeper's consolidation proposals — superseded by current doc structure. See `docs/INDEX.md`. |

## Reference

| File | Status | Description |
|---|---|---|
| `reference/AI_PROBLEMS.md` | CURRENT | Bug tracker — 2 open items (pipeline drifts). |
| `reference/xgboost-investigation-report.md` | CURRENT | Root cause analysis of XGBoost false-negative rate. ✅ All 8 fixes applied, model retrained 2026-07-08. |
| `archive/ml-implementation-plan.md` | ARCHIVED | → Replaced by `graphify_output/ml_inventory.md` (auto-generated, run `just graphify`) |
| `reference/hostname-standards.md` | CURRENT | WA government hostname conventions, data classification, department naming. |
| `backend/ml/README.md` | CURRENT | ML artifact index — lists active and pending ML components, lives with code. |

## Research

| File | Status | Description |
|---|---|---|
| `research/RESEARCH_FINDINGS.md` | OUTDATED | Strategic gap analysis from July 3. Some findings superseded by Sprint NEXT. See ROADMAP.md for current status. |
| `../backend/reports/intel/wa-gov-infrastructure-research.md` | CURRENT | WA Government ICT infrastructure research — 23 agencies, hostname synthesis rules, findings methodology (913 lines, 54 KB). Generated Sprint 14. |

## Guides

| File | Status | Description |
|---|---|---|
| `guides/WINDOWS_SETUP.md` | CURRENT | Windows 10/11 setup guide with troubleshooting. |

## Archive

| File | Status | Description |
|---|---|---|
| `archive/SPRINT_NEXT_PLAN.md` | ARCHIVED | Sprint NEXT detailed plan (merged into ROADMAP.md) |
| `archive/handoffs/SPRINT_9_HANDOFF.md` | ARCHIVED | Sprint 9 handoff — data supremacy. |
| `archive/sprints-1-6/*.md` | ARCHIVED | Sprint 1-6 handoffs, plans, team briefings. |

---

## Quick Reference: Which File for Which Question?

| Question | Read |
|---|---|---|
| What's the current state of the project? | `planning/ROADMAP.md` |
| What's broken? | `reference/AI_PROBLEMS.md` (2 open pipeline drifts) |
| What ML models exist and how do they work? | `graphify_output/ml_inventory.md` (auto-generated) |
| How do I train the model? | `planning/ROADMAP.md` §Sprint NEXT |
| How do I retrain all ML models from scratch? | Use `just retrain-all` — see ROADMAP.md §Sprint 14 |
| How do I set up on Windows? | `guides/WINDOWS_SETUP.md` |
| What WA gov conventions apply? | `reference/hostname-standards.md` |
| What data does the corpus contain? | `planning/ROADMAP.md` §Data Corpus |
| What's the scoring engine logic? | `architecture/MVP_SCOPE.md` §2.5 (then verify against current code) |
| What pipeline stages exist? | `planning/ROADMAP.md` §Pipeline Stages |
| Full file tree | `graphify_output/file_tree.md` (auto-generated) |
| ML models + training | `graphify_output/ml_inventory.md` (auto-generated) |
| Do inference and training feature columns match? | `graphify_output/feature_parity.md` (auto-generated) |
| How to generate synthetic data? | `backend/ml/generate_synthetic_data_v2.py` — `python -m ml.generate_synthetic_data_v2` |
| How to load research references? | `backend/scripts/load_research_refs.py` — `python -m scripts.load_research_refs` |
| What's in the WA gov infrastructure research? | `backend/reports/intel/wa-gov-infrastructure-research.md` |
| What are the 3 new Sprint 14 DB tables? | `docs/planning/ROADMAP.md` §Sprint 14 or `docs/INDEX.md` §New Database Tables |
| What is EPSS v4 and where does it fit? | Fallback model in Tier 1: v4 → v3 → v2 → v1 → heuristic rule engine. See ROADMAP.md §Sprint 14. |
| What is system name embedding? | Feature index 59: `system_category` (ordinal 0-8) replaces binary `has_known_system` in Pre-Tier. See ROADMAP.md §Pre-Tier Model Retrain. |

## New Database Tables (Sprint 14)

| Table | Rows | Purpose |
|---|---|---|
| `synthetic_assets` | 1,827 | Synthetic WA gov hostnames across 23 agencies — hostname, agency, environment, network zone, mission/wellbeing labels, blind holdout flag, research source refs |
| `synthetic_findings` | 777 | Host-to-vulnerability mappings with realistic exploitation likelihoods; used for EPSS v4 sector-aware training |
| `research_references` | 97 | WA government ICT research references — agency inventories, software profiles, hostname conventions, methodology citations |

## New Scripts (Sprint 14)

| Script | Command | Purpose |
|---|---|---|
| `backend/ml/generate_synthetic_data_v2.py` | `python -m ml.generate_synthetic_data_v2` | Generates 1,500–2,000 synthetic WA gov hostnames with probabilistic labels, blind holdout, and confidence scores; inserts into `synthetic_assets` |
| `backend/ml/generate_synthetic_findings.py` | `python -m ml.generate_synthetic_findings` | Generates host-to-vulnerability mappings with exploitation likelihoods for EPSS v4 training; inserts into `synthetic_findings` |
| `backend/ml/train_epss_v4.py` | `python -m ml.train_epss_v4` | Trains the EPSS v4 sector-aware substitution model from `synthetic_findings` data |
| `backend/scripts/load_research_refs.py` | `python -m scripts.load_research_refs` | Seeds or refreshes `research_references` table from embedded WA gov ICT research corpus |

## New Automation (Sprint 14)

| Command | Purpose |
|---|---|
| `just retrain-all` | Retrains all ML models from scratch: synthetic data → pre-tier → EPSS v4 |

## Graphify — Auto-Generated Knowledge Artifacts

These files are regenerated on demand with `just graphify`. They are always current with the codebase.

| File | Description |
|---|---|
| `graphify_output/file_tree.md` | Complete annotated directory tree (299 entries, auto-generated) |
| `graphify_output/api_deps.md` | Python import dependency map (421 dependencies, auto-generated) |
| `graphify_output/ml_inventory.md` | Canonical ML model and script inventory |
| `graphify_output/knowledge_graph.json` | Structured CVE↔hostname↔CWE knowledge graph |
| `graphify_output/feature_parity.md` | Tabular feature parity check (inference vs training vs inventory) |

---

## Notes

**Archive files:** Files under `docs/archive/` (sprint handoffs S1–S6, superseded plans) are preserved for historical context but are not listed in this index. They are **ARCHIVED** — do not use as reference for current state.

**Root-level `.md` symlinks:** Files like `ROADMAP.md`, `AI_PROBLEMS.md`, etc. at the project root are symlinks into `docs/`. Always read the canonical copy under `docs/`.

**Auto-generated files:** Files under `graphify_output/` are regenerated with `just graphify`. Their freshness depends on the last run. If they look stale, run `just graphify` to regenerate.
