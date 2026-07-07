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
| 3 | `reference/AI_PROBLEMS.md` | CURRENT | Bug tracker. 1 unfixed issue (#14, won't-fix). |
| 4 | `reference/ml-implementation-plan.md` | OUTDATED | Original ML design. PCA removed, SecureBERT deprecated, 6 dims. See banner. |

## Architecture

| File | Status | Description |
|---|---|---|
| `architecture/MVP_SCOPE.md` | OUTDATED | Scope authority from Sprint 1. Many deferred items now implemented (Docker, JWT, Alembic, T3 queue, drift dashboard, Pre-Tier RF). |

## Planning

| File | Status | Description |
|---|---|---|
| `planning/ROADMAP.md` | CURRENT | Master roadmap + sprint history + next actions. All 9 sprints tracked. |
| `planning/ai-doc-strategy-2026-07-07.md` | CURRENT | This consolidation plan — how and why docs were restructured. |
| `planning/file-consolidation-plan-2026-07-07.md` | CURRENT | Bookkeeper's detailed consolidation analysis. |

## Reference

| File | Status | Description |
|---|---|---|
| `reference/AI_PROBLEMS.md` | CURRENT | Known bugs and discrepancies found during development. |
| `reference/xgboost-investigation-report.md` | CURRENT | Root cause analysis of XGBoost false-negative rate. 8 fixes identified, 5 require retrain (pending). |
| `reference/ml-implementation-plan.md` | OUTDATED | Original ML design from early sprints. Historical only. |
| `reference/hostname-standards.md` | CURRENT | WA government hostname conventions, data classification, department naming. |

## Research

| File | Status | Description |
|---|---|---|
| `research/RESEARCH_FINDINGS.md` | CURRENT | Strategic gap analysis — KEV coverage, EPSS baseline, pipeline drift. Sprint NEXT+2. |

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
|---|---|
| What's the current state of the project? | `planning/ROADMAP.md` |
| What's broken? | `reference/AI_PROBLEMS.md` |
| What ML models exist and how do they work? | `planning/ROADMAP.md` §ML Artifacts, then `reference/xgboost-investigation-report.md` |
| How do I train the model? | `planning/ROADMAP.md` §Quick Start |
| How do I set up on Windows? | `guides/WINDOWS_SETUP.md` |
| What WA gov conventions apply? | `reference/hostname-standards.md` |
| What data does the corpus contain? | `planning/ROADMAP.md` §Data Corpus |
| What's the scoring engine logic? | `architecture/MVP_SCOPE.md` §2.5 (then verify against current code) |
| What pipeline stages exist? | `planning/ROADMAP.md` §Pipeline Stages |
