# TriageMate Project Rules

## Documentation Freshness
After completing every task, the commander MUST delegate to bookkeeper for a freshness pass. This is not optional — bookkeeper is the mechanical guarantee against .md drift.

## Decision Framework
All subagents load the `decision-framework` skill at the start of every task. It teaches when to flag assumptions vs. proceed, and how to report to the commander.

## Sprint Workflow
The commander plans sprints, executes them via subagent delegation, and triggers bookkeeper at sprint end. Sprint plans live in `.opencode/plans/`.

## Documentation Structure

All project documentation lives under `docs/` in subdirectories by category. Root-level `.md` files (except `AGENTS.md`) are symlinks into `docs/` for backward compatibility.

| Category | Directory | Contents |
|---|---|---|
| Architecture | `docs/architecture/` | `MVP_SCOPE.md` — scope authority |
| Guides | `docs/guides/` | `DEMO_SCRIPT.md`, `TRIAGEMATE_BOOK_PROMPT.md`, `WINDOWS_SETUP.md` |
| Planning | `docs/planning/` | `ROADMAP.md`, `SPRINT_NEXT_PLAN.md` |
| Reference | `docs/reference/` | `AI_PROBLEMS.md`, `XGBOOST_INVESTIGATION_REPORT.md`, hostname standards, ML implementation plan |
| Research | `docs/research/` | `RESEARCH_FINDINGS.md` |
| Archive | `docs/archive/` | Superseded plans, handoffs, sprint archives |

> **Note:** `AGENTS.md` is the only real `.md` file at the project root. All other root `.md` files are symlinks into `docs/`. Opening `ROADMAP.md` at root opens `docs/planning/ROADMAP.md` transparently.
