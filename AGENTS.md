# TriageMate Project Rules

## Documentation Freshness
After completing every task, the commander MUST delegate to bookkeeper for a freshness pass. This is not optional — bookkeeper is the mechanical guarantee against .md drift.

## Decision Framework
All subagents load the `decision-framework` skill at the start of every task. It teaches when to flag assumptions vs. proceed, and how to report to the commander.

## Sprint Workflow
The commander plans sprints, executes them via subagent delegation, and triggers bookkeeper at sprint end. Sprint plans live in `.opencode/plans/`.

## Documentation Structure

All project documentation lives under `docs/` in subdirectories by category. Root-level `.md` files (except `AGENTS.md`) are symlinks into `docs/` for backward compatibility.

> **For AI agents:** Start at `docs/INDEX.md` — it lists every document with its status (CURRENT/OUTDATED/ARCHIVED) and tells you which file to read for common questions.

### Quick Reference
| Need | Read |
|---|---|
| Current project status | `docs/planning/ROADMAP.md` |
| Full doc index | `docs/INDEX.md` |
| Known bugs | `docs/reference/AI_PROBLEMS.md` |
| ML models + training | `docs/planning/ROADMAP.md` §ML Artifacts |
| WA gov conventions | `docs/reference/hostname-standards.md` |
| Windows setup | `docs/guides/WINDOWS_SETUP.md` |

### Directory Map
| Category | Directory | Contents |
|---|---|---|
| Architecture | `docs/architecture/` | Scope boundaries, design decisions |
| Guides | `docs/guides/` | Setup, configuration, walkthroughs |
| Planning | `docs/planning/` | Roadmap, sprint plans, strategy docs |
| Reference | `docs/reference/` | Standards, bug tracker, investigation reports |
| Research | `docs/research/` | Gap analysis, data findings |
| Archive | `docs/archive/` | Historical handoffs, superseded plans |
