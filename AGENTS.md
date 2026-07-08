# TriageMate Project Rules

## Documentation Freshness
After completing every task, the commander MUST delegate to bookkeeper for a freshness pass. This is not optional — bookkeeper is the mechanical guarantee against .md drift.

## Decision Framework
All subagents load the `decision-framework` skill at the start of every task. It teaches when to flag assumptions vs. proceed, and how to report to the commander.

## Sprint Workflow
The commander plans sprints, executes them via subagent delegation, and triggers bookkeeper at sprint end. Sprint plans live in `.opencode/plans/`.

## Quality Gate Loop (Commander)
After every batch of changes, verify. If issues are found, fix them and re-verify. Repeat until clean. This applies regardless of what changed — run whatever checks are appropriate (tests, audits, bookkeeping), fix whatever they find, stop only when two consecutive passes return nothing.

## Documentation Structure

All project documentation lives under `docs/` in subdirectories by category. Root-level `.md` files (except `AGENTS.md`) are symlinks into `docs/` for backward compatibility.

> **For AI agents:** Start at `docs/INDEX.md` — it lists every document with its status (CURRENT/OUTDATED/ARCHIVED) and tells you which file to read for common questions.

### Quick Reference
| Need | Read |
|---|---|
| Current project status | `docs/planning/ROADMAP.md` |
| Full doc index | `docs/INDEX.md` |
| Known bugs | `docs/reference/AI_PROBLEMS.md` |
| ML models + training | `graphify_output/ml_inventory.md` (auto-generated) |
| WA gov conventions | `docs/reference/hostname-standards.md` |
| Windows setup | `docs/guides/WINDOWS_SETUP.md` |
| Full file tree | `graphify_output/file_tree.md` (auto-generated) |
| Feature parity (training vs inference) | `graphify_output/feature_parity.md` (auto-generated) |
| Knowledge graph (JSON) | `graphify_output/knowledge_graph.json` (auto-generated) |
| Import/dependency map | `graphify_output/api_deps.md` (auto-generated) |

### Directory Map
| Category | Directory | Contents |
|---|---|---|
| Architecture | `docs/architecture/` | Scope boundaries, design decisions |
| Guides | `docs/guides/` | Setup, configuration, walkthroughs |
| Planning | `docs/planning/` | Roadmap, sprint plans, strategy docs |
| Reference | `docs/reference/` | Standards, bug tracker, investigation reports |
| Research | `docs/research/` | Gap analysis, data findings |
| Archive | `docs/archive/` | Historical handoffs, superseded plans |
