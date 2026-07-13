# TriageMate Project Rules

## Documentation Freshness
After completing every task, the commander MUST delegate to bookkeeper for a freshness pass. This is not optional — bookkeeper is the mechanical guarantee against .md drift.

## GitHub Workflow Overview

TriageMate uses a **conditional-access GitHub model**:

- **Test first, use when verified:** Subagents with verified Level 4+ `gh` CLI access may handle GitHub operations (branches, commits, PRs, issues) directly. Access is tested via `gh auth status` at the start of a session.
- **Fallback to commander:** If subagent `gh` access is not verified, remote GitHub mutations are routed through the commander's `github_*` MCP tools.
- **Hybrid git model:** Small, low-risk changes commit directly to `main`. Substantial changes (feature work, refactors, structural modifications) use a branch-and-PR workflow: create a branch → push → open PR → merge after review.
- **Canonical tracking:** GitHub Issues and Milestones serve as the canonical source of truth for task tracking and release planning.
- **Execution reference:** Detailed sprint execution plans live in `.opencode/plans/` and reference their corresponding GitHub Issues and Milestones.

## Decision Framework
All subagents load the `decision-framework` skill at the start of every task. It teaches when to flag assumptions vs. proceed, and how to report to the commander.

## Sprint Workflow
The commander plans sprints, executes them via subagent delegation, and triggers bookkeeper at sprint end. Sprint plans live in `.opencode/plans/`.

## Documentation Structure

All project documentation lives under `docs/` in subdirectories by category.

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
