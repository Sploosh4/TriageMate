# TriageMate Project Rules

## Documentation Freshness
After completing every task, the commander MUST delegate to bookkeeper for a freshness pass. This is not optional — bookkeeper is the mechanical guarantee against .md drift.

## Decision Framework
All subagents load the `decision-framework` skill at the start of every task. It teaches when to flag assumptions vs. proceed, and how to report to the commander.

## Sprint Workflow
The commander plans sprints, executes them via subagent delegation, and triggers bookkeeper at sprint end. Sprint plans live in `.opencode/plans/`.

## Documentation Structure
All project documentation lives under `docs/` in subdirectories by category. Root-level `.md` files (except `AGENTS.md`) are symlinks into `docs/` for backward compatibility. See `docs/` for the full index.

| Category | Directory |
|---|---|
| Architecture | `docs/architecture/` |
| Guides | `docs/guides/` |
| Planning | `docs/planning/` |
| Reference | `docs/reference/` |
| Research | `docs/research/` |
| Archive | `docs/archive/` |
