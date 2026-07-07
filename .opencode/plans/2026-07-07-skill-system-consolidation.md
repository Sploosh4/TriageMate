# Plan: Skill System Consolidation

**Date:** 2026-07-07
**Status:** Implemented
**Trigger:** Review of agent/skill architecture

---

## What Changed

### Merged Skills (2 → 0 standalone directories)

| Old | New Home | Reason |
|---|---|---|
| `dual-database-ddl` | Section in `backend-engineering` | 6-step checklist + type map — not a standalone domain |
| `feature-vector-spec` | Section in `ml-engineering` | Contract for one function — belongs in ML skill |
| `new-integration-pattern` | Kept standalone | Procedural template, different purpose from `intel-toolbox` catalog |

Both old directories moved to `.opencode/ARCHIVED/skills/`. Total project skills: 15 → 13.

### Created: `decision-framework` (global skill)

`~/.config/opencode/skills/decision-framework/SKILL.md`

Teaches all subagents:
- Do everything possible before asking
- Report results first, assumptions second
- Flag assumptions with `**Assumption:**` prefix
- Never ask open-ended questions
- Present two options with a recommendation

### Created: `bookkeeper` agent

`.opencode/agents/bookkeeper.md` — documentation hygiene subagent.

- Freshness check — verifies .md files match reality
- Orphan detection — finds stale cross-references
- Coverage check — new features reflected in skills?
- Auto-fixes simple drift (stale paths, renamed refs)
- Reports to `backend/reports/bookkeeping/`

### Updated: `commander` agent

`.opencode/agents/commander.md`

- Sprint lifecycle: plan → execute → review → bookkeep
- Per-task workflow now includes bookkeeper step
- Handles subagent `**Assumption:**` flags: relay → user silence = tacit approval
- Loads `decision-framework` before every delegation

### Updated: `strike` agent

`.opencode/agents/strike.md`

- Added `decision-framework` as first loadable skill
- Two new guidelines: load decision-framework, report assumptions
- Removed references to archived skills

### Updated: `auditor` agent

`.opencode/agents/auditor.md`

- Added `decision-framework` to loadable skills
- Removed references to archived skills

### Updated: `AGENTS.md`

Project root. Now three rules instead of one:
- Bookkeeper mandatory after every task
- Decision framework for all subagents
- Sprint workflow with plans directory

---

## What Requires Restart

All changes are file-based. Requires opencode restart to take effect.

---

## Future Items (Not Done)

1. **Graphify evaluation** — if you want to try it, install and run once in a sprint, let the bookkeeper report on whether the agent actually uses it
2. **Further consolidation** — `privacy-legal-advising` and `wa-gov-consulting` could merge (both are "ONLY when" assessment skills for WA data), but they serve different triggers
3. **Automated validation** — a script that verifies agent permissions match descriptions and skill descriptions don't have keyword collisions. The bookkeeper could eventually run this.
