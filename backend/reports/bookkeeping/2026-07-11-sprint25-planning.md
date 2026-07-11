# Bookkeeping Report — Sprint 25 Planning

**Date:** 2026-07-11
**Trigger:** Pre-approval freshness pass for Sprint 25 plan

---

## P0 Cross-File Contradiction — Plan asserts non-existent `ARCHIVED/` directory

### Finding
The Sprint 25 plan (`.opencode/plans/2026-07-11-sprint-25.md`) asserts in **7 locations** that the actual archive directory is `ARCHIVED/` (uppercase) and that `.opencodeignore` needs its pattern fixed from `archive/` to `ARCHIVED/`:

| Location | Assertion |
|---|---|
| Line 29 | `archive/` pattern doesn't match `ARCHIVED/` |
| Line 111 | Item 22: `archive/` → `ARCHIVED/` |
| Lines 528–530 | "The current `.opencodeignore` has pattern `archive/` which does NOT match the actual directory `ARCHIVED/`" |
| Line 545 | `.opencodeignore` fixed: `ARCHIVED/` (not `archive/`) |
| Line 586 | Pattern fix: `archive/` → `ARCHIVED/` |
| Line 604 | `.opencodeignore` pattern (archive/ → ARCHIVED/) |
| Line 708 | `.opencodeignore` correctly protects `ARCHIVED/` from AI tooling |

### Reality
- **No `ARCHIVED/` directory exists** anywhere in the project
- The actual archive directory is **`archive/`** (lowercase) at project root
- The `.opencodeignore` **already correctly matches** with `archive/**`
- "Fixing" it per the plan would **break the exclusion** by pointing to a non-existent path

### Verdict
**P0 CONTRADICTION** — The plan is based on a false premise about the directory name. The `.opencodeignore` needs **no changes** regarding this pattern. All references to `ARCHIVED/` in the plan should be corrected to `archive/`.

---

## Auto-Fixed

None — all issues found require human review before changes.

---

## Items Flagged for Human Review

### 1. ROADMAP.md — Stale sprint name (line 16) ⚠️ Confirmed

**File:** `docs/planning/ROADMAP.md:16`
**Current:** `| Current sprint | Sprint 25 (TBD) — see GitHub Milestones |`
**Should be:** `Sprint 25 (GitHub-Native Workflow Operationalization)`
**Status:** The plan correctly identifies this needs updating in Phase 1.3 (line 180). No action needed now — it's in scope.

### 2. `.opencodeignore` — No fix needed ⚠️ Plan is wrong

**File:** `.opencodeignore`
**Current:** `archive/**` 
**Should be:** Keep as-is — correctly matches the `archive/` directory
**Status:** The plan's Phase 5.1 (Item 5.1, line 528–530) incorrectly says to change `archive/` to `ARCHIVED/`. This would break the exclusion. **Remove this item from the plan** or change it to verify the pattern is correct (which it already is).

### 3. INDEX.md — Missing `github-label-taxonomy.md` ⚠️

**File:** `docs/INDEX.md` — Planning section (lines 40–46)
**Issue:** `docs/planning/github-label-taxonomy.md` exists (created in Sprint 24, 43 lines, describes the 25-label taxonomy) but is **not listed** in INDEX.md.
**Recommendation:** Add an entry in the Planning table:
```
| `planning/github-label-taxonomy.md` | CURRENT | GitHub label taxonomy — 25 labels (9 defaults + 16 custom), created Sprint 24 |
```

### 4. `codebase-review` skill — Missing YAML frontmatter ⚠️ Noted

**File:** `.opencode/skills/codebase-review/SKILL.md`
**Issue:** Has **zero YAML frontmatter** (not just "an issue" with it — it starts directly with `# Codebase Review...`). All other skills have frontmatter.
**Status:** Correctly noted in the plan as out of scope for Sprint 25 (line 417). Flagging for future triage.

### 5. ROADMAP.md line 122 — Historical `master` reference ⚠️ Non-actionable

**File:** `docs/planning/ROADMAP.md:122`
**Content:** `Fixed CI benchmark branch bug (\`main\`→\`master\`).`
**Issue:** Documents a Sprint 23 bug fix that changed CI from `main` to `master`. This is a **historical record** of what was done, not a current instruction. The default branch is now `main`.
**Status:** Flag but **do not edit** — historical accuracy matters. The plan's Phase 5 check (line 535) should recognize this as a historical citation, not a stale reference.

---

## Cross-File Contradictions

| File A | File B | Contradiction | Severity |
|---|---|---|---|
| Sprint 25 plan (line 29, 111, 528–530, 545, 586, 604, 708) | Project filesystem | Plan says `ARCHIVED/` is the actual directory; no such directory exists — it's `archive/` (lowercase) | **P0** |
| `.opencodeignore` (`archive/**`) | Sprint 25 plan fix | `.opencodeignore` correctly matches `archive/`. Plan wants to change it to `ARCHIVED/` which would BREAK the exclusion | **P0** |
| ROADMAP.md line 16 (`Sprint 25 (TBD)`) | Sprint 25 plan naming | ROADMAP doesn't know Sprint 25's name yet | Minor — plan covers this in Phase 1.3 |

---

## File Existence Verification

All files listed in the Sprint 25 plan's Phase 0.3 file map (lines 98–114) exist at their specified paths:

| # | Path | Status |
|---|---|---|
| 1 | `AGENTS.md` | ✅ EXISTS |
| 2 | `.opencode/agents/commander.md` | ✅ EXISTS |
| 3 | `.opencode/agents/strike.md` | ✅ EXISTS |
| 4 | `.opencode/agents/bookkeeper.md` | ✅ EXISTS |
| 5 | `.opencode/agents/auditor.md` | ✅ EXISTS |
| 6 | `.opencode/agents/intel.md` | ✅ EXISTS |
| 7 | `~/.config/opencode/skills/decision-framework/SKILL.md` | ✅ EXISTS |
| 8 | `.opencode/skills/github-basics/SKILL.md` | ✅ EXISTS (8-line skeleton) |
| 9 | `.opencode/skills/backend-engineering/SKILL.md` | ✅ EXISTS |
| 10–20 | 11 remaining skill files | ✅ ALL EXIST |
| 21 | `~/.config/opencode/skills/cli-toolbox/SKILL.md` | ✅ EXISTS |
| 22 | `.opencodeignore` | ✅ EXISTS |
| 23 | `docs/planning/ROADMAP.md` | ✅ EXISTS |
| 24 | `opencode.jsonc` | ✅ EXISTS |

**Full skill inventory** (17 skills):

**Under `.opencode/skills/`:**
- `archived-files/SKILL.md` ✅ (skeleton, 8 lines)
- `audit-checklist/SKILL.md` ✅
- `backend-engineering/SKILL.md` ✅
- `cloud-llm-engineering/SKILL.md` ✅
- `codebase-review/SKILL.md` ✅ (no YAML frontmatter)
- `devops-engineering/SKILL.md` ✅
- `frontend-engineering/SKILL.md` ✅
- `github-basics/SKILL.md` ✅ (skeleton, 8 lines)
- `intel-toolbox/SKILL.md` ✅
- `ml-engineering/SKILL.md` ✅
- `ml-toolbox/SKILL.md` ✅
- `new-integration-pattern/SKILL.md` ✅
- `privacy-legal-advising/SKILL.md` ✅
- `triage-toolbox/SKILL.md` ✅
- `ux-designing/SKILL.md` ✅
- `wa-gov-consulting/SKILL.md` ✅

**Under `~/.config/opencode/skills/`:**
- `cli-toolbox/SKILL.md` ✅
- `decision-framework/SKILL.md` ✅

---

## Stale References Found

| File | Stale Reference | Detail |
|---|---|---|
| `docs/planning/ROADMAP.md:16` | `Sprint 25 (TBD)` | Should be `Sprint 25 (GitHub-Native Workflow Operationalization)` |
| `docs/INDEX.md` (Planning section) | Missing `github-label-taxonomy.md` | Sprint 24 artifact not indexed |
| Various archived sprint plans (`archive/`, `docs/archive/`) | `master` branch references | Historical documents — correct in their context, not actionable |

### `master` branch health check (CURRENT docs only)

**In CURRENT docs:**
- `ROADMAP.md:122` — Historical record of a bug fix; not a current `master` instruction
- `.opencode/plans/2026-07-11-sprint-25.md` — Uses `master` only in the context of "we need to fix this" (correct usage)
- All other CURRENT docs consistently use `main`

**In ARCHIVED/ARCHIVE docs:**
- Multiple files reference `master` — this is expected and acceptable for historical records

**No actionable stale `master` references** in current documentation.

---

## INDEX.md Completeness Check

| Status | File | In INDEX.md? |
|---|---|---|
| ✅ | `docs/INDEX.md` | Self |
| ✅ | `docs/planning/ROADMAP.md` | Yes (lines 25, 42) |
| ✅ | `docs/planning/HANDOFF-2026-07-08.md` | Yes (line 43) |
| ✅ | `docs/planning/ai-doc-strategy-2026-07-07.md` | Yes (line 44) |
| ❌ | **`docs/planning/github-label-taxonomy.md`** | **Missing** — not listed anywhere |
| ✅ | `docs/architecture/MVP_SCOPE.md` | Yes |
| ✅ | `docs/architecture/scoring-weights.md` | Yes |
| ✅ | `docs/architecture/comparison-vs-described-system.md` | Yes |
| ✅ | `docs/reference/AI_PROBLEMS.md` | Yes |
| ✅ | `docs/reference/hostname-standards.md` | Yes |
| ✅ | `docs/reference/xgboost-investigation-report.md` | Yes |
| ✅ | `docs/research/RESEARCH_FINDINGS.md` | Yes |
| ✅ | `docs/guides/WINDOWS_SETUP.md` | Yes |
| ⚠️ | `docs/archive/*` | Some listed, most excluded by note (line 247) |

**Result:** 1 document missing from INDEX.md (`github-label-taxonomy.md`).

---

## Consistency Checks

### Test count consistency: ✅
| Source | Value |
|---|---|
| ROADMAP.md line 13 | 449 pass, 0 fail |
| INDEX.md line 140 | 449+ tests |
| Sprint plan line 7 | 449 pass, 0 fail (Sprint 23) |
| **Consistent** | ✅ |

### Sprint 24 completeness: ✅
- ROADMAP.md marks Sprint 24 as ✅ Complete (line 130) ✅
- INDEX.md lists Sprints 17-24 as done (line 25, 42) ✅
- Sprint plan says "Sprint 24 — ✅ Complete" (line 6) ✅

### Default branch consistency: ✅
- `git branch` shows `main` as default
- `opencode.jsonc` has no branch references
- All CURRENT docs use `main` for the default branch
- ROADMAP.md:122 historical mention is a bug-fix record, not a current reference

### Skill reference consistency: ✅
- All agent files have `Loadable Skills` tables that reference existing skill files
- All `Related Skills` (where applicable) reference existing skills
- No dead links found in agent-to-skill cross-references

### `.opencodeignore` pattern: ⚠️ (see P0 above)
- Current: `archive/**` — **correctly** matches the `archive/` directory
- Plan says to change to `ARCHIVED/` — this is **wrong**

---

## Verdict

**NEEDS ATTENTION** — 1 P0 contradiction found

### Why
The Sprint 25 plan contains a **P0 cross-file contradiction** that would cause a broken `.opencodeignore` if executed as written. The plan asserts the existence of a directory named `ARCHIVED/` (uppercase), which does not exist. The actual directory is `archive/` (lowercase), and the `.opencodeignore` is already correct.

### Required actions before approval
1. **Fix the Sprint 25 plan** — Remove or correct all references to `ARCHIVED/`:
   - Lines 29, 111, 528–530, 545, 586, 604, 708
   - The `.opencodeignore` `archive/` → `ARCHIVED/` fix should be changed to **"Verify `.opencodeignore` pattern `archive/**` correctly matches the `archive/` directory"** (it already does)
2. **Add `github-label-taxonomy.md` to INDEX.md** (minor, pre-existing gap from Sprint 24)

### What's already good
- All 24 files in the plan's file map exist at the specified paths
- Test counts are consistent across all docs
- Sprint 24 is consistently marked as complete
- Default branch is consistently `main` everywhere
- The plan correctly identifies ROADMAP.md line 16 as needing a Sprint 25 name update
- No dead skill references or broken cross-links
- No actionable stale `master` references in CURRENT docs
