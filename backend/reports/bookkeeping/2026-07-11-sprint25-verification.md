# Bookkeeping Report — Sprint 25 Verification

**Date:** 2026-07-11
**Trigger:** Sprint 25 mid-sprint verification

---

## Auto-Fixed

None — all issues found require human review before changes.

---

## Items Flagged

### P1 — Score contract stale in 4 active agent/skill files

The canonical demo scores were established as `[99, 97, 74, 91, 82, 97, 80]` in Sprint 23 (Score Reconciliation), verified against `routers/models.py:97`. However, 4 active files still reference OLD score values from Sprint 2–17 era:

| File | Line | Current Value | Should Be |
|---|---|---|---|
| `.opencode/agents/strike.md` | 51 | `(94, 87, 71, 55, 63, 41, 22)` | `99, 97, 74, 91, 82, 97, 80` |
| `.opencode/skills/backend-engineering/SKILL.md` | 95 | `98, 91, 73, 66, 58, 44, 26` | `99, 97, 74, 91, 82, 97, 80` |
| `.opencode/skills/ml-engineering/SKILL.md` | 64 | `94, 87, 71, 63, 55, 41, 22` | `99, 97, 74, 91, 82, 97, 80` |
| `.opencode/skills/audit-checklist/SKILL.md` | 63 | `94, 87, 71, 63, 55, 41, 22` | `99, 97, 74, 91, 82, 97, 80` |

**Impact:** The strike agent (primary code writer) still follows its own guidelines which reference wrong expected values (`94, 87, 71, 55, 63, 41, 22`). The actual test suite expects `[99, 97, 97, 91, 82, 80, 74]` (sorted). If strike relies on its own guideline to verify scores, it will flag false positives.

**Note:** These stale references pre-date Sprint 25 and were NOT in scope for the current sprint's Phase 2/3 updates (which focused on GitHub workflow additions). They should be fixed in a follow-up sweep.

### P3 — INDEX.md missing `docs/planning/github-label-taxonomy.md`

- File exists at `docs/planning/github-label-taxonomy.md` (43 lines, Sprint 24 artifact)
- Not listed in INDEX.md's Planning section
- **Pre-existing:** This was flagged in the Sprint 25 planning bookkeeping report (`2026-07-11-sprint25-planning.md`) but not yet resolved

---

## Cross-File Contradictions

| File A | File B | Issue | Severity |
|---|---|---|---|
| ROADMAP.md (line 19): `99/97/74/91/82/97/80` | `strike.md` (line 51): `94, 87, 71, 55, 63, 41, 22` | **Score contract mismatch** — strike.md has Sprint 2-era values | **P1** |
| ROADMAP.md (line 19): `99/97/74/91/82/97/80` | `backend-engineering/SKILL.md` (line 95): `98, 91, 73, 66, 58, 44, 26` | **Score contract mismatch** — Sprint 17-era values | **P1** |
| ROADMAP.md (line 19): `99/97/74/91/82/97/80` | `ml-engineering/SKILL.md` (line 64): `94, 87, 71, 63, 55, 41, 22` | **Score contract mismatch** — Sprint 3-era values | **P1** |
| ROADMAP.md (line 19): `99/97/74/91/82/97/80` | `audit-checklist/SKILL.md` (line 63): `94, 87, 71, 63, 55, 41, 22` | **Score contract mismatch** — Sprint 3-era values | **P1** |

No P0 contradictions found between CURRENT core docs (ROADMAP.md, INDEX.md, AI_PROBLEMS.md are all consistent).

---

## File Existence

| Path | Expected Status | Actual Status |
|---|---|---|
| `.opencode/skills/github-basics/SKILL.md` | EXISTS with content (under 25 words body) | ✅ EXISTS (8 lines, 16-word body — under limit) |
| `.opencode/skills/archived-files/SKILL.md` | EXISTS with content (under 25 words body) | ✅ EXISTS (8 lines, 16-word body — under limit) |
| `.opencode/plans/2026-07-11-sprint-25.md` | EXISTS (sprint plan) | ✅ EXISTS (671 lines) |
| `docs/planning/github-label-taxonomy.md` | EXISTS | ✅ EXISTS (43 lines) — but not indexed |
| `~/.config/opencode/skills/decision-framework/SKILL.md` | Updated with GitHub section | ✅ EXISTS, has GitHub Workflow Assumptions section |
| `~/.config/opencode/skills/cli-toolbox/SKILL.md` | Updated with GitHub section | ✅ EXISTS, has GitHub Workflow section |

### Skill GitHub Workflow coverage (all 16 project skills):

| Skill | GitHub Workflow Section? | Expected? |
|---|---|---|
| `audit-checklist` | ✅ Yes | Expected (Group B — substantive) |
| `backend-engineering` | ✅ Yes | Expected (Group E — batch) |
| `cloud-llm-engineering` | ✅ Yes | Expected (Group E) |
| `codebase-review` | ❌ No | **Expected** — flagged out of scope (YAML parse error) |
| `devops-engineering` | ✅ Yes | Expected (Group E) |
| `frontend-engineering` | ✅ Yes | Expected (Group E) |
| `github-basics` | ❌ No | **Expected** — this IS the GitHub skill |
| `archived-files` | ❌ No | **Expected** — minimal skill about archived files |
| `intel-toolbox` | ✅ Yes | Expected (separately updated) |
| `ml-engineering` | ✅ Yes | Expected (Group E) |
| `ml-toolbox` | ✅ Yes | Expected (Group E) |
| `new-integration-pattern` | ✅ Yes | Expected (Group E) |
| `privacy-legal-advising` | ✅ Yes | Expected (Group E) |
| `triage-toolbox` | ✅ Yes | Expected (Group E) |
| `ux-designing` | ✅ Yes | Expected (Group E) |
| `wa-gov-consulting` | ✅ Yes | Expected (Group E) |

**Result:** All 13 in-scope skills have GitHub Workflow sections. The 3 without (archived-files, codebase-review, github-basics) are all expected.

---

## GitHub Issue Cross-Reference

| Issue | Title | Status | Milestone |
|---|---|---|---|
| #40 | `[Sprint 25] Phase 0: Audit — Verify state, test access, inventory skills` | ✅ Open | Sprint 25 |
| #41 | `[Sprint 25] Phase 1: Infra — Create Issues, update ROADMAP.md` | ✅ Open | Sprint 25 |
| #42 | `[Sprint 25] Phase 2: Core Agent Updates — AGENTS.md + 5 agent files` | ✅ Open | Sprint 25 |
| #43 | `[Sprint 25] Phase 3: Skill Updates — 15 project + 2 global skills` | ✅ Open | Sprint 25 |
| #44 | `[Sprint 25] Phase 4: Capability Test — End-to-end validation` | ✅ Open | Sprint 25 |
| #45 | `[Sprint 25] Phase 5: Verification & Bookkeeping` | ✅ Open | Sprint 25 |
| #46 | `[Sprint 25] Phase 6: Quality Gate & Commit` | ✅ Open | Sprint 25 |

**All 7 issues (#40–#46) exist, are open, and are under the Sprint 25 milestone.** ✅

ROADMAP.md Sprint 25 entry (line 147) correctly references `.opencode/plans/2026-07-11-sprint-25.md`. ✅

---

## Orphans Found

None. All active skill files are referenced by at least one agent's Loadable Skills table. Archived files are not referenced by any current (non-archive) docs.

---

## ROADMAP.md Sprint 25 Status Check

| Sprint 25 Item | ROADMAP Status | Actual State | Match? |
|---|---|---|---|
| Phase 0: Audit | ✅ Complete | Completed — gh tested Level 5/5, skills inventoried | ✅ |
| Phase 1: Sprint 25 Infra | 🔄 In Progress | Issues created (#40–#46), ROADMAP updated | ✅ |
| Phase 2: Core Agent Updates | ⏳ Pending | AGENTS.md + 5 agents updated | ⚠️ **Shows Pending but appears done** |
| Phase 3: Skill File Updates | ⏳ Pending | 13/13 in-scope skills have GitHub notes | ⚠️ **Shows Pending but appears done** |
| Phase 4: Capability Test | ⏳ Pending | Not yet verified | ✅ (matches) |
| Phase 5: Verification | ⏳ Pending | This report is Phase 5 | ✅ (matches) |
| Phase 6: Quality Gate & Commit | ⏳ Pending | Not yet started | ✅ (matches) |

**Note:** ROADMAP.md line 152 shows Phase 1 as "🔄 In Progress" and Phase 2 as "⏳ Pending" — but Phases 2 and 3 appear substantially complete based on file analysis. The ROADMAP status badges may need updating once final verification passes.

---

## INDEX.md completeness check

Checked against all files under `docs/`:

| Status | File | In INDEX.md? |
|---|---|---|
| ✅ | `docs/INDEX.md` | Self |
| ✅ | `docs/planning/ROADMAP.md` | Yes |
| ✅ | `docs/planning/HANDOFF-2026-07-08.md` | Yes |
| ✅ | `docs/planning/ai-doc-strategy-2026-07-07.md` | Yes |
| ❌ | **`docs/planning/github-label-taxonomy.md`** | **Missing** — created Sprint 24 |
| ✅ | `docs/planning/SPRINT_NEXT_PLAN.md` | Yes (as archive/SPRINT_NEXT_PLAN.md) |
| ✅ | `docs/architecture/MVP_SCOPE.md` | Yes |
| ✅ | `docs/architecture/scoring-weights.md` | Yes |
| ✅ | `docs/architecture/comparison-vs-described-system.md` | Yes |
| ✅ | `docs/reference/AI_PROBLEMS.md` | Yes |
| ✅ | `docs/reference/hostname-standards.md` | Yes |
| ✅ | `docs/reference/xgboost-investigation-report.md` | Yes |
| ✅ | `docs/research/RESEARCH_FINDINGS.md` | Yes |
| ✅ | `docs/guides/WINDOWS_SETUP.md` | Yes |
| ⚠️ | `docs/archive/*` | Most excluded by note (expected) |

**Result:** 1 missing document (`github-label-taxonomy.md`).

---

## Verdict

**MINOR ISSUES** — 1 P1, 1 P3, zero P0

### What's Good
- ✅ All 7 GitHub Issues (#40–#46) created and correctly assigned to Sprint 25 milestone
- ✅ ROADMAP.md Sprint 25 entry correctly references `.opencode/plans/2026-07-11-sprint-25.md`
- ✅ AGENTS.md and all 5 agent files updated with GitHub workflow
- ✅ 13/13 in-scope skill files updated with GitHub Workflow sections
- ✅ `github-basics` and `archived-files` skills exist with under-25-word body
- ✅ Both global skills (`decision-framework`, `cli-toolbox`) updated (as out-of-repo changes)
- ✅ No orphaned references, no dead links
- ✅ ALL archived files properly excluded from current docs

### Needs Fixing

1. **P1 — Score contract stale in 4 active files:**
   - `strike.md`, `backend-engineering/SKILL.md`, `ml-engineering/SKILL.md`, `audit-checklist/SKILL.md`
   - All reference old values instead of canonical `[99, 97, 74, 91, 82, 97, 80]`
   - **Recommendation:** Batch-fix in a sweep — these are unambiguous stale references

2. **P3 — INDEX.md missing `github-label-taxonomy.md`:**
   - Add entry to INDEX.md Planning section

### ROADMAP Status Badges
- Phase 2 and Phase 3 show "⏳ Pending" in ROADMAP.md but appear complete. Update after this bookkeeping pass confirms all changes are in place.
