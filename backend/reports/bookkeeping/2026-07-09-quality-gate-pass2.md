# Bookkeeping Report — Quality Gate Pass 2

**Date:** 2026-07-09  
**Trigger:** Quality gate — second consecutive clean-pass verification  

---

## Specific Check Result (User-Requested)

| Check | Result |
|-------|--------|
| `rg -n "OPEN\|pipeline drifts remain\|🔴 MEDIUM" docs/reference/AI_PROBLEMS.md` | **CLEAN** — only line 5 matches (intentional "OPEN items remain unresolved" in doc description text) |

---

## 1. Cross-File Contradictions

### P0 — INDEX.md vs AI_PROBLEMS.md: open pipeline drift count mismatch

| Source | Claim | Actual in AI_PROBLEMS.md |
|--------|-------|--------------------------|
| `INDEX.md:20` | `Bug tracker. 2 open items (pipeline drifts).` | All items ✅ FIXED, no OPEN items remain |
| `INDEX.md:42` | `Bug tracker — 2 open items (pipeline drifts).` | Line 3: "ALL pipeline drifts now fixed" |
| `INDEX.md:76` | `What's broken? — 2 open pipeline drifts` | Items #17, #18 both ✅ FIXED |

**Verdict:** P0 contradiction. `INDEX.md` is marked CURRENT and claims 2 open pipeline drifts, but `AI_PROBLEMS.md` (also CURRENT) says ALL pipeline drifts are fixed. Both items #17 and #18 are marked ✅ FIXED with no other OPEN items remaining.

**Note:** The 2 items previously referenced by INDEX.md (`_cvss_cia` default mismatch, `lateral_reachability` type mismatch) were resolved during Sprint NEXT / subsequent hygiene rounds. AI_PROBLEMS.md was updated to reflect this, but INDEX.md was not.

### ROADMAP.md vs MVP_SCOPE.md — Status consistency

| Check | Result |
|-------|--------|
| ROADMAP.md:CURRENT, MVP_SCOPE.md:OUTDATED | ✅ Consistent — MVP_SCOPE correctly marked outdated |
| Feature counts: both say 419-dim (35 tabular + 384 SBERT) | ✅ Consistent |
| Sprint 16 in ROADMAP sprint table | ✅ Present (row added since previous round) |

### HANDOFF-2026-07-08.md — Sprint 16 updates

| Check | Result |
|-------|--------|
| Test count line 21 | ✅ Updated to "275/275 tests pass" |
| Drift monitoring table (Pre-Tier, EPSS) | ✅ Updated — tests, feature parity, registries shown |
| Model registry entries | ✅ Present for Pre-Tier and EPSS |
| Action items line 47 | ✅ Updated — acknowledges Sprint 16 completion |

---

## 2. Stale File References

| Reference | File | Status |
|-----------|------|--------|
| `docker-compose` (hyphenated) | `docs/archive/*.md` | ✅ All in ARCHIVED — no action |
| `PRIS Act` → `WAICP` | `docs/archive/sprints-1-6/COURSE_CORRECTION.md` | ✅ Archived only — acceptable |
| `integrations/llm.py` | Any CURRENT doc? | ✅ Clean — zero references in CURRENT docs |
| `backend/venv/` | Any CURRENT doc? | ✅ Clean — all use `.venv` |

---

## 3. Numeric Consistency

| Metric | Sources | Consistent? |
|--------|---------|-------------|
| Test count: 275 | ROADMAP.md, HANDOFF.md, INDEX.md | ✅ All agree |
| 419-dim model (35 tabular + 384 SBERT) | ROADMAP.md, MVP_SCOPE.md | ✅ All agree |
| Pre-Tier: 60-dim RF, 1,476 training rows, 351 holdout | ROADMAP.md, HANDOFF.md | ✅ All agree |
| EPSS v4: 777 rows from `synthetic_findings` | ROADMAP.md, HANDOFF.md, INDEX.md | ✅ All agree |
| 1,827 synthetic_assets rows | ROADMAP.md, HANDOFF.md, INDEX.md | ✅ All agree |
| 97 research_references rows | ROADMAP.md, INDEX.md | ✅ All agree |
| ROC-AUC 0.9459 | ROADMAP.md, MVP_SCOPE.md, HANDOFF.md | ✅ All agree |
| R² 0.99 for EPSS v4 | HANDOFF.md | ✅ Single source, no contradiction |
| Alembic migrations: 001-007 (7) | ROADMAP.md, MVP_SCOPE.md | ✅ All agree |

---

## 4. Status Badge Accuracy

| Doc | Self-Declared | INDEX.md Declares | Match? |
|-----|--------------|------------------|--------|
| `ROADMAP.md` | CURRENT | CURRENT | ✅ |
| `MVP_SCOPE.md` | OUTDATED | OUTDATED | ✅ |
| `AI_PROBLEMS.md` | CURRENT | CURRENT | ✅ (badge matches, but description content contradicts — see P0 above) |
| `RESEARCH_FINDINGS.md` | OUTDATED | OUTDATED | ✅ |
| `HANDOFF-2026-07-08.md` | CURRENT (no badge, implied) | CURRENT | ✅ |
| `ai-doc-strategy-2026-07-07.md` | CURRENT (implied) | CURRENT | ✅ |
| `xgboost-investigation-report.md` | CURRENT | CURRENT | ✅ |
| `hostname-standards.md` | CURRENT | CURRENT | ✅ |
| `WINDOWS_SETUP.md` | CURRENT | CURRENT | ✅ |

---

## 5. INDEX.md Completeness

All non-archive CURRENT docs are accounted for in INDEX.md. Archived files are excluded per the note at line 148 (intentional). ✅

**Note:** `backend/ml/README.md` is referenced in INDEX.md line 46 as CURRENT — verified it exists and redirects to graphify output. ✅

---

## 6. Orphan Detection

| Pattern | Result |
|---------|--------|
| Archived files referenced by CURRENT docs | ✅ None found (references to archive are intentional historical notes) |
| Skill/agent file exists but never referenced | ✅ All skills and agents cross-referenced in agent Loadable Skills tables |
| `.opencode/ARCHIVED/` files referenced by active docs | ✅ Only in `.opencode/DESIGN_RATIONALE.md` and `.opencode/RESTRUCTURE_HANDOFF.md` (both intentional) |

---

## 7. Items from Previous Round — Re-check

Issues flagged in `2026-07-09-gate-freshness.md` (MINOR ISSUES verdict):

| Issue | Status |
|-------|--------|
| **P3** ROADMAP.md:77 note mentions `cisa_kev` as excluded from table where it doesn't appear | 🔴 **Still present** — should reference `osv_lead_days` |
| **P3** INDEX.md:36 archive-path file under Planning section | 🔴 **Still present** — `archive/file-consolidation-plan-2026-07-07.md` under `## Planning` |
| **P4** AGENTS.md Quick Reference omits HANDOFF-2026-07-08.md | 🔴 **Still present** (minor) |
| **P4** `backlog/` directory not discoverable | 🔴 **Still present** (minor) |

Issues from `2026-07-09-sprint16-freshness.md` (NEEDS ATTENTION verdict):

| Issue | Status |
|-------|--------|
| ROADMAP.md: Sprint 16 entry in table | ✅ **Fixed** |
| ROADMAP.md: Pre-Tier/EPSS registries in ML Artifacts | ✅ **Fixed** |
| HANDOFF.md: Test count + drift table | ✅ **Fixed** |
| INDEX.md: Sprint 16 docs + test files | ✅ **Fixed** |
| INDEX.md: Sprint count 15→16 | ✅ **Fixed** |

---

## 8. Auto-Fixed Items

None auto-fixed in this round. All issues found are content inaccuracies, not stale path references.

---

## 9. Items Flagged for Human Review

| Priority | File | Issue |
|----------|------|-------|
| **P0** | `docs/INDEX.md:20,42,76` | Says "2 open items (pipeline drifts)" but AI_PROBLEMS.md shows 0 open items (all fixed). Fix: change to "0 open items (all resolved)" everywhere. |
| **P3** | `docs/planning/ROADMAP.md:77` | Note says `cisa_kev` is "excluded" from the 37-field table, but `cisa_kev` doesn't appear in the table. Should reference `osv_lead_days` instead (the actual 38th field that's metadata-only). |
| **P3** | `docs/INDEX.md:36` | `archive/file-consolidation-plan-2026-07-07.md` listed under `## Planning` section. Should be under `## Archive` or clearly prefixed. |
| **P4** | `AGENTS.md:19-30` | Quick Reference table doesn't include `docs/planning/HANDOFF-2026-07-08.md` or `backend/reports/intel/wa-gov-infrastructure-research.md`. |
| **P4** | `backlog/TASK_STORE_COLUMNS_IN_NPZ.md` | Not referenced in INDEX.md or AGENTS.md — invisible to AI agents. |

---

## 10. Verdict

**ISSUES FOUND** — Not eligible for audit retirement.

One P0 cross-file contradiction (INDEX.md vs AI_PROBLEMS.md on open pipeline drifts) and several lingering P3–P4 issues from the previous round remain unaddressed.

### What's clean
- All 6 root symlinks valid ✅
- All status badges consistent ✅
- Sprint 16 content (test files, registries) now documented in all CURRENT docs ✅
- No orphaned references to deleted files ✅
- All numeric metrics consistent across docs ✅
- HANDOFF-2026-07-08.md fully updated for Sprint 16 changes ✅

### What needs fixing before audit can be clean
1. **P0:** Fix INDEX.md lines 20, 42, 76 — change "2 open items (pipeline drifts)" to "0 open items (all resolved)" 
2. **P3:** Fix ROADMAP.md line 77 — change `cisa_kev` reference to `osv_lead_days`
3. **P3:** Move INDEX.md archive file entry from Planning to Archive section
4. **P4:** Add HANDOFF-2026-07-08.md to AGENTS.md Quick Reference (optional)
