# Bookkeeping Report — Final Documentation Freshness Pass

**Date:** 2026-07-09
**Trigger:** Manual — post-bugfix-sprint final audit
**Auditor:** Bookkeeper

---

## 1. Auto-Fixed

None — all findings below required documentation to be flagged rather than auto-fixed.

---

## 2. Items Flagged for Human Review

### P0 — Cross-File Contradiction

| File | Line | Issue |
|---|---|---|
| `docs/INDEX.md` | 83 | Says **"Enrichment sources: 12 integrations"** but `ROADMAP.md` line 17 says **"14 integrations"** and `HANDOFF-2026-07-08.md` line 117 says **"14 total"** |

**Fix needed:** Change `12` → `14` in INDEX.md line 83:
```
| What data does the corpus contain? | `planning/ROADMAP.md` §Current State (Enrichment sources: 14 integrations) |
```

This is a **P0** — two CURRENT docs contradict each other on a simple factual count. The correct count is 14 (verified: NVD, OSV, OTX, ExploitDB, Metasploit, Tenable, GreyNoise, CMDB, Advisories, MITRE, CWE classifier, Demo generator, Synthetic Telemetry, Network Context).

### P2 — Duplicate Audit File

| File | Size | Description |
|---|---|---|
| `backend/reports/audits/2026-07-09-sprint-17-wip-audit.md` | 204 lines | Earlier version: "Sprint 17 WIP Audit — Database Accessibility, MCP Compatibility, Missed/Outdated Patterns" |
| `backend/reports/audits/2026-07-09-sprint17-wip-audit.md` | 252 lines | Later version: "Sprint 17 WIP Audit — Database MCP Accessibility & DDL Parity" |

These are **two different files** with the same date but different content and different filename conventions (hyphen vs no hyphen in "sprint17"). The shorter one appears to be the superseded earlier version; **it should be archived or removed** to prevent confusion about which audit is authoritative.

---

## 3. Doc-by-Doc Status

### `docs/planning/ROADMAP.md`
**Status: CURRENT** ✅

| Check | Result |
|---|---|
| Open bugs = 0 | ✅ Line 14: "0 (AI_PROBLEMS.md is clean)" — matches reality |
| Test count = 275 | ✅ Lines 13, 101: "275 pass, 0 fail" — consistent with HANDOFF.md |
| Demo scores = 94/92/86/76/71/63/57 | ✅ Line 18: correct Sprint 17 values |
| Sprint 18 items 4, 6, 7 in "Now" | ✅ Lines 51, 53, 54: all three present in "Now — Sprint 18" section |
| Enrichment sources | ✅ 14 integrations — correct count, verified against `backend/integrations/` |
| ML Models table | ✅ ROC-AUC, dims, calibrator/drift status all consistent |

### `docs/reference/AI_PROBLEMS.md`
**Status: CURRENT** ✅

| Check | Result |
|---|---|
| Items 19 and 20 present | ✅ Lines 147-156: Both present and marked FIXED |
| All items resolved | ✅ Line 4: "ALL historical issues resolved" |
| Logic sound | ✅ Item 19 (seed data scores) and Item 20 (hostname regex) are properly documented |

### `docs/INDEX.md`
**Status: NEEDS_UPDATE** ⚠️ (1 P0 issue)

| Check | Result |
|---|---|
| All referenced files exist | ✅ All 16+ referenced files verified on disk |
| Score values correct | ✅ Line 141: "94/92/86/76/71/63/57" |
| **Enrichment source count** | ❌ **Line 83: "12 integrations" should be "14"** |
| Sprint 17 section | ✅ Components and scores accurate |
| Graphify files listed | ✅ All 5 exist on disk |

### `docs/planning/HANDOFF-2026-07-08.md`
**Status: CURRENT** ✅

| Check | Result |
|---|---|
| Score values | No explicit per-row scores listed — no contradiction risk |
| Test count | ✅ Line 21: "275/275 tests pass" matches ROADMAP.md |
| Integration count | ✅ Line 117: "Integration modules (14 total)" — correct |
| Pipeline descriptions | ✅ All tiers, models, metrics accurate |

### `docs/architecture/MVP_SCOPE.md`
**Status: OUTDATED** ✅ (correctly marked)

| Check | Result |
|---|---|
| Status banner | ✅ CAUTION banner at top: "Status: OUTDATED" |
| Old scores | ✅ Line 223: "98, 91, 73, 66, 58, 44, 26" — these are Sprint 1 era scores, expected for an OUTDATED doc |
| Caution text | ✅ References ROADMAP.md for current state |

### Root Symlinks
**Status: CURRENT** ✅

All 6 symlinks verified resolving correctly:
- `ROADMAP.md → docs/planning/ROADMAP.md` ✅
- `AI_PROBLEMS.md → docs/reference/AI_PROBLEMS.md` ✅
- `MVP_SCOPE.md → docs/architecture/MVP_SCOPE.md` ✅
- `RESEARCH_FINDINGS.md → docs/research/RESEARCH_FINDINGS.md` ✅
- `WINDOWS_SETUP.md → docs/guides/WINDOWS_SETUP.md` ✅
- `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md` ✅

---

## 4. Report Directory Analysis

### `backend/reports/audits/` — 31 entries
- One duplicate pair found: `2026-07-09-sprint-17-wip-audit.md` vs `2026-07-09-sprint17-wip-audit.md`
- The rest are unique and appear to be legitimate audit artifacts

### `backend/reports/bookkeeping/` — 39 entries
- Heavy concentration from July 7-9 (many rounds of freshness/hygiene/structural audits)
- Valid accumulation from multiple pass cycles — no clear duplicates

### `backend/reports/intel/` — 17 entries
- Reasonable count covering intelligence research, code audits, and WA gov research
- No anomalies

---

## 5. Orphans Check

| Check | Result |
|---|---|
| Archived files referenced by active docs? | ✅ `docs/INDEX.md` references `archive/` files correctly as ARCHIVED |
| Active file never referenced? | ✅ All active docs appear in INDEX.md |
| Dead links in INDEX.md? | ✅ All referenced paths resolve |

---

## 6. Coverage Gaps

None identified — all new features from Sprints 16-17 (Pre-Tier tests, EPSS monitoring, Security Telemetry, Network Context, Panel 5) are documented in ROADMAP.md, INDEX.md, and HANDOFF.md.

---

## 7. Verdict

```
MINOR ISSUES — 1 P0 contradiction found, 1 P2 duplicate file found
```

| Priority | Issue | File | Action |
|---|---|---|---|
| **P0** | "12 integrations" → "14 integrations" | `docs/INDEX.md` line 83 | Edit the number |
| **P2** | Duplicate sprint-17-wip audit files | `backend/reports/audits/` | Archive/remove superseded version |

**Recommendation:** Apply the P0 fix before the next AI agent reads INDEX.md (the contradiction could mislead an agent about available enrichment sources). The P2 duplicate is cosmetic but worth cleaning up to avoid confusion.

No STRUCTURALLY VERIFIED retirement yet — the P0 contradiction means a follow-up pass is warranted after the fix.
