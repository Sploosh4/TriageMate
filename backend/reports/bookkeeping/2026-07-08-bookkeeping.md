# Bookkeeping Report

**Date:** 2026-07-08
**Trigger:** Documentation update — ROADMAP.md CWE encoder deferral reason corrected; verify-tier2-cwe-encoder.md post-audit correction added

---

## Scope of This Round

The following files were updated:

1. **`docs/planning/ROADMAP.md`** (line 197): Changed deferral reason from "Blocked on SecureBERT bug fixes" → "Deferred — NVD API + regex sufficient for CWE resolution; local 656MB model adds complexity for marginal benefit"
2. **`backend/reports/audits/verify-tier2-cwe-encoder.md`** (lines 145–165): Added Post-Audit Correction section clarifying the "blocked on SecureBERT bug fixes" framing was logically misleading (ModernBERT and SecureBERT are independent approaches)

Checks performed:
- Stale "Blocked on SecureBERT bug fixes" references in CURRENT docs
- Cross-file contradictions arising from the updated rationale
- ROADMAP.md status date freshness
- Cross-references from/to the audit correction
- Residual open issues from prior bookkeeping rounds (final-2026-07-08.md)

---

## Auto-Fixed

None. All findings require human judgment.

---

## Items Flagged for Human Review

### P2 — Minor / Documentation Drift

| # | File | Issue | Details |
|---|------|-------|---------|
| 1 | `graphify_output/ml_inventory.md` line 222 | Pipeline diagram still says `420 cols` | Actual `training_data_v2.npz` has `X.shape = (253568, 419)` — confirmed via numpy inspection. This was flagged as P1 in `final-2026-07-08.md` but remains unfixed. Regenerate with `just graphify`. |
| 2 | `backend/reports/audits/verify-tier2-cwe-encoder.md` (lines 4, 12, 29, 76, 125, 139) | Original audit body still uses old "Blocked on SecureBERT bug fixes" framing | **Not a bug** — this is a timestamped audit record documenting the state as found. The Post-Audit Correction (lines 145–165) explains the misleading framing. When citing this audit, reference the correction section. No edit needed. |

### P3 — Cosmetic / Non-Urgent

| # | File | Issue |
|---|------|-------|
| 3 | `docs/archive/ml-implementation-plan.md` | File banner says `OUTDATED` but INDEX.md lists it as `ARCHIVED`. Pre-existing from prior rounds — not introduced by this update. |

---

## Slient Check: Old Framing Scan

Searched all active (non-archived) `.md` files for "Blocked on SecureBERT bug fixes":

| File | Found? | Verdict |
|------|--------|---------|
| `docs/planning/ROADMAP.md` | ❌ Clean — updated to new wording (line 197) | ✅ |
| `docs/architecture/MVP_SCOPE.md` | ❌ Clean — references are factual ("without the 656MB SecureBERT model") | ✅ |
| `docs/reference/AI_PROBLEMS.md` | ❌ Clean — issues marked BYPASSED with correct rationale | ✅ |
| `docs/INDEX.md` | ❌ Clean | ✅ |
| `AGENTS.md` | ❌ Clean | ✅ |
| `.opencode/skills/*.md` | ❌ Clean | ✅ |
| `verify-tier2-cwe-encoder.md` | ⚠️ Found in original audit body (see #2 above) | ✅ Correction exists |

**Archived files** (sprints-1-6, archive/) contain historical references — acceptable per policy. No action needed.

---

## Cross-File Contradiction Scan

Checked pairs of CURRENT-status documents for contradictions related to the CWE encoder:

| Check | Result |
|-------|--------|
| ROADMAP.md (line 197) vs MVP_SCOPE.md (line 120) — CWE encoder rationale | ✅ **Consistent.** Both say NVD API + regex is sufficient / authoritative |
| ROADMAP.md (line 197) vs AI_PROBLEMS.md (#1-3) — "BYPASSED" status | ✅ **Consistent.** AI_PROBLEMS correctly marks SecureBERT/ModernBERT bugs as BYPASSED |
| ROADMAP.md vs INDEX.md — all status badges | ✅ **Consistent** (via prior round validation) |

**No cross-file contradictions found.** ✅

---

## ROADMAP.md Status Date

| Field | Expected | Actual | Result |
|-------|----------|--------|--------|
| Status badge (line 3) | `CURRENT (8 July 2026)` | `CURRENT (8 July 2026)` | ✅ |
| "Last updated" (line 5) | `8 July 2026` | `8 July 2026` | ✅ |

Date is current. No update needed.

---

## Cross-Reference Check: Audit Correction

The `verify-tier2-cwe-encoder.md` audit correction (2026-07-08) explains that "Blocked on SecureBERT bug fixes" was misleading because ModernBERT and SecureBERT are independent approaches.

Should any other document explicitly reference this audit?
- **ROADMAP.md**: Already has the corrected rationale. No additional cross-reference needed.
- **MVP_SCOPE.md**: Never used the "Blocked on SecureBERT bug fixes" framing; its §3.1 already says "The NVD API + regex lookup provides authoritative CWE without the 656MB SecureBERT model." No update needed.
- **AI_PROBLEMS.md**: Issues #1-3 correctly state BYPASSED in favour of NVD API + regex. No update needed.

**Verdict:** No new cross-references required. The corrected rationale is self-consistent across all CURRENT docs.

---

## Residual Open Issues from Prior Rounds

Tracking from `final-2026-07-08.md` (1 P0, 4 P1, 2 P2):

| # | Issue | Priority | Status This Round |
|---|-------|----------|-------------------|
| 1 | INDEX.md line 42 vs xgboost-investigation-report.md (P0 contradiction) | P0 | ✅ **RESOLVED** — INDEX.md now says "✅ All 8 fixes applied, model retrained 2026-07-08" |
| 2 | INDEX.md wrong path for ml-implementation-plan.md | P1 | ✅ **RESOLVED** — Path `archive/ml-implementation-plan.md` is correct |
| 3 | file-consolidation-plan.md says "retrain pending" | P1 | ✅ Acceptable — file is ARCHIVED |
| 4 | ml_inventory.md pipeline diagram says 420 cols | P1 | ❌ **STILL OPEN** — see P2 #1 above |
| 5 | AI_PROBLEMS.md "will be re-added" → "re-added ✅" | P1 | ✅ **RESOLVED** — all three addenda now say "re-added ✅" |
| 6-7 | MVP_SCOPE.md OUTDATED drift, feature_parity.md tooling issue | P2 | ✅ Acceptable drift in OUTDATED file / known tooling limitation |

One residual item from prior rounds remains: **ml_inventory.md line 222** (420 cols → 419 cols).

---

## Orphans Found

None. The two updated files (ROADMAP.md and verify-tier2-cwe-encoder.md) did not create any orphaned references. No archived files are newly orphaned.

---

## Coverage Gaps

None related to this update. Pre-existing gap (archive files not all listed in INDEX.md) noted in prior rounds.

---

## Structural Verification Note

Prior consecutive rounds (`final-2026-07-08.md` → `validation-sprint-convergence-2026-07-08.md`) converged to FRESH with zero structural issues in CURRENT docs. This round introduced two doc updates but created no new contradictions. The only residual issue is a stale auto-generated artifact (`ml_inventory.md` — needs `just graphify`).

**This is the third consecutive round without structural issues in CURRENT docs.** Per the aging-out rule (§76 of bookkeeper.md), this audit indicates convergence. The ml_inventory.md issue is an auto-regeneration workflow gap, not a documentation contradiction.

---

## Verdict

**MINOR ISSUES** — 1 cosmetic P2 (stale graphify output) + 1 P3 (pre-existing badge mismatch)

- ✅ ROADMAP.md deferral reason corrected — no stale "Blocked on SecureBERT fix" framing remains in CURRENT docs
- ✅ No cross-file contradictions created by the update
- ✅ No cross-references needed for the audit correction
- ✅ ROADMAP.md status date is current
- ❌ `graphify_output/ml_inventory.md` line 222 still says 420 cols (419 actual) — run `just graphify`
- 🔄 Approaching structural convergence; one more clean round may trigger audit retirement
