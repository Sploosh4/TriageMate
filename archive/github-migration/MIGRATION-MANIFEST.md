# TriageMate Migration Manifest — Sprint 24

**Date:** 2026-07-11
**Purpose:** Record what was migrated to GitHub-native work tracking
**Verified:** 2026-07-11 via GitHub API (post-execution audit)

## What Changed

| Feature | Status | Details |
|---------|--------|---------|
| Labels | ✅ Created | 16 custom labels + 9 defaults retained = 25 total |
| Milestones | ✅ Created | Sprints 17–25, Backlog, Post-MVP (11 total) |
| Issue Templates | ✅ Created | bug-report, feature-request, task, research (4 + config.yml) |
| Repo Topics | ✅ Set | 6 topics added (vulnerability-management, security, wa-government, python, fastapi, machine-learning) |
| Issues Backfilled | ✅ Created | 37 issues (31 AI_PROBLEMS bugs + 1 backlog + 5 Sprint 24 tracking) |

## Pre-Existing Resources (before Sprint 24)

- Issue #7: Pre-existing test issue "[Bug] **TEST2** CWE Classifier" (CLOSED, Backlog) — not modified by Sprint 24
- Default GitHub labels (9): bug, documentation, duplicate, enhancement, good first issue, help wanted, invalid, question, wontfix
- CI workflow at `.github/workflows/ci.yml`

## Archive Contents

- `plans/` — Snapshot of `.opencode/plans/` at time of migration

## Final State Summary

| Metric | Count |
|--------|-------|
| Labels (total) | 25 |
| Custom labels | 16 |
| Milestones | 11 |
| Migrated issues | 37 |
| Pre-existing issues (excluded) | 1 (issue #7) |
| Total remote issues | 38 |

## Notes

- **Discussions link in config.yml:** Removed on 2026-07-11 — Discussions are disabled and the link was removed from the template chooser.
- **Canonical docs** remain in `docs/` directory
- **Planning** moved to GitHub Issues + Milestones
- See `docs/INDEX.md` for cross-references

## How to Roll Back

See `docs/planning/github-manifest-20260711.json` for the full resource manifest.
See the cleanup procedure in `.opencode/plans/2026-07-11-sprint-24.md` Phase 1 prerequisites.

## Key Commits

- Migration commit: `ed1821e` — Sprint 24: GitHub-Native Work Tracking for AI Workflow
- Template files: `e36b390` — Sprint 24: Add issue templates (bug, feature, task, research)
- Pre-migration checkpoint: `sprint-24-start` tag
