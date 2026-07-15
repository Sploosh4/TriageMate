---
name: audit-checklist
description: Technical audit procedures, ML calibration checks, schema parity validation, feature vector compliance, regression testing, and self-hosted GitHub Actions evidence. Use when running audits, verifying changes, validating deployment readiness, or performing sprint quality gates.
---

# Audit Checklist

This skill grows over time as audit patterns emerge. Add new sections when an agent repeatedly does the same verification.

## GitHub Workflow

Follow `github-basics`: only the user creates the task workspace through OpenCode; use its existing shared worktree and branch, and never create or switch workspaces, worktrees, or branches or use a manual/CLI fallback. Auditors report evidence and do not mutate GitHub state.

---

## 1. ML Calibration Audit 🔴 HUMAN ONLY (~5 min)

**Do NOT run automatically.** Loads 260K CVEs + model inference — takes 5+ minutes.

**Command:** `python -m analysis.calibration_audit --max-samples 5000` (use `--max-samples` to cap time)
**What it checks:** XGBoost probability calibration (predicted vs. actual exploitation rates)
**When:** Manually after any model retraining or feature change

## 2. EPSS Evaluation 🔴 HUMAN ONLY (~5 min)

**Do NOT run automatically.** Same heavyweight corpus load as calibration audit.

**Command:** `python -m analysis.epss_eval --max-samples 5000` (use `--max-samples` to cap time)
**What it checks:** EPSS substitution model accuracy vs. real EPSS scores
**When:** Manually after EPSS model retraining or cache refresh

## 3. Feature Parity Check

**Command:** `python -m analysis.feature_parity_check`
**What it checks:** Feature vector keys match between build script and prediction pipeline
**When:** After any change to `build_feature_vector()` or `build_training_corpus.py`

## 4. Schema Conversion Validation

**Command:** `python -m analysis.validate_conversion`
**What it checks:** Data schema integrity after conversion or migration
**When:** After database schema changes

## 5. Full Regression Test

**Command:** `pytest backend/tests/ -v`
**What it checks:** The default pytest suite — ingest, queue, health, demo generator, and integration. Fuzz testing is opt-in and must be run separately when its risk warrants it.
**When:** Before any deployment or sprint completion

## 6. Self-Hosted CI Verification — required for sprint completion

Local tests establish fast feedback. GitHub Actions establishes that the
committed revision succeeds in a clean checkout on the repository's isolated
`triagemate-vm` runner. Do both for any code-changing sprint.

1. Run the relevant local checks first (`just test`, `just lint`, and focused
   checks for the changed subsystem).
2. Confirm runner health without changing infrastructure:

   ```bash
   bash .opencode/skills/triagemate-runner-ops/scripts/runner-doctor.sh
   gh api repos/Sploosh4/TriageMate/actions/runners
   ```

3. After an authorized push or PR update, wait for the exact PR checks:

   ```bash
   gh pr checks <pr-number> --watch
   ```

4. Record the run URL(s), commit SHA, and result. Every required job must
   succeed. A skipped job is acceptable only when its workflow condition
   intentionally excludes the event; report why it was skipped.
5. Do not claim CI verification from a direct SSH test in the VM. That is a
   useful diagnostic, but GitHub Actions validates the actual workflow,
   checkout, action setup, and runner-label routing.

The intended runner selector is:

```yaml
runs-on: [self-hosted, Linux, X64, triagemate]
```

Do not start, stop, re-register, or rebuild the VM merely to satisfy this
gate. For an offline or queued runner, use `triagemate-runner-ops` and obtain
approval for state-changing recovery actions.

---

## Placeholder Audits (to be implemented)

### 7. Schema Parity Audit
Verify SQLite and PostgreSQL table schemas match exactly. Compare `_init_db_sqlite()` and `_init_db_pg()` in `database.py`. Every column in one must exist in the other with correct type mapping.

### 8. Demo Data Plausibility Audit
Check all demo scenarios against `wa-gov-consulting` rules. No real WA government hostnames, IPs, or department identifiers. Hostnames must follow PRD-APP-SERVER01.dept.wa.gov.au pattern. OS-to-department mappings must be realistic.

### 9. LLM Cost-Per-Case Audit
Track Tier 2 LLM calls — token counts, provider used, fallback triggered. Compare actual costs to the $0.0004/case target. Flag cases that hit the expensive provider or exceeded token budget.

### 10. Cache Freshness Audit
Check last-modified timestamps on all cache files in `backend/data/`. Flag any cache older than its TTL. Identify which caches need refresh before the next pipeline run.

### 11. Score Drift Audit
Track the 7 demo row scores over time. If any score shifts by more than ±3 from its baseline (99, 97, 74, 91, 82, 97, 80), flag for investigation. This catches silent model drift.

### 12. Integration Health Audit
Test each integration module with a known CVE. Verify graceful degradation — failed integrations must not crash the pipeline. Check that all integrations return safe defaults on error.

### 13. DDL Compliance Audit
Verify that any recent `database.py` change has entries in both `_init_db_sqlite()` and `_init_db_pg()`. Cross-reference with the `backend-engineering` skill (dual-DDL pattern was consolidated there after `dual-database-ddl` was archived).

## GitHub Workflow Verification

When auditing changes that involve GitHub:
- Verify the user-created OpenCode GUI workspace, its existing branch, and its worktree match the assignment; confirm no agent-created or switched workspace, worktree, or branch exists for the task.
- Verify the submitted branch/PR has the stated base and exact head SHA; do not infer evidence from a similarly named run.
- Check for a duplicate PR, competing worktree, or relevant stash before recommending merge or cleanup.
- For code changes, verify the required PR checks and, after merge, the relevant `main` workflow checks. Record URLs/SHA/status.
- Confirm documentation describes work as implemented/complete only once the intended commit is present on `origin/main`.
- Do local `.md` files reference GitHub Issues that actually exist? Check with `gh issue view <number>`
- Are milestone references in local sprint plans accurate? Check with `gh api repos/.../milestones`
