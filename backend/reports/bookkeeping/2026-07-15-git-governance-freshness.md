# Git Governance Freshness Report

**Date:** 2026-07-15
**Trigger:** Completed Git governance documentation update
**Verdict:** FRESH

## Scope reviewed

- `AGENTS.md`
- `.opencode/DESIGN_RATIONALE.md`
- `.opencode/agents/git-steward.md`
- `.opencode/agents/commander.md`
- `.opencode/agents/strike.md`
- `.opencode/agents/auditor.md`
- `.opencode/agents/bookkeeper.md`
- `.opencode/skills/decision-framework/SKILL.md`
- `.opencode/skills/github-basics/SKILL.md`
- `.opencode/skills/audit-checklist/SKILL.md`
- `.opencode/skills/triage-toolbox/SKILL.md`
- Engineering and specialist skills that hand repository coordination to
  `git-steward`
- `docs/guides/SELF_HOSTED_RUNNER.md`

## Validation

- Confirmed `AGENTS.md` contains one authoritative GitHub-workflow line, with no
  conditional-access route remaining: `github-basics` and `git-steward` govern
  repository work; each task owns one workspace/worktree, branch, and PR; and
  `main` is integration-only.
- Confirmed agents report repository evidence to the Commander, which delegates
  a self-contained package to `git-steward`; Commander and steward instructions
  require the Issue, scope, base, workspace/branch, SHA, changed files,
  verification evidence, and requested action.
- Confirmed Sprint 25 is explicitly a historical execution record and that its
  conditional-access workflow is superseded. Confirmed Sprint 29 identifies its
  branch/direct-main directions as historical and points to the current Git
  workflow.
- Confirmed the Roadmap identifies the former Sprint 25 conditional-access and
  capability-test workflow as superseded by the current
  `github-basics`/`git-steward` model.
- Confirmed one task/workspace/worktree/branch/PR ownership and integration-only
  `main` are governed by `github-basics` and `git-steward`.
- Confirmed irreversible Git/GitHub actions and ML training require explicit
  authorization; authentication alone is not treated as authority.
- Confirmed commander, Strike, steward, auditor, and bookkeeper responsibilities
  do not overlap unsafely.
- Confirmed the mandatory bookkeeper pass is described consistently as occurring
  after every completed task and at sprint completion.
- Confirmed the auditor is report-only for product code and GitHub state while
  retaining audit-command and Markdown-report capability.
- Confirmed XGBoost feature dimensions and training-gate instructions are current,
  and corrected `just` commands match the repository recipes.
- Confirmed specialist skills refer repository lifecycle work to
  `github-basics`/`git-steward` rather than duplicating an independent workflow.
- Confirmed the self-hosted runner guide reflects the workflow currently merged
  to `main` and keeps VM operations separate from Git lifecycle policy.
- `git diff --check` reported no whitespace errors.

## Non-blocking follow-up

`.opencode/skills/github-basics/agents/openai.yaml` remains root-owned and could
not be updated during this task. Its display metadata still describes generic
GitHub guidance, while `SKILL.md` now contains the authoritative, expanded
TriageMate workflow. The desired metadata update is known; correcting ownership
and applying it is a non-blocking filesystem follow-up.

## Verdict

**FRESH.** No unblocked instruction or documentation contradiction prevents the
Git governance update from being committed and reviewed.
