# Bookkeeping Report

**Date:** 2026-07-15
**Trigger:** Final freshness pass for GitHub Issue #86
**Scope:** Proposed OpenCode GUI workspace governance changes

## Auto-Fixed

- `.opencode/agents/bookkeeper.md` — added `workspaces` to the existing no-create/remove/switch/merge/clean rule so GUI workspaces receive the same protection as worktrees and branches.
- `.opencode/skills/github-basics/SKILL.md` — added `workspace` to the explicit-authority deletion rule and normalized `Commander` capitalization.

## Items Flagged for Human Review

- None. The Issue #86 governance change is **proposed and unmerged**. Its workflow requirements must not be described as implemented on `origin/main` until the intended commit is merged and relevant CI evidence is recorded.

## Orphans Found

- None in the changed governance documentation. `github-basics`, `git-steward`, `decision-framework`, the affected agent definitions, and `docs/guides/SELF_HOSTED_RUNNER.md` all resolve to active repository files or roles.

## Coverage Gaps

- None. The proposed GUI-workspace rule is represented in the root `AGENTS.md`, authoritative `github-basics` skill, Commander and Git Steward instructions, specialist agent/skill handoffs, audit and bookkeeping checks, design rationale, historical-plan warnings, and runner boundary guidance.

## Verification Evidence

- Reviewed the complete uncommitted governance diff: 29 pre-report files, limited to governance metadata and Markdown documentation; no product implementation files are changed.
- Cross-file language consistently defines one task as one owned GUI workspace, one worktree, one branch, and normally one PR; subagents assigned to the same task share that workspace.
- Manual/CLI worktrees are consistently described as a fallback only when no OpenCode GUI workspace exists and the Commander explicitly assigns that mode, owner, and path.
- `main` remains integration-only, and merge, closure, deletion, reset, force-push, and other irreversible actions continue to require exact authority.
- Historical Sprint 24 and Sprint 26b plans are explicitly marked as historical execution records, preventing their old Git/worktree commands from overriding current guidance.
- The self-hosted runner remains correctly separated from development workspace/worktree topology and is indexed as CURRENT in `docs/INDEX.md`.
- No proposed text claims that Issue #86 is implemented, complete, merged, or present on `origin/main`.

## Verdict

**FRESH** — after the two mechanical terminology corrections above. The Issue #86 governance documentation is coherent and ready for review as a proposed, unmerged change.
