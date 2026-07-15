---
name: github-basics
description: "Safely manage TriageMate Git and GitHub lifecycle work: workspace ownership, branch and PR preflight, CI evidence, Issues, Milestones, authorized merges, and recovery. Use for any repository coordination or GitHub mutation."
---

# GitHub workflow

Use this skill for repository coordination. The `git-steward` owns normal Git/GitHub lifecycle work; other agents report evidence to the Commander, which delegates a self-contained task package to the steward.

## Safety invariants

- One task has one owned workspace/worktree, one branch, and normally one PR. Do not reuse another agent's branch or worktree.
- `main` is integration-only. Never push directly to it, merge, close a PR/Issue, delete a branch/worktree, drop a stash, reset, rebase shared history, or force-push without explicit commander or user authority for that exact action.
- `gh auth status` confirms authentication only. It does not grant authority to mutate remote state.
- A change is not implemented, completed, or safe to document as such until its intended commit is merged to `origin/main` and the relevant CI evidence is recorded.

## Preflight before edits or remote changes

From the repository root, inspect state before selecting or creating a branch:

```bash
git fetch --prune origin
git status --short --branch
git worktree list --porcelain
git branch -vv
git stash list
gh auth status
gh pr list --state open --limit 100
```

Confirm the assigned Issue, target base, existing PRs, and worktrees do not already cover the task. If ownership, a dirty worktree, a duplicate PR, or the correct base is unclear, stop and report it to the commander; do not "clean up" another agent's state.

## Change and PR workflow

1. The commander assigns the Issue, base, branch name, workspace owner, allowed scope, and verification requirements. The steward records this allocation for multi-agent work.
2. Create or use only the assigned branch from the verified base. Keep commits scoped and inspect `git diff --check` plus the intended test results before committing.
3. Push the branch and create one PR linked to the Issue and milestone. State the exact head SHA, changed files, tests, and known limitations in the handoff.
4. Verify CI for the exact PR head, not merely a similarly named run:

   ```bash
   gh pr checks <pr-number> --watch
   gh pr view <pr-number> --json headRefOid,baseRefName,state,mergeStateStatus,url
   ```

5. Merge only after explicit authorization. After merge, update the integration checkout with a fast-forward pull, confirm `main == origin/main`, and check the resulting main CI where the workflow runs differently for pushes.

## Tracking and documentation

- GitHub Issues are the task record; Milestones group sprint work. Do not create duplicate tracking.
- Update Issue/Milestone status only when the corresponding delivery state supports it.
- Docs may describe a design as proposed on a branch, but may say **implemented** or **complete** only after the intended change is present on `origin/main`.

## Safe cleanup and recovery

After a confirmed merge and a clean owner worktree, remove only the merged branch/worktree that was explicitly assigned for cleanup. Do not use `gh pr merge --delete-branch` when the branch is checked out by a worktree.

For abandoned or confusing work: preserve the branch name and commit SHA first, inspect all worktrees and stashes, and report a recovery plan. Force-removal, stash dropping, reset, or history rewriting requires separate explicit authority.
