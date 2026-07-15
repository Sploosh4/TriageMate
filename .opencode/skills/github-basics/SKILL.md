---
name: github-basics
description: "Safely manage TriageMate Git and GitHub lifecycle work from the user-created OpenCode workspace and its existing branch: preflight, commits, pushes, PRs, CI evidence, tracking, authorized merges, and recovery."
---

# GitHub workflow

Use this skill for repository coordination. The `git-steward` owns normal Git/GitHub lifecycle work; other agents report evidence to the Commander, which delegates a self-contained task package to the steward.

## Safety invariants

- Only the user creates a task workspace manually through OpenCode. The GUI workspace already supplies the task's one worktree and branch; all agents assigned to that task share them.
- No agent may create or switch a workspace, worktree, or branch. There is no manual/CLI worktree fallback. Never run `git worktree add`, `git switch`, or `git checkout` to change branches, and never edit the separate primary `main` checkout.
- `main` is integration-only. Never push directly to it, merge, close a PR/Issue, delete a branch/workspace/worktree, drop a stash, reset, rebase shared history, or force-push without explicit Commander or user authority for that exact action.
- `gh auth status` confirms authentication only. It does not grant authority to mutate remote state.
- A change is not implemented, completed, or safe to document as such until its intended commit is merged to `origin/main` and the relevant CI evidence is recorded.

## User-created OpenCode workspace

- The current GUI workspace is the task's only worktree. Use its existing path and branch exactly as assigned.
- Before editing, verify that the workspace belongs to the assigned Issue and was created from the intended base. If it is stale, dirty with unrelated changes, or assigned to another task, report the mismatch; do not repurpose it.
- The user creates one GUI workspace per independent Issue. Commander, Strike, Auditor, Bookkeeper, Intel, and Git Steward work inside that same task workspace and on its existing branch.
- If no suitable GUI workspace exists, stop and ask the user to create one through OpenCode. Do not construct a substitute with Git or the CLI.

## Preflight before edits or remote changes

From the assigned workspace root, validate the existing workspace and branch before edits or remote changes:

```bash
git fetch --prune origin
git status --short --branch
git worktree list --porcelain
git branch -vv
git stash list
gh auth status
gh pr list --state open --limit 100
```

Record the repository root (`git rev-parse --show-toplevel`), current branch, and head SHA. Confirm they match the Commander's assigned Issue, target base, workspace, and existing branch, and that existing PRs and worktrees do not already cover the task. If ownership, a dirty worktree, a duplicate PR, a second worktree for the same task, or the correct base is unclear, stop and report it to the Commander; do not create, switch, repurpose, or clean repository topology.

## Change and PR workflow

1. The user creates the task workspace manually through OpenCode. The Commander assigns the Issue, expected base, existing GUI workspace and branch, allowed scope, expected PR, and verification requirements; Git Steward validates and records that allocation without creating or selecting repository topology.
2. Work only in the already assigned GUI workspace and existing branch. Keep commits scoped and inspect `git diff --check` plus the intended test results before committing.
3. Push the branch and create one PR linked to the Issue and milestone. State the exact head SHA, changed files, tests, and known limitations in the handoff.
4. Verify CI for the exact PR head, not merely a similarly named run:

   ```bash
   gh pr checks <pr-number> --watch
   gh pr view <pr-number> --json headRefOid,baseRefName,state,mergeStateStatus,url
   ```

5. Merge only after explicit authorization. After merge, verify the resulting `origin/main` SHA and main CI where the workflow runs differently for pushes. Do not switch the task workspace to `main` or update the separate primary `main` checkout; report any local integration-checkout maintenance for the user to handle separately.

## Tracking and documentation

- GitHub Issues are the task record; Milestones group sprint work. Do not create duplicate tracking.
- Update Issue/Milestone status only when the corresponding delivery state supports it.
- Docs may describe a design as proposed on a branch, but may say **implemented** or **complete** only after the intended change is present on `origin/main`.

## Safe cleanup and recovery

After a confirmed merge and successful `main` CI, cleanup still requires explicit authority for the exact branch or GUI workspace. The user closes the agent session and deletes the GUI workspace through OpenCode. Git Steward may delete the merged remote branch only when separately authorized and safe; it never removes the GUI worktree directly. Do not use `gh pr merge --delete-branch` while the branch is checked out by any worktree.

For abandoned or confusing work: preserve the branch name and commit SHA first, inspect all worktrees and stashes, and report a recovery plan. Force-removal, stash dropping, reset, or history rewriting requires separate explicit authority.
