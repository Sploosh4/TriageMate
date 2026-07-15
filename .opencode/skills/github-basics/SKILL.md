---
name: github-basics
description: "Safely manage TriageMate Git and GitHub lifecycle work: workspace ownership, branch and PR preflight, CI evidence, Issues, Milestones, authorized merges, and recovery. Use for any repository coordination or GitHub mutation."
---

# GitHub workflow

Use this skill for repository coordination. The `git-steward` owns normal Git/GitHub lifecycle work; other agents report evidence to the Commander, which delegates a self-contained task package to the steward.

## Safety invariants

- One task has one owned workspace, one worktree, one branch, and normally one PR. Subagents for that task share the assigned workspace; they do not receive separate workspaces.
- Select exactly one workspace mode before making changes. Never combine an OpenCode GUI workspace with a manually created worktree for the same task.
- `main` is integration-only. Never push directly to it, merge, close a PR/Issue, delete a branch/workspace/worktree, drop a stash, reset, rebase shared history, or force-push without explicit Commander or user authority for that exact action.
- `gh auth status` confirms authentication only. It does not grant authority to mutate remote state.
- A change is not implemented, completed, or safe to document as such until its intended commit is merged to `origin/main` and the relevant CI evidence is recorded.

## Workspace mode

### OpenCode GUI-managed workspace — default for OpenCode tasks

- The current GUI workspace is already the task's only worktree. Use its current path and branch.
- Never run `git worktree add`, create a `/tmp` worktree, switch this workspace to `main`, or edit the separate primary `main` checkout.
- Before editing, verify that the workspace belongs to the assigned Issue and was created from the intended base. If it is stale, dirty with unrelated changes, or assigned to another task, report the mismatch; do not repurpose it.
- The user creates one GUI workspace per independent Issue. Commander, Strike, Auditor, Bookkeeper, Intel, and Git Steward work inside that same task workspace.

### Manual/CLI worktree — fallback only

Use a manual worktree only when no OpenCode GUI workspace exists and the Commander explicitly assigns manual mode, an owner, and a path. Only Git Steward creates or removes it. Never create a manual worktree merely because another agent needs to inspect or verify the same task.

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

Record the selected workspace mode and repository root (`git rev-parse --show-toplevel`). Confirm the assigned Issue, target base, existing PRs, and worktrees do not already cover the task. If ownership, a dirty worktree, a duplicate PR, a second worktree for the same task, or the correct base is unclear, stop and report it to the Commander; do not create another workspace or "clean up" another agent's state.

## Change and PR workflow

1. The Commander assigns the Issue, workspace mode, base, branch name, workspace owner, allowed scope, and verification requirements. Git Steward records this allocation.
2. In GUI mode, use the already assigned workspace and branch. In explicitly assigned manual mode, Git Steward creates or selects the worktree. Keep commits scoped and inspect `git diff --check` plus the intended test results before committing.
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

After a confirmed merge and successful `main` CI, remove only the merged branch/workspace/worktree explicitly approved for cleanup. The user deletes an OpenCode GUI workspace through the GUI after its agent session is closed; Git Steward removes an explicitly assigned manual worktree. Do not use `gh pr merge --delete-branch` while the branch is checked out by any worktree.

For abandoned or confusing work: preserve the branch name and commit SHA first, inspect all worktrees and stashes, and report a recovery plan. Force-removal, stash dropping, reset, or history rewriting requires separate explicit authority.
