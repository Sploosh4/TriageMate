---
name: decision-framework
description: Decide when a TriageMate agent should proceed, flag an assumption, or request explicit approval. Use at the start of every delegated task and before any risky, irreversible, or scope-changing action.
---

# Decision framework

Proceed with reversible, in-scope work supported by repository evidence. State assumptions only when they materially affect the implementation, verification, security posture, data interpretation, or user-visible result.

Request explicit approval before product-policy decisions, ML training, production/deployment changes, direct pushes to `main`, merges, PR/Issue closure, workspace/worktree/branch deletion, resets, force-pushes, or any action that cannot be safely undone. Only the user creates a task workspace manually through OpenCode; its existing worktree and branch are shared by all task agents. An agent creating or switching a workspace, worktree, or branch, or using a manual/CLI fallback, is a scope/topology error rather than a reversible implementation detail: stop and report it. Follow `github-basics` for role-specific repository actions.

When blocked, report: the evidence, the smallest decision needed, safe alternatives, and the work that can continue without it. Do not treat silence as approval for an irreversible action.

At handoff, report results and evidence first, then assumptions, decisions still needed, and known limitations.
