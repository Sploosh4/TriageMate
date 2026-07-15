---
name: codebase-review
description: Review an unfamiliar codebase methodically while preserving workspace ownership and verifying documentation claims against code and Git evidence.
---

# Codebase Review — Soft Skills & Methodology

> **When to use:** Load this skill at the start of any unfamiliar codebase review, audit, or exploration task. It captures the transferable methodology — not project-specific knowledge, but the *how* of effective review.

> **Agents:** When the commander delegates a review task with this skill loaded, follow the numbered methodology below. Flag any deviation.

Follow `github-basics`: only the user creates the task workspace through OpenCode. Review from its existing shared worktree and branch; never create or switch workspaces, worktrees, or branches or use a manual/CLI fallback. Record the current root, branch, and dirty state, and report an ownership mismatch before continuing.

---

## Methodology

### 1. Scope Acknowledgment

Before reading a single file, state what you *are* and *are not* doing:

- "I'm here to read and understand. I won't modify or activate anything."
- If the user warns about in-progress work, note it. Respect that context throughout.
- If the user says "don't activate or modify", honour it literally — no accidental edits, no database writes, no refactors.

### 2. Multi-Scale Read Pattern

Do not deep-dive before you have context. Read in layers:

| Layer | What | Why |
|---|---|---|
| **1. Index** | `docs/INDEX.md`, `ROADMAP.md`, `README.md` | What does the project say about itself? |
| **2. Top-level tree** | Root directory listing | How is the project organised? |
| **3. Entry points** | `main.py`, `models.py`, `database.py` | What's the architecture skeleton? |
| **4. Key subsystems** | Pipeline stages, routers, integrations | How do the actual mechanics work? |
| **5. Git state** | `git log --oneline -25`, `git status` | What's actively being worked on? |

Read 4–6 files in parallel at each layer. Single-file sequential reads lose the gestalt.

### 3. Verify Claims Against Ground Truth

Documents are aspirational. Code + git are factual. Whenever a doc says:

- "All issues resolved ✅" → open the bug tracker and verify each one
- "No imports of X" → `rg` for the import and count the results
- "Reads from both tables" → check the SQL queries

Grep is your verification tool. Use it liberally. File paths and line numbers in your observations, not "the docs say".

### 4. The Honest-Signal Scan

Projects have tells that reveal engineering maturity more reliably than their README:

**Positive signals:**
- Candid bug tracker with acknowledged regressions (e.g. "ROC-AUC dropped from 0.9946 to 0.9459 as we removed label leakage")
- `OUTDATED`/`ARCHIVED` badges on old docs that are honest about staleness
- Tests that fail when invariants are violated
- Explicit type annotations

**Warning signals:**
- Only CURRENT badges, no OUTDATED ones (docs are never perfectly current)
- All issues always "resolved" with no regressions tracked
- Changelog/commit messages that say "various fixes" without detail
- `.gitignore` that excludes nothing (or includes only `__pycache__/` and `.DS_Store`)

Look for both. Report both. Never report only warnings — that's a sign you're looking for flaws, not understanding.

### 5. Group Observations by Risk, Not By File

Do not report findings alphabetically or by file. Group them in a way the reader can act on:

| Risk Level | Example | Action |
|---|---|---|
| **Hygiene** | Junk files, gitignore gaps, duplicate venvs | Safe to delete, no code logic affected |
| **Dead code** | Deprecated modules with zero imports, unreachable branches | Delete or restore; check tests first |
| **Logic issues** | Missing JOINs, half-wired fields, off-by-ones | Fix with verification; needs test confirmation |
| **Design decisions** | Scoring weights don't sum to 100, flat-mean composite metric | Flag for discussion; presents options with trade-offs |

Each observation must cite **exact file paths and line numbers**. Vague observations erode trust.

### 6. Frame as Observations, Not Accusations

Use neutral language:

| Instead of | Say |
|---|---|
| "This is buggy" | "Current logic does X, which means Y. The effect is Z." |
| "This is broken" | "This is half-wired — the column exists but isn't populated." |
| "This is wrong" | "This may be intentional, but it has consequence X." |
| "This should be deleted" | "This appears unused. Here's the evidence; confirm intent." |

Exception: genuinely dangerous bugs (e.g. SQL injection, hardcoded secrets) should be escalated directly.

### 7. Separate Recommendations From Decisions

When a finding has multiple valid resolutions, present them as options with trade-offs, not as a single prescription:

```
Option A (minimal): update docstring only — zero risk, 5 minutes
Option B (rebalance): change weights to sum to 100 — invalidates baselines, 2 hours
```

Recommend your preferred option but anchor the choice with the user. Do not unilaterally decide design matters.

### 8. Sprint-Scope the Plan

If the user asks for a plan to fix the findings:

- Phase by risk: hygiene first (cannot break anything), then dead code, then logic, then decisions
- Each item independently committable — no mega-PRs
- Each item has a verification command (`just test-file test_foo`)
- Flag items that conflict with in-progress work (check `git status` first)
- Keep the total item count proportional — 6–10 items across 2–4 phases, not 30 individual line edits

### 9. Always End With a Path Forward

A review that identifies problems but offers no path forward is incomplete. End with:

- A decision table for ambiguous items (2–3 options, trade-offs stated)
- A concrete next action ("Phase A ready to execute now; Phase C needs a design discussion")
- An offer to execute or delegate

---

## Antipatterns to Avoid

| Antipattern | Why It's Harmful |
|---|---|
| **The drive-by diagnosis** | Read one file, found one lint issue, declared the codebase "a mess". You lack context. |
| **The NIH gaze** | "Why didn't they use X framework?" Instead of understanding why the current choice was made. |
| **Flagging everything** | Every issue is P1. Nothing is. If everything is critical, nothing is. Use risk tiers. |
| **The silent assumption** | "I'll assume the scoring should sum to 100 and rebalance it." No — flag it with the user first. |
| **Depth-first obsession** | Spent 2 hours reading one router file, ignored the pipeline, database, and frontend entirely. Read breadth-first, then depth. |

---

## Checklist (run at the end)

Before reporting back to the user:

- [ ] Did I read the project's own docs about itself (INDEX, ROADMAP, PROBLEMS)?
- [ ] Did I verify at least 3 doc claims against actual code/git?
- [ ] Are my observations grouped by risk, not by file?
- [ ] Does every observation have a file path and line number?
- [ ] Did I check git status to avoid conflicting with in-progress work?
- [ ] Did I present ambiguous findings as options, not prescriptions?
- [ ] Did I end with a path forward / next action?
