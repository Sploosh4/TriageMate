# Agent & Skill Descriptions — Design Rationale

## Agents (6)

---

### commander
> Primary coordinator for TriageMate. Delegates work to specialist subagents, including git-steward, strike, intel, auditor, and bookkeeper. Never writes code or runs commands directly. Use for multi-step tasks, sprint planning, orchestration, and coordinating complex changes across the codebase.

**Why this description:**
- "Coordinates" / "delegates" / "orchestration" are the keywords — the AI should think of commander as a dispatcher, not a doer.
- "Never writes code or runs commands directly" is explicit so the AI doesn't attempt direct work. Combined with the `edit: deny, bash: deny, write: deny` permissions, this makes delegation the only available path.
- "Multi-step tasks, sprint planning" covers the commander's role across the full sprint lifecycle — not just immediate requests.
- `mode: primary` means it can be the default agent. The description is broad enough to handle any opening prompt but specific enough that the AI knows its role.

---

### git-steward
> Repository publishing steward for TriageMate. Validates the user-created OpenCode workspace and existing branch, then owns commits, pushes, pull requests, CI, Issue/Milestone tracking, merge-readiness, and safe recovery; never creates or switches repository topology and does not implement product code.

**Why this description:**
- Repository topology is a distinct coordination responsibility, separate from product implementation and audit.
- The Commander relays a self-contained task package to `git-steward` for commit, push, PR, CI, and tracking work while retaining approval authority for irreversible actions; this avoids assuming one fresh subagent can inherit another's context.
- Only the user creates a task workspace manually through OpenCode. The GUI workspace already supplies the task worktree and branch, all assigned agents share them, and agents never create or switch repository topology. Independent Issues require separate user-created GUI workspaces; there is no manual/CLI fallback.
- “Does not implement product code” prevents repository maintenance from becoming a competing implementation workspace.

---

### strike
> Full-stack code-writing agent for TriageMate. Writes Python, JavaScript, CSS, Docker configs, ML training code, database schema changes, and all file modifications. Use for ANY task that requires editing code, running commands, or modifying files.

**Why this description:**
- "Full-stack code-writing" immediately signals this is the implementation agent. Keywords cover every layer: Python, JavaScript, CSS, Docker, ML, DB.
- No permission restrictions — strike is trusted to do everything. The description doesn't need to gate behavior because the agent's prompt and loaded skills handle domain decisions.
- "ANY task that requires editing code, running commands, or modifying files" is deliberately broad. Every code-change task routes here. The commander decides WHEN to delegate; this description tells it WHO to delegate to.
- The strike agent loads domain-specific skills (backend-engineering, ml-engineering, frontend-engineering, etc.) on demand, so the description doesn't need to enumerate them.

---

### intel
> Threat intelligence research agent for TriageMate. Researches CVEs, queries NVD/OSV/ExploitDB/GreyNoise/OTX, assesses threat landscape, and produces .md intelligence reports. Use for ANY external research, vulnerability lookup, or threat assessment.

**Why this description:**
- "Threat intelligence research" is the domain. Specific data sources (NVD, OSV, ExploitDB, GreyNoise, OTX) are listed as keywords so the AI matches this agent when any of those sources are mentioned.
- "Produces .md intelligence reports" makes the output format explicit. The commander knows it will get a file back, not a code change.
- "ANY external research" — broad gate. The word "external" is important: intel is the only agent with `webfetch: allow`.
- Permission restrictions (`bash: deny`, `task: deny`, `.md`-only edit/write) enforce the research-only role. The description aligns: research, query, assess, produce reports — no mention of implementation.

---

### auditor
> Technical auditor for TriageMate. Runs analysis scripts, validates ML models, checks schema parity, verifies feature vector contracts, and produces .md audit reports. Use for code review verification, pre-deployment checks, sprint quality gates, and calibration validation.

**Why this description:**
- "Technical auditor" — distinguishes from intel's research focus. Auditor verifies what exists; intel researches what's out there.
- "Runs analysis scripts" signals that auditor can execute audit commands (unlike intel) while remaining report-only for product code and GitHub state.
- Specific audit types listed: ML calibration, schema parity, feature vector contracts. These keywords match when the user says "check the calibration" or "validate the schema."
- "Pre-deployment checks, sprint quality gates" covers the auditor's role in the workflow — post-strike verification.
- "Produces .md audit reports" makes the output format explicit, matching the report directory convention.

---

### bookkeeper
> Documentation bookkeeper for TriageMate. Verifies .md freshness, checks for orphaned references, consolidates stale docs, and produces freshness reports. Run after every completed task, sprint completion, or when asked "are the docs up to date?".

**Why this description:**
- Added after sprint experience showed documentation drift between agent descriptions, skill files, and code was the #1 source of rework loops.
- "Freshness" / "orphans" / "consolidates" — the keywords signal this agent maintains structural integrity of the project's documentation, not its content.
- "After every completed task, sprint completion" encodes the mandatory trigger pattern so the commander knows when to invoke it.
- Produces .md reports like auditor and intel — consistent output convention across all subagents.

---

## Skills — Engineering Domain (8)

---

### backend-engineering
> Python, FastAPI, SQLite, database schema, pipeline logic, API endpoints, Pydantic models, scoring engine. Use when editing backend/ files, designing APIs, modifying the pipeline, or changing database schema.

**Why:** Front-loads the tech stack keywords so any mention of Python, FastAPI, or database matches. The "editing backend/ files" trigger is concrete — the AI knows exactly when the code is in the backend directory. Covers the full backend surface: API design, pipeline, schema, scoring.

---

### cloud-llm-engineering
> Tier 2 cloud LLM integration, API call architecture, prompt engineering, retry/backoff, multi-provider failover. Use when editing pipeline/tier_2.py, or working on LLM-related pipeline logic.

**Why:** Narrow trigger — "Tier 2," "LLM," "retry/backoff," "multi-provider" are unique keywords that won't collide with other skills. File path (tier_2.py) gives concrete match. Small surface area means this skill only loads on LLM work. Note: `integrations/llm.py` was removed in Sprint 15.5 hygiene cleanup — all logic consolidated into `pipeline/tier_2.py`.

---

### devops-engineering
> Docker, docker-compose, CI/CD, environment variables, database migration, deployment architecture, infrastructure. Use when editing Dockerfile, docker-compose.yml, .github/workflows, or requirements files.

**Why:** Infrastructure keywords up front. File-path triggers cover all DevOps surface. "requirements files" deliberately includes both requirements.txt and requirements-dev.txt. Not gated with "ONLY when" because Docker/CI questions can come from any context.

---

### frontend-engineering
> HTML, CSS, JavaScript, DOM manipulation, Fetch API, vanilla JS SPA, UI components. Use when editing frontend/ files, index.html, CSS, or JavaScript.

**Why:** "Vanilla JS SPA" is important — signals no framework. If someone says "React" or "Vue," this skill won't match (and shouldn't). File-path trigger covers all frontend work. Now cross-references `ux-designing` for visual/layout decisions.

---

### ml-engineering
> ML model development, XGBoost tuning, feature vector design, training pipelines, EPSS data, NVD corpus, LanceDB vector store, pre-tier classifier. Use when training models, building corpus, engineering features, or evaluating ML performance.

**Why:** Most keyword-dense description — intentionally. ML work touches many subdomains: XGBoost, EPSS, NVD, LanceDB, pre-tier. All listed here so any mention triggers the skill. "Building corpus" and "engineering features" cover the data pipeline side, not just training. Deliberately separate from `ml-toolbox` — this is domain knowledge, the toolbox is CLI commands.

---

### privacy-legal-advising
> Australian privacy law, data handling compliance, demo data safety review, vulnerability disclosure policy, WA government data classification. Use ONLY when assessing privacy/legal risk in data handling, demo scenarios, or implementing new data pipelines.

**Why:** "ONLY when" gate prevents false triggers. Privacy terms ("Australian Privacy Act," "data classification") are unique — they shouldn't match normal development conversations. The gate prevents the AI from loading legal advice for every mention of "data."

---

### wa-gov-consulting
> WA government SOC conventions, hostname plausibility, department naming, data classification rules, Australian government IT standards. Use ONLY when validating hostnames, department assignments, or WA government domain authenticity.

**Why:** Narrowest trigger. "WA government" and "hostname plausibility" are the key unique phrases. "ONLY when" gate is critical here — without it, any mention of "government" or "department" in normal conversation could trigger this. The word "validating" also signals this is a review/check skill, not an implementation skill.

---

### ux-designing
> Visual design, CSS architecture, layout, color palette, accessibility, user-facing copy/text. Use when making UI changes, styling, layout decisions, or reviewing visual consistency in the TriageMate frontend.

**Why:** "Visual design" and "CSS architecture" are the domain signals. "Accessibility" and "user-facing copy" broaden the trigger beyond just color/layout. Cross-linked from `frontend-engineering` for consistency.

---

## Skills — Toolbox/Checklist (4)

---

### ml-toolbox
> ML CLI commands for training, corpus building, data fetching, model evaluation. Use when running train_xgboost, build_training_corpus, fetch_nvd_corpus, refresh_caches, train_pre_tier, or any ML pipeline script.

**Why:** Pure command reference. Specific script names (train_xgboost, build_training_corpus, etc.) as keywords trigger this when exact commands are needed. Deliberately separate from `ml-engineering` — one is "what does XGBoost do and how does the pipeline work," the other is "what exact command do I type." They'll often load together.

---

### intel-toolbox
> Threat intelligence integration modules, data sources, cache files, API endpoints. Use when researching CVEs, querying threat intel sources, checking cache freshness, or understanding available enrichment data.

**Why:** "Integration modules" and "cache files" are concrete resource references. "Cache freshness" triggers when the intel agent needs to check if data is stale. This skill documents what exists and where it lives — it's a map, not instructions since intel can't run commands.

---

### audit-checklist
> Technical audit procedures, ML calibration checks, schema parity validation, feature vector compliance, EPSS evaluation, regression testing. Use when running audits, verifying changes, validating deployment readiness, or performing sprint quality gates.

**Why:** "Audit procedures" is the anchor. "Verify" and "validate" catch audit-like requests that don't explicitly say "audit." The 5 implemented + 7 placeholder audits live in this skill — it grows as the team discovers new audit patterns.

---

### triage-toolbox
> Project-level CLI commands, justfile, Docker, dev server, testing, linting. Use when running the dev server, building Docker, running tests, linting, or asking "what commands are available" in TriageMate.

**Why:** "Commands available" and "justfile" make this the answer to "how do I do X in this project?" The keywords (server, Docker, test, lint) cover the daily dev loop. Updated to list `just` recipes as the primary interface.

---

## Skills — Legacy (1 active, 2 archived)

> **Note:** `dual-database-ddl` and `feature-vector-spec` were archived on 2026-07-07 and their content consolidated into `backend-engineering`. Their design rationale is preserved below for historical reference.

---

### dual-database-ddl [ARCHIVED 2026-07-07]
> Enforce SQLite + PostgreSQL dual DDL pattern for every schema change in database.py

**Why (existing, unchanged):** Simple, direct. "database.py" as the trigger file. "DDL pattern" is unique vocabulary that only appears in schema change contexts.

---

### feature-vector-spec [ARCHIVED 2026-07-07]
> Exact feature list and contract for build_feature_vector() — never remove or rename keys, only append

**Why (existing, unchanged):** Function-name trigger. "Never remove or rename keys, only append" is a behavioral constraint encoded in the description itself.

---

### new-integration-pattern
> Boilerplate template for adding a new threat intel / enrichment source to TriageMate

**Why (existing, unchanged):** Pattern/boilerplate is the signal. "New threat intel" and "enrichment source" match when adding integration modules.

---

## Skill — Global (1)

---

### cli-toolbox
> Universal CLI tools available system-wide: ripgrep (rg), fd, bat, eza, fzf, delta, just, uv. Use when searching code, finding files, reading output, navigating directories, or asking "what tools are available".

**Why:** Tool names are the primary keywords — the AI sees "rg" or "fd" and knows this skill covers it. "Searching code, finding files, reading output, navigating directories" covers the four main CLI use cases. Updated with behavioral rules: always use rg over grep, bat over cat, fd over find, eza over ls. The behavioral rules are in the skill body (not the description) because the description is for matching, the body is for instruction.

---

## Description Design Principles Applied

1. **Front-load concrete keywords.** The AI pattern-matches against the description. If the user says "retrain the XGBoost model," the ML descriptions need "XGBoost" and "train" early.

2. **Use file paths as triggers.** "backend/," "frontend/," "database.py," "tier_2.py" — these are unambiguous. The AI knows exactly which skill to load.

3. **Gate narrow skills with "ONLY when."** Without this, `wa-gov-consulting` would fire on any mention of "government" or "department." The gate prevents false triggers.

4. **Distinguish knowledge vs. commands.** `ml-engineering` (domain knowledge) and `ml-toolbox` (CLI commands) are separate skills with different triggers. They load together when both are needed but independently when only one is.

5. **Match verbs to agent roles.** Intel "researches" and "produces reports." Auditor "validates" and "checks." Strike "writes" and "edits." Commander "coordinates" and "delegates." The verbs in the descriptions align with the permission restrictions.

6. **Keep legacy descriptions as-is.** The 3 existing skills (dual-database-ddl, feature-vector-spec, new-integration-pattern) were already well-described. No reason to change what works.
