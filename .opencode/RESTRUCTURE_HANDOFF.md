# OpenCode Restructure — Handoff Note

**Date:** 2026-07-06
**What:** Complete re-architecture of TriageMate's opencode agent/skill system
**Who should review:** Any AI team validating or correcting this setup
**Requires restart:** Yes — all changes require `opencode` restart to take effect

---

## Philosophy of the Change

Previous state: 8 specialized agents (backend-engineer, ml-engineer, cloud-llm-engineer, devops-engineer, frontend-dev, privacy-legal-advisor, wa-gov-consultant, ux-designer). Each agent carried both identity (who they are) AND expertise (what they know) in a single file.

New state: 4 general agents (commander, strike, intel, auditor) + 12 composable skills. Agents define their role, permissions, and model. Expertise lives in skills that ANY agent can load on demand.

This enables the sprint review workflow: "What did you do that was hard/undocumented?" → add a new skill or update an existing one.

---

## Files Changed

### No code files were touched.
### Only `.opencode/` and `~/.config/opencode/` were modified.

---

## What Was Created

### Agents (4 new, in `.opencode/agents/`)

| File | Role | Model | Writes Code? | Key Restriction |
|---|---|---|---|---|
| `commander.md` | Primary coordinator | Inherits default | **No** | edit:deny, bash:deny, write:deny — MUST delegate |
| `strike.md` | Code writer | deepseek/deepseek-v4-flash | Yes | None — full access |
| `intel.md` | Threat intel researcher | deepseek/deepseek-v4-flash | .md only | bash:deny, task:deny, edit/write restricted to *.md |
| `auditor.md` | Technical auditor | deepseek/deepseek-v4-flash | .md only | task:deny, bash restricted to analysis/pytest/python -c |

### Skills — Engineering Domain (7 converted from old agents, in `.opencode/skills/`)

| Skill File | Loads When | Key Knowledge |
|---|---|---|
| `backend-engineering/SKILL.md` | Editing backend/, pipeline, database | FastAPI, SQLite, pipeline architecture, scoring engine |
| `cloud-llm-engineering/SKILL.md` | Editing tier_2.py, LLM integration | Multi-provider failover, force-reflection prompt, retry strategy |
| `devops-engineering/SKILL.md` | Docker, CI/CD, env vars | docker-compose, Dockerfile, GitHub Actions, env var naming |
| `frontend-engineering/SKILL.md` | HTML/CSS/JS changes | Vanilla JS SPA, component architecture, design system colors |
| `ml-engineering/SKILL.md` | ML models, training, features | XGBoost (68 features), Pre-Tier RF, EPSS, training pipeline |
| `privacy-legal-advising/SKILL.md` | Privacy/legal compliance | Australian Privacy Act, WA data classification, demo data safety |
| `wa-gov-consulting/SKILL.md` | WA Gov domain validation | Department names, hostname conventions, OS-to-dept mappings |
| `ux-designing/SKILL.md` | Visual design, CSS | Color palette, component library, accessibility, demo-reference.html |

### Skills — Toolbox/Checklist (4 new)

| Skill File | Loads When | Key Knowledge |
|---|---|---|
| `ml-toolbox/SKILL.md` | Running ML CLI commands | Exact train/corpus/cache commands, file locations, training screens |
| `intel-toolbox/SKILL.md` | Researching threat intel | 10 integration modules, cache files, API keys, data sources |
| `audit-checklist/SKILL.md` | Running audits | 5 implemented audits + 7 placeholder audit types to be filled in |
| `triage-toolbox/SKILL.md` | Dev server, Docker, testing | Docker compose, pytest, ruff, uvicorn, environment variables |

### Skills — Legacy (3 kept unchanged)

- `dual-database-ddl/SKILL.md` — SQLite + PostgreSQL dual DDL pattern
- `feature-vector-spec/SKILL.md` — feature vector key contract (42 keys)
- `new-integration-pattern/SKILL.md` — boilerplate for adding integrations

### Global Skill (1 new, in `~/.config/opencode/skills/`)

| Skill File | Available In | Knowledge |
|---|---|---|
| `cli-toolbox/SKILL.md` | ALL projects | rg, fd, bat, eza, fzf, delta, just, uv — versions and usage |

### Report Directories (2 new, in `backend/reports/`)

- `backend/reports/intel/` — intel agent writes `.md` intelligence reports here
- `backend/reports/audits/` — auditor agent writes `.md` audit reports here

---

## What Was Archived

8 old agent files moved to `.opencode/ARCHIVED/agents/`:

- `backend-engineer.md` → expertise extracted to `backend-engineering` skill
- `cloud-llm-engineer.md` → expertise extracted to `cloud-llm-engineering` skill
- `devops-engineer.md` → expertise extracted to `devops-engineering` skill
- `frontend-dev.md` → expertise extracted to `frontend-engineering` skill
- `ml-engineer.md` → expertise extracted to `ml-engineering` skill
- `privacy-legal-advisor.md` → expertise extracted to `privacy-legal-advising` skill
- `wa-gov-consultant.md` → expertise extracted to `wa-gov-consulting` skill
- `ux-designer.md` → expertise extracted to `ux-designing` skill

These are preserved for reference. They are NOT loaded by opencode.

---

## Agent Permissions — Exact Specification

### Commander
```yaml
permission:
  edit: deny
  bash: deny
  write: deny
```
Read, glob, grep, task, skill, and webfetch are implicitly allowed (not denied).
The commander coordinates, discovers available work via `grep`/`glob`/`read`, and delegates EVERYTHING via `task`.

### Strike
No permission block — implicit full access to all tools.

### Intel
```yaml
permission:
  webfetch: allow
  read: allow
  glob: allow
  grep: allow
  edit:
    "*": deny
    "*.md": allow
  write:
    "*": deny
    "*.md": allow
  bash: deny
  task: deny
```
Intel can web-fetch, read any file, and write/edit `.md` files only.
Cannot run commands, cannot modify code, cannot delegate to other agents.

### Auditor
```yaml
permission:
  read: allow
  glob: allow
  grep: allow
  edit:
    "*": deny
    "*.md": allow
  write:
    "*": deny
    "*.md": allow
  bash:
    "*": deny
    "python -m analysis*": allow
    "pytest*": allow
    "python -c *": allow
  task: deny
```
Auditor can run analysis scripts, pytest, and Python one-liners.
Cannot run arbitrary bash, cannot modify code, cannot delegate.

### Permission Pattern Rules
Pattern ordering matters: **last matching rule wins.** Broader rules first, narrower rules last.
- `"*": deny, "*.md": allow` → `.md` files allowed, everything else denied ✓
- `"*.md": allow, "*": deny` → `.md` files would be denied because `*` matches last ✗

---

## Skill-Trigger Design

Skills fire when the user's request matches their description keywords. This was intentional:

- `ml-toolbox`: "training", "corpus", "fetch nvd", "train_xgboost"
- `intel-toolbox`: "research", "CVE", "threat intel", "NVD", "ExploitDB"
- `audit-checklist`: "audit", "verify", "validate", "check", "quality gate"
- `triage-toolbox`: "server", "docker", "test", "lint", "commands"
- `cli-toolbox`: "tools", "CLI", "available", "search", "find files"
- `backend-engineering`: "backend", "python", "FastAPI", "database", "pipeline"
- `ml-engineering`: "XGBoost", "feature vector", "model", "train"
- `wa-gov-consulting`: "WA government", "hostname", "department", "ONLY when" gate
- `privacy-legal-advising`: "privacy", "legal", "compliance", "data handling", "ONLY when" gate
- `ux-designing`: "UI", "CSS", "design", "layout", "visual"

---

## Standard Workflow (How These Fit Together)

```
User: "Implement feature X and verify it works"
  ↓
Commander (cannot write code or run commands):
  1. Loads relevant skills to understand the domain
  2. Delegates research to intel → intel writes backend/reports/intel/2026-07-06-feature-x-research.md
  3. Delegates implementation to strike → strike loads backend-engineering, writes code
  4. Delegates audit to auditor → auditor runs analysis, writes backend/reports/audits/2026-07-06-feature-x-audit.md
  5. Reports summary to user with links to both reports
```

---

## Validation Checklist for AI Reviewers

When validating this setup, check:

1. **Agent files parse correctly:**
   - All YAML frontmatter has `description:`, `mode:`, and (where specified) `model:` and `permission:`
   - No YAML syntax errors (especially with `*` and `*.md` quoted properly)

2. **Permission logic is correct:**
   - Commander cannot edit/bash/write → MUST use task tool
   - Intel cannot bash/task → purely research
   - Intel can edit/write *.md but not *.py, *.js, etc.
   - Auditor can run `python -m analysis*` but not arbitrary bash
   - Strike has no restrictions

3. **Skill descriptions are distinct:**
   - No two skills have overlapping keywords that would cause both to fire simultaneously unnecessarily
   - `wa-gov-consulting` and `privacy-legal-advising` use "ONLY when" gates to prevent false triggers on adjacent topics

4. **No orphaned references:**
   - No agent references an agent that was archived
   - No skill references an archived agent (they shouldn't — skills are domain knowledge, not agent references)

5. **Global skill is discoverable:**
   - `cli-toolbox` in `~/.config/opencode/skills/` should appear in all projects
   - Verify by starting opencode in a different project and checking `<available_skills>`

6. **Report directories exist:**
   - `backend/reports/intel/` exists (empty)
   - `backend/reports/audits/` exists (empty)

---

## What Was NOT Done (Deliberate Omissions)

1. **No `justfile` was created.** The `triage-toolbox` skill documents raw commands. A justfile would be the next improvement — convert long `python -m` commands into short `just` recipes.

2. **No `opencode.json` was created at the project root.** All agent/skill definitions use file-based configuration, which is cleaner. A project-level config would only be needed if you want to override provider settings or register MCP servers.

3. **The commander's model was not hardcoded.** It inherits whatever the primary model is, which is correct behavior — the commander is the face of the session and should use your preferred model.

4. **No agent permissions were set on `skill` tool.** All agents can load any skill. This is by design — skills self-select via description keywords. Adding `skill: deny` restrictions would be premature optimization.

---

## Known Issues / Edge Cases

1. **YAML `*` character:** The `*` in `"*": deny` must be quoted in YAML. Unquoted `*` is a YAML alias reference and will cause a parse error. All agent files use `"*"` (quoted) correctly.

2. **Pattern evaluation order:** Permission patterns use LAST-match-wins semantics. The order `"*": deny` then `"*.md": allow` is correct. If someone swaps them, `.md` files become denied.

3. **Commander + default_agent:** The commander has `mode: primary` but is NOT set as `default_agent` in any config. The user must explicitly invoke `/commander` or set `default_agent: commander` in opencode.json to make it the default.

4. **Skill loading race:** If a user says "train a new model and add threat intel," both `ml-toolbox` and `intel-toolbox` may trigger. This is fine — load both, they don't conflict.

5. **Intel can't refresh caches:** Intel is read-only (no bash). If intel discovers stale cache data, it must note this in its report so the commander can delegate a cache refresh to strike.

---

## Next Steps for the User

1. **Restart opencode** — all changes require restart
2. **Test the workflow:** "Commander, research CVE-2024-1234 and tell me if it's in our demo data"
3. **After a sprint,** ask the commander what was difficult — add/update skills accordingly
4. **Consider a `justfile`** to shorten the long `python -m` commands in the toolbox skills
5. **Set `default_agent: commander`** in an opencode.json if you want it to be the default agent
