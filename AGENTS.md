# TriageMate project rules

## Scope

Start with [docs/INDEX.md](docs/INDEX.md) and [current scope](docs/planning/PIVOT_SCOPE.md). TriageMate is a GPL-3.0-only, self-hosted application deployed through two containers: PostgreSQL and FastAPI/React. Fixed React screens and a read-only SQL explorer replace the custom Markdown engine. Obsolete product history and recovery tags have been removed; retained provenance identifiers describe prior construction, not available recovery sources or requirements.

Preserve source provenance, observation times, scopes, exact values and explicit unknowns. CVSS, EPSS and KEV are separate signals; do not invent combined risk scores or infer patch applicability from a product name. Product patch execution and device changes remain out of scope. Microsoft source contracts support operator-configured inputs; missing facts remain unknown.

The user requested discussion before changing database standards. Preserve schema fingerprints, role/authority, migration and evidence contracts until that decision. Deployment changes do not authorize rewriting immutable baseline reference bytes or removing database protections. See [standards tradeoffs](docs/architecture/REFACTOR_STANDARDS.md).

## Evidence and secrets

Fixtures, demonstrations and acceptance use explicitly synthetic data or public data with source/license information. Keep operator-specific Microsoft evidence, tenant/device identifiers, credentials and operational configuration outside Git. Never commit `.env`, database dumps, signed URLs or tokens. Preserve ignored `docs/guides/lab/` originals and private storage without reading, moving or deleting them during cleanup.

Existing scoped private-lab authority does not authorize unrelated environments, product device changes or evidence publication. Verify identity and applicable authorization before private environment operations. Do not contact external parties without explicit authorization.

## Shared checkout and publication

Use the single shared `main` checkout in `origin` (`Sploosh4/TriageMate`) for release-ready work. Future authorized pushes target `main`. Do not switch/create branches, workspaces or worktrees without direction. Coordinate file ownership and preserve concurrent changes. GitHub Issues are canonical work records; do not create local sprint diaries. External writes need applicable authorization.

Keep unfinished work uncommitted. Commit only at the whole user-task boundary, after implementation, documentation and checks. Do not push, create a pull request, change visibility, integrate `main`, publish a release or deploy externally without applicable user instruction. Destructive data/volume deletion, reset, rebase, force-push and issue closure require explicit authority.

## Verification and coordination

Run the smallest complete check set appropriate to the change, including behavior regressions and direct positive/negative coverage for authority, SQL, input validation, migrations and failure paths. Dependency/image changes need provenance checks. Every change receives a secret check and `git diff --check`. Report unavailable checks; a build does not prove collection or persistence.

Integrated changes need frontend/API contract checks and actual two-container startup, health, loopback binding and persistent-volume restart verification. Use isolated synthetic targets; never run mutation tests against retained operator data. Run shared-target PostgreSQL suites sequentially. Fix reproducible failures before claiming completion.

Delegate genuinely independent research, experiments, test/log analysis or explicitly required consolidated passes. Define stable interfaces and non-overlapping ownership for parallel implementation. The coordinator owns schema decisions and integration. Review the complete result after implementation/checks; subagents cannot approve their own work.

## UI and documentation

Use semantic HTML, accessible names, visible focus and keyboard behavior. Keep page/chart titles and actionable errors; omit mini headings, slogans, generic captions and routine success boilerplate. Follow [UI instructions](ui-engine/AGENTS.md). After UI changes, verify the running interface in a new visible tab and leave it open.

Use `docs/` for shared architecture and operating guides and colocated READMEs for module contracts. Use the index rather than duplicating inventories. Write each prose paragraph on one source line, with meaningful blank lines and required list/table/code structure.
