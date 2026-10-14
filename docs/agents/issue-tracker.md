# Issue tracker: GitHub

Issues and specifications for this repository live in GitHub Issues. Use an
available GitHub connector or the `gh` CLI and infer the repository from the
configured Git remote. The commands below describe mechanisms, not authorization.
Issue closure and other consequential actions require the authority in AGENTS.md.

## Conventions

- Create an issue with `gh issue create`.
- Read an issue and its comments with `gh issue view <number> --comments`.
- List and filter issues with `gh issue list` and structured JSON output.
- Comment with `gh issue comment <number>`.
- Apply or remove labels with `gh issue edit <number>`.
- Close an issue with `gh issue close <number>`.

Pull requests are not a triage request surface. GitHub shares one number space for
issues and pull requests, so resolve an ambiguous number before acting on it.

When a skill says to publish to the issue tracker, create a GitHub issue. When it
says to fetch the relevant ticket, read the GitHub issue and its comments.

## Wayfinding

Use one issue labelled `wayfinder:map` as the map and link its work items as child
issues. Prefer GitHub sub-issues and native issue dependencies. If those features
are unavailable, use a task list in the map, put `Part of #<map>` in each child,
and record blockers as `Blocked by: #<number>`.

When authorized, claim a ready child by assigning it to the active developer and
record its result in the issue. Close it only with explicit user authority;
finishing local work alone does not authorize closure.
