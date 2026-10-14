# Contributing to TriageMate

Start with [README](README.md), [project scope](docs/planning/PIVOT_SCOPE.md) and [retained standards](docs/architecture/REFACTOR_STANDARDS.md). The supported application deployment is Docker Compose with one PostgreSQL service and one FastAPI/React service. Python services live under `app/services/`; the frontend contains ordinary React screens. Do not add another rendering framework or restore notebook/native launchers.

## Install contributor tools

Use Python 3.12, Node 22 and PostgreSQL 16 test binaries on a Linux development environment. Docker is sufficient for application deployment and the isolated unit/container build gate. Host tools are optional contributor facilities.

```sh
uv sync --frozen --no-default-groups --group ci
npm --prefix ui-engine ci
docker build --target checks -t triagemate-checks .
docker run --rm triagemate-checks
```

The CI group installs testing, formatting and typing tools. The dev group adds pre-commit; application contributors do not need Jupyter, notebook collaboration or a patched vendor wheel. The optional root Playwright MCP package is agent tooling, not an application or browser-test prerequisite.

## Test the relevant behavior

Keep positive and refusal/cancellation/corruption cases when simplifying code. Run shared-target database suites sequentially. Never select an operator's retained database, application volume or private source bundles as test fixtures.

```sh
uv run --frozen --no-default-groups --group ci python -m pytest app/tests/test_api.py app/tests/test_notifications.py scripts/test_browser_checks.py -q
uv run --frozen --no-default-groups --group ci python scripts/check_conventions.py
npm --prefix ui-engine run build
npm --prefix ui-engine run test:notices
uv run --frozen --no-default-groups --group ci python scripts/check_secret_patterns.py
git diff --check
```

Database integration needs an explicitly isolated synthetic target via `TRIAGEMATE_DATABASE_TARGET`. Keep its credentials private. `ui-engine/postgres/` and `standalone/evidence_pipeline/test_bootstrap.py` provide synthetic test facilities; they are not application launchers. Tests requiring native PostgreSQL 16 create isolated clusters or use the selected synthetic target. SQL parsing needs a prepared artifact selected by absolute `TRIAGEMATE_PG_PARSER_LIBRARY`; the contributor fallback is `ui-engine/work/parser/libpg_query.so`. Build it explicitly with `python ui-engine/scripts/build_parser.py --allow-downloads`, or supply the verified source archive with `--source-archive`. Tests do not download it implicitly.

With the compiled frontend, a prepared synthetic database and Playwright Chromium installed, run `python -m scripts.browser_checks`. This helper verifies the synthetic/runner schema profile, starts an owned FastAPI server on a temporary loopback port and private state directory, runs the five browser tests, then verifies server drain. It does not use the application's port 5190 or an operator collection configuration. The optional offline native harness remains a contributor test tool while database/retained-profile standards are under discussion; container CI is the supported release build path.

## Prepare a release

Build from a fresh source checkout with no local `.env`, ignored private data, dependencies or generated assets. Confirm container health, reader authority, cancellation, notifications, classifications, collection controls and persistence after container recreation. Keep collection Off until configured source collection is separately validated. Retain locked dependency/image provenance and the [frontend](docs/ui/engine/FrontendThirdPartyNotices.md) and [parser](docs/ui/engine/ParserThirdPartyNotices.md) notices in distributed artifacts.

Use a Git clone/checkout for the database baseline and retained companion: `.gitattributes` restores their required CRLF reference representation and preserves recorded CSV bytes. GitHub source ZIP/tar archives contain Git blob bytes without checkout conversion, so they are not an equivalent database build input. Validate a separately prepared source archive against the same immutable reference hashes before using or publishing it; do not rewrite reference hashes to accept a different representation.

Before public publication, audit Git history and source/data licenses as well as the current source tree. Passing a current secret-pattern check is not a claim that every historical commit or credential type was inspected. Repository visibility, pushes, releases and external deployment require separate authorization. Authentication/TLS and multi-user authorization must be decided before exposing the local configuration beyond loopback.

## Licensing contributions

Current first-party TriageMate contributions are submitted under `GPL-3.0-only`. Identify adapted third-party material and preserve its copyright, notices and compatible original license. Existing valid permissive grants can permit inclusion without obtaining a new grant; unknown or incompatible rights require resolution. See [licensing and redistribution](docs/architecture/licensing.md).
