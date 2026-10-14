# TriageMate

TriageMate is a GPL-3.0-only application for self-hosted vulnerability and device evidence analysis. It presents source observations, public CVE information, CVSS, EPSS and CISA KEV without inventing missing facts or a custom combined risk score. It is in development and is not deployed to users.

The application runs in two containers: PostgreSQL 16 stores evidence in a persistent named volume, and FastAPI serves the compiled React interface and the existing input pipeline. Fixed React screens and a read-only SQL explorer replace the custom Markdown page engine. Repository Markdown is documentation, not executable application pages.

## Run locally

Install Docker Desktop with Linux containers and Docker Compose v2. From this checkout on Windows:

```powershell
scripts\setup-containers.cmd
```

The helper creates an ignored `.env` with a random database owner password if absent, then builds and starts the two containers. Open [TriageMate](http://127.0.0.1:5190). Initial image builds need internet access to obtain pinned dependencies and source artifacts.

For other hosts, copy `.env.example` to `.env`, set `TRIAGEMATE_DB_OWNER_PASSWORD` to a unique random value of at least 32 characters, and run:

```sh
docker compose up -d --build --wait
```

The application port binds to `127.0.0.1`; PostgreSQL has no published host port. This setup targets one user on this computer. Session and request-origin guards are implemented, but remote identity authentication, TLS and multi-user authorization remain design decisions. Do not expose this configuration externally as a production service.

## Operate and preserve data

```sh
docker compose ps
docker compose logs --tail=100 app db
docker compose stop
docker compose up -d --wait
```

Stopping or recreating containers preserves the `database` and `application` named volumes. `docker compose down` also preserves them. **`docker compose down -v` deletes stored database evidence and application state.** A volume is persistent storage, not a backup; see the [container guide](docs/guides/CONTAINERS.md).

## Development and verification

See [CONTRIBUTING](CONTRIBUTING.md) for dependency setup, isolated targets, the owned browser-test server and release preparation.

Runtime deployment uses containers; host Python and Node commands below are contributor checks rather than startup instructions. Use isolated synthetic test databases. Database suites install fixtures and exercise authority failures and must not target an operator's evidence database. Run shared-target PostgreSQL suites sequentially.

The applicable gate includes Python behavior tests, SQL parser/read-only checks, frontend lint/type/build and browser checks, and actual container health, loopback binding, restart/persistence and failure-path checks. Existing schema fingerprint, authority and migration tests remain required while database standards are under discussion.

```sh
python -m pytest app backend/tests standalone/evidence_pipeline standalone/operations standalone/windows_inventory -q
python -m unittest discover -s ui-engine/postgres -p 'test_*.py'
python -m pytest ui-engine/postgres/epss -q
python -m ruff check app backend standalone
python -m ruff format --check app backend standalone
python scripts/check_conventions.py
npm --prefix ui-engine run build
npm --prefix ui-engine test -- --workers=1
python scripts/check_secret_patterns.py
git diff --check
```

Checks require dependencies pinned in `uv.lock` and `ui-engine/package-lock.json`, compatible Chromium for Playwright and synthetic database/parser prerequisites. Install contributor Python dependencies with `uv sync --frozen --no-default-groups --group ci`; use the `dev` group only for pre-commit hooks. Jupyter and a patched notebook dependency are no longer required. `ui-engine/postgres/` and the optional offline native CI harness are synthetic test facilities, not application deployment paths. Report missing tools, unavailable checks and evidence limits. Container definitions use immutable base-image references; dependency updates need provenance and applicable regression checks.

## Code and documentation

- `app/`: FastAPI routes, container bootstrap and packaged SQL/classification/operations services, with transport and service tests under `app/tests/`.
- `ui-engine/src/`: React screens and SQL explorer.
- `backend/configuration/` and `backend/database/`: shared configuration, role-specific connections and retained schema lifecycle.
- `backend/microsoft_evidence/`: Microsoft source contracts and transport.
- `standalone/evidence_pipeline/`: collection, parsing, assessment, provenance and persistence.
- `standalone/operations/`: scheduling and durable collection state.
- `standalone/windows_inventory/`: read-only Windows inventory contracts; the Linux container cannot automatically inspect a remote registry.

Start with the [documentation index](docs/INDEX.md), [standards discussion](docs/architecture/REFACTOR_STANDARDS.md), [Microsoft tool research](docs/research/MICROSOFT_COLLECTORS.md) and [public feed research](docs/research/PUBLIC_FEEDS.md). GPL-3.0-only covers current first-party TriageMate code; libraries and input data retain their own licenses. See [licensing policy](docs/architecture/licensing.md), [LICENSE](LICENSE), [NOTICE](NOTICE), [SQL parser notices](docs/ui/engine/ParserThirdPartyNotices.md) and [bundled frontend notices](docs/ui/engine/FrontendThirdPartyNotices.md). Each clean frontend build validates and includes `/third-party-notices.txt`. Local open-source preparation does not change repository visibility.
