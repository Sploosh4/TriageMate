---
name: devops-engineering
description: Docker, docker-compose, CI/CD, environment variables, database migration, deployment architecture, infrastructure. Use when editing Dockerfile, docker-compose.yml, .github/workflows, or requirements files.
---

# TriageMate DevOps Engineering

## GitHub Workflow

Test `gh` access before relying on it. Use subagent operations when Level 4+ verified; otherwise route mutations through the commander.

## Infrastructure
- Docker compose: `db` (PostgreSQL 16-alpine) + `triagemate` (FastAPI app)
- SQLite for dev (no DB_URL set), PostgreSQL for production
- Multi-stage Dockerfile: builder (torch + sentence-transformers) → runtime
- Volumes: `triagemate-data`, `pgdata`

## Environment Variables
All project-specific vars use `TRIAGEMATE_` prefix:
- `DATABASE_URL` — PostgreSQL connection string (unset = SQLite)
- `TRIAGEMATE_LLM_API_KEY`, `TRIAGEMATE_LLM_PROVIDER`, `TRIAGEMATE_LLM_MODEL`
- `TRIAGEMATE_CMDB_PROVIDER` (default: stub)
- `NVD_API_KEY` — NVD API 2.0 key
- `HF_HUB_OFFLINE=1` — disables HuggingFace downloads in container
- `DEMO_MODE=true` — enables demo endpoints

## Key Files
- `docker-compose.yml` — service definitions, healthchecks, env vars
- `Dockerfile` — multi-stage build with pre-cached SentenceTransformer model
- `.dockerignore` — build context exclusions
- `.pre-commit-config.yaml` — ruff check + format hooks
- `.github/workflows/ci.yml` — GitHub Actions: pytest + ruff on push/PR
- `backend/requirements.txt` — production dependencies
- `requirements-dev.txt` — dev dependencies (pytest, ruff, pre-commit)

## Conventions
- Docker changes must work with `docker compose up` from project root
- Database schema must be backward-compatible (SQLite is default)
- All new Python deps go into `backend/requirements.txt`
- Never commit secrets, `.env` files, or database files
