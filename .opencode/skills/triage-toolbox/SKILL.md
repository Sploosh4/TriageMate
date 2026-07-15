---
name: triage-toolbox
description: Project-level CLI commands, justfile, Docker, dev server, testing, linting. Use when running the dev server, building Docker, running tests, linting, or asking "what commands are available" in TriageMate.
---

# TriageMate Project Toolbox

## GitHub Workflow

Follow `github-basics`: only the user creates the task workspace through OpenCode; use its existing shared worktree and branch, and never create or switch workspaces, worktrees, or branches or use a manual/CLI fallback. Implementation agents report the workspace path, branch, SHA, and test evidence to the Commander; `git-steward` owns role-authorized Git/GitHub publishing actions, and only exact authority permits merge, deletion, closure, or a direct push to `main`.

**Primary interface: `just`** (34 recipes). Run `just --list` from the project root to see all available commands. The justfile lives at `./justfile`.

## Dev Loop (via just)

```bash
just test                    # complete pytest suite (fuzz test skipped)
TRIAGEMATE_RUN_FUZZ=1 just test  # include the opt-in fuzz test
just test-file test_health   # run specific test file
just lint                    # ruff check + format check
just lint-fix                # ruff auto-fix + format
just server                  # uvicorn --reload on :8000
just server-demo             # server with DEMO_MODE=true
```

## Docker (via just)

```bash
just docker-up               # docker compose up --build
just docker-up-d             # daemon mode
just docker-down             # stop and remove
just docker-build            # rebuild only
```

## Setup (via just)

```bash
just install                 # pip install requirements + dev
just seed-db                 # python seed_data.py
```

## Data Pipeline (via just)

```bash
just refresh-caches          # refresh all caches
just refresh-caches nvd      # NVD cache only
just fetch-corpus            # bulk NVD fetch
just fetch-corpus-resume     # resume from checkpoint
just build-corpus            # build training NPZ
just build-corpus "--limit 1000 --skip-sbert"  # with args
just build-cwe               # build CWE hierarchy JSON
just build-vendor-index      # build vendor popularity index
```

## ML Training (via just)

**Training is human-authorized only.** Do not run a model-changing command without explicit user approval. Before Tier-1 XGBoost `--train`, the required Gate A/Gate B evidence in `docs/reference/ml-retraining-gate.md` must be reviewed; other model-training workflows still require an approved, model-appropriate evaluation plan. Long gathers/training runs are performed by the user when they choose.

```bash
just train-xgboost --train   # Tier-1 XGBoost train only — requires Gate B authorization
just train-xgboost --gather  # gather only
just train-pretier           # pre-tier RF classifier
just train-epss              # EPSS substitution v3
just fetch-epss-data         # fetch EPSS training data
just generate-hostnames      # supplemental hostnames for pre-tier (legacy)
just train-epss-v4           # EPSS substitution v4 (sector-aware)
just retrain-all             # retrain Pre-Tier + EPSS v4 (not Tier-1 XGBoost)
just ingest-docs             # LanceDB vector store ingestion
```

## Analysis / Audit (via just)

```bash
just audit-calibration       # ML calibration audit
just audit-epss              # EPSS substitution evaluation
just audit-features          # feature vector contract check
just audit-schema            # data schema validation
just audit-all               # run all four audits in sequence
```

## Full Sprint Quality Gate

```bash
just gate                    # full gate with a 10-CVE calibration sample
TRIAGEMATE_FULL=true just gate  # full gate, including calibration audit + fuzz test
```

## GitHub Actions verification (self-hosted VM)

Use after local checks and an authorized push or PR update. These commands
verify the repository workflow on `triagemate-vm`; they do not mutate the VM.

```bash
# Read-only runner health check
bash .opencode/skills/triagemate-runner-ops/scripts/runner-doctor.sh

# Wait for the exact PR's CI result
gh pr checks <pr-number> --watch

# Inspect recent workflow runs when a PR number is unavailable
gh run list --workflow "TriageMate CI" --limit 10
```

The expected workflow selector is
`[self-hosted, Linux, X64, triagemate]`. A manual command over
`triagemate-runner ssh` is useful for diagnosis only; it is not CI evidence.
For offline/queued runner recovery, load `triagemate-runner-ops`.

## Database (via just)

```bash
just db-shell                # open SQLite shell
just db-count                # vulnerability count
just db-schema               # show schema
```

## Raw Commands (Fallback)

If just is unavailable, all commands run from `backend/`:

```bash
cd backend && pytest tests/ -v
cd backend && ruff check . && ruff format --check .
cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000
cd backend && python seed_data.py
cd backend && python -m scripts.refresh_caches [--source nvd|kev|epss]
cd backend && python -m ml.train_xgboost [--gather|--train]
cd backend && python -m analysis.calibration_audit
# ... etc — full listing in justfile
```

## Environment Variables

Copy `.env.example` to `.env` and configure:
- `DATABASE_URL` — PostgreSQL URL (unset = SQLite)
- `TRIAGEMATE_LLM_API_KEY` — LLM provider key (Tier 2)
- `NVD_API_KEY` — NVD API 2.0 key (Tier 1 enrichment)
- `DEMO_MODE=true` — enable demo endpoints
- `TRIAGEMATE_ADMIN_USER` / `TRIAGEMATE_ADMIN_PASS` — enable auth
- `TRIAGEMATE_JWT_SECRET` — JWT signing key

## Adding a New just Command

1. Open `./justfile` and add a recipe under the appropriate section
2. Run `just --list` to verify it appears
3. Update this skill if the new command changes any recommended workflow
