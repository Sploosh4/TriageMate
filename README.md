# TriageMate

TriageMate is a cybersecurity vulnerability-triage application for prioritising
findings using threat intelligence, asset context, security telemetry, network
context, and machine-learning signals.

## Current capabilities

- Staged triage pipeline: Pre-Tier, Tier 0, Tier 1, Tier 2, and human review
- NVD, OSV, CISA KEV, EPSS, MITRE, ExploitDB, Metasploit, and advisory enrichment
- WA government hostname and asset-context modelling
- Drift monitoring, scheduled retraining triggers, model registries, and rollback
- FastAPI backend with a lightweight browser frontend
- SQLite by default, with PostgreSQL available through `DATABASE_URL`
- Docker Compose deployment and GitHub Actions CI

## Quick start

Requirements: Python 3.11 or 3.12, and `just` (optional but recommended).

```bash
python -m venv backend/.venv
source backend/.venv/bin/activate
pip install -r backend/requirements.txt
pip install -r requirements-dev.txt

cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>.

On Windows, see [`docs/guides/WINDOWS_SETUP.md`](docs/guides/WINDOWS_SETUP.md).

## Verification

From the repository root:

```bash
just test       # Run the backend test suite (fuzz test skipped)
just test full=true  # Run the backend test suite, including fuzz testing
just lint       # Ruff checks and formatting verification
just verify-seeds
just gate       # Full quality gate with a 10-CVE calibration sample
just gate full=true  # Full quality gate with the full calibration audit + fuzz testing
```

The current score contract and project status are maintained in
[`docs/planning/ROADMAP.md`](docs/planning/ROADMAP.md). Start with
[`docs/INDEX.md`](docs/INDEX.md) when browsing the documentation.

## Configuration

Copy `.env.example` to `.env` and set only the integrations required for your
environment. Never commit `.env`, API keys, model artifacts, databases, or
local virtual environments.

## Repository status

This is a private, proprietary repository. See [`LICENSE`](LICENSE) for usage
terms.
