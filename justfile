# TriageMate justfile
# Run `just --list` to see all available commands.
#
# Adding a new command:
#   1. Add the recipe to the appropriate section below
#   2. If it takes arguments, use $1, $2, … or {{argument}} syntax
#   3. Run `just --list` to verify it appears correctly
#   4. Update `.opencode/skills/triage-toolbox/SKILL.md` if the command
#      changes the recommended workflow

# --- Variables ---
BACKEND := "backend"
PY := ".venv/bin/python"
PIP := ".venv/bin/pip"
RUFF := ".venv/bin/ruff"
PYTEST := ".venv/bin/pytest"
UVICORN := ".venv/bin/uvicorn"

# --- Dev Loop ---

# Run all tests with verbose output
test:
    cd {{BACKEND}} && {{PYTEST}} tests/ -v

# Run a specific test file (e.g., just test-file test_health)
test-file file:
    cd {{BACKEND}} && {{PYTEST}} tests/{{file}}.py -v

# Capture benchmark baseline
bench:
    cd {{BACKEND}} && {{PY}} -m pytest tests/test_benchmark.py --benchmark-save=baseline --benchmark-autosave

# Compare against saved baseline (fails on >=10% regression)
bench-check:
    cd {{BACKEND}} && {{PY}} -m pytest tests/test_benchmark.py --benchmark-compare=baseline --benchmark-compare-fail=min:10%

# Run Tier 2 unit tests with coverage (must be >= 70%)
verify-tier2:
    cd {{BACKEND}} && {{PY}} -m pytest tests/test_tier2.py -v --cov=pipeline.tier_2 --cov-report=term --cov-fail-under=70

# Lint check only (no changes)
lint:
    cd {{BACKEND}} && {{RUFF}} check . && {{RUFF}} format --check .

# Lint and auto-fix
lint-fix:
    cd {{BACKEND}} && {{RUFF}} check . --fix && {{RUFF}} format .

# Start FastAPI dev server with auto-reload
server:
    cd {{BACKEND}} && {{UVICORN}} main:app --reload --host 0.0.0.0 --port 8000

# Start FastAPI dev server with demo mode enabled
server-demo:
    cd {{BACKEND}} && DEMO_MODE=true {{UVICORN}} main:app --reload --host 0.0.0.0 --port 8000

# --- Docker ---

# Start postgres + app (with rebuild)
docker-up:
    docker compose up --build

# Start postgres + app in daemon mode
docker-up-d:
    docker compose up -d

# Stop all containers
docker-down:
    docker compose down

# Rebuild the app container only
docker-build:
    docker compose build

# --- Setup ---

# Install production + dev dependencies
install:
    cd {{BACKEND}} && {{PIP}} install -r requirements.txt && {{PIP}} install -r ../requirements-dev.txt

# Seed demo data into the database
seed-db:
    cd {{BACKEND}} && {{PY}} seed_data.py

# --- Data Pipeline ---

# Refresh threat intel caches (default: all)
# e.g., just refresh-caches nvd
refresh-caches source="":
    cd {{BACKEND}} && {{PY}} -m scripts.refresh_caches {{if source != "" {"--source " + source} else {""}}}

# Bulk fetch NVD corpus (200K+ CVEs)
fetch-corpus:
    cd {{BACKEND}} && {{PY}} -m scripts.fetch_nvd_corpus

# Resume NVD corpus fetch from checkpoint
fetch-corpus-resume:
    cd {{BACKEND}} && {{PY}} -m scripts.fetch_nvd_corpus --resume

# Build unified training NPZ from NVD corpus
build-corpus +args="":
    cd {{BACKEND}} && {{PY}} -m scripts.build_training_corpus {{args}}

# Build CWE hierarchy JSON (downloads MITRE XML first)
build-cwe:
    cd {{BACKEND}} && {{PY}} -m scripts.build_cwe_hierarchy --download

# Build vendor popularity index
build-vendor-index:
    cd {{BACKEND}} && {{PY}} -m scripts.build_vendor_index

# --- ML Training ---

# Full XGBoost training pipeline (gather + train)
train-xgboost +args="":
    cd {{BACKEND}} && {{PY}} -m ml.train_xgboost {{args}}

# Train Pre-Tier RandomForest classifier
train-pretier:
    cd {{BACKEND}} && {{PY}} -m ml.train_pre_tier

# Train EPSS substitution model v3
train-epss:
    cd {{BACKEND}} && {{PY}} -m ml.train_epss_v3

# Train EPSS substitution model v4 (sector-aware)
train-epss-v4:
    cd {{BACKEND}} && {{PY}} -m ml.train_epss_v4

# Retrain all ML models from scratch (synthetic data → pre-tier → EPSS v4)
retrain-all:
    @echo "=== Generating synthetic data ==="
    cd {{BACKEND}} && {{PY}} -m ml.generate_synthetic_data_v2
    cd {{BACKEND}} && {{PY}} -m ml.generate_synthetic_findings
    cd {{BACKEND}} && {{PY}} -m scripts.load_research_refs
    @echo "=== Validating synthetic data ==="
    cd {{BACKEND}} && {{PY}} -m scripts.validate_synthetic_data --table synthetic_assets
    @echo "=== Training Pre-Tier model ==="
    cd {{BACKEND}} && {{PY}} -m ml.train_pre_tier --from-db
    @echo "=== Training EPSS v4 model ==="
    cd {{BACKEND}} && {{PY}} -m ml.train_epss_v4
    @echo "=== Done ==="

# Fetch EPSS training data
fetch-epss-data:
    cd {{BACKEND}} && {{PY}} -m ml.fetch_epss_data

# Generate supplemental hostnames for Pre-Tier training  # DEPRECATED — use `just generate-synthetic-data` instead
generate-hostnames:
    cd {{BACKEND}} && {{PY}} -m ml.generate_supplemental_hostnames  # DEPRECATED

# Ingest documents into LanceDB vector store
ingest-docs:
    cd {{BACKEND}} && {{PY}} -m ml.ingest_docs

# --- Analysis ---

# ML calibration audit
audit-calibration:
    cd {{BACKEND}} && {{PY}} -m analysis.calibration_audit

# EPSS substitution accuracy evaluation
audit-epss:
    cd {{BACKEND}} && {{PY}} -m analysis.epss_eval

# Feature vector contract compliance check
audit-features:
    cd {{BACKEND}} && {{PY}} -m analysis.feature_parity_check

# Data schema conversion validation
audit-schema:
    cd {{BACKEND}} && {{PY}} -m analysis.validate_conversion

# Run ML drift tests and endpoint check
verify-drift:
    cd {{BACKEND}} && {{PY}} -m pytest tests/test_drift_ml.py -v
    @echo "--- Drift endpoint check ---"
    curl -s http://localhost:8000/api/drift/ml | python3 -m json.tool

# Run all audits sequentially
audit-all: audit-calibration audit-epss audit-features audit-schema
    @echo "All audits complete."

# Full stress test with real LLM API calls
stress-test:
    @echo "=== TriageMate Stress Test ==="
    @echo "Starting stack..."
    docker compose up -d --wait
    @echo "Waiting for healthy..."
    @for i in 1 2 3 4 5 6 7 8 9 10; do \
        curl -sf http://localhost:8000/api/health > /dev/null && break; \
        sleep 2; \
    done
    @echo "Running locust (60s)..."
    cd {{BACKEND}} && STRESS_RUN_ID=$(date +%Y-%m-%d-%H%M%S) \
        .venv/bin/locust -f tests/load/locustfile.py --headless \
        -u 10 -r 2 -t 60s --host http://localhost:8000
    @echo "Generating report..."
    cd {{BACKEND}} && {{PY}} scripts/stress_report.py reports/stress/$(ls -t reports/stress/ | head -1 | sed 's/.db//')
    @echo "=== Done ==="

# Stress test without LLM (no API cost)
stress-test-no-llm:
    @echo "=== TriageMate Stress Test (no LLM) ==="
    TRIAGEMATE_LLM_API_KEY="" docker compose up -d --wait
    @echo "Waiting for healthy..."
    @for i in 1 2 3 4 5 6 7 8 9 10; do \
        curl -sf http://localhost:8000/api/health > /dev/null && break; \
        sleep 2; \
    done
    @echo "Running locust (60s)..."
    cd {{BACKEND}} && STRESS_RUN_ID=$(date +%Y-%m-%d-%H%M%S) \
        TRIAGEMATE_LLM_API_KEY="" \
        .venv/bin/locust -f tests/load/locustfile.py --headless \
        -u 10 -r 2 -t 60s --host http://localhost:8000
    @echo "Generating report..."
    cd {{BACKEND}} && {{PY}} scripts/stress_report.py reports/stress/$(ls -t reports/stress/ | head -1 | sed 's/.db//')
    @echo "=== Done ==="

# --- Graphify (sibling project) ---

# Regenerate graphify knowledge artifacts (writes to graphify_output/)
graphify:
    cd ../../graphify && python3 generators/file_tree.py && \
    python3 generators/api_deps.py && \
    python3 generators/knowledge_graph.py && \
    python3 generators/ml_inventory.py && \
    python3 generators/feature_parity.py

# --- Database ---

# Open SQLite shell on the project database
db-shell:
    sqlite3 {{BACKEND}}/triagemate.db

# Show vulnerability count
db-count:
    sqlite3 {{BACKEND}}/triagemate.db "SELECT COUNT(*) FROM vulnerabilities;"

# Show database schema
db-schema:
    sqlite3 {{BACKEND}}/triagemate.db ".schema"

# --- Full Sprint Gate ---

# Verify seed data scores match canonical contract
verify-seeds:
	cd {{BACKEND}} && {{PY}} -m scripts.verify_seed_scores

# Run full sprint quality gate: lint → test → verify-seeds → graphify → audit-all
gate: lint test verify-seeds graphify audit-all
    @echo "============================================"
    @echo "Sprint quality gate passed."
    @echo "============================================"
