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

# --- Dev Loop ---

# Run all tests with verbose output
test:
    cd {{BACKEND}} && pytest tests/ -v

# Run a specific test file (e.g., just test-file test_health)
test-file file:
    cd {{BACKEND}} && pytest tests/{{file}}.py -v

# Lint check only (no changes)
lint:
    cd {{BACKEND}} && ruff check . && ruff format --check .

# Lint and auto-fix
lint-fix:
    cd {{BACKEND}} && ruff check . --fix && ruff format .

# Start FastAPI dev server with auto-reload
server:
    cd {{BACKEND}} && uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Start FastAPI dev server with demo mode enabled
server-demo:
    cd {{BACKEND}} && DEMO_MODE=true uvicorn main:app --reload --host 0.0.0.0 --port 8000

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
    cd {{BACKEND}} && pip install -r requirements.txt && pip install -r ../requirements-dev.txt

# Seed demo data into the database
seed-db:
    cd {{BACKEND}} && python seed_data.py

# --- Data Pipeline ---

# Refresh threat intel caches (default: all)
# e.g., just refresh-caches nvd
refresh-caches source="":
    cd {{BACKEND}} && python -m scripts.refresh_caches {{if source != "" {"--source " + source} else {""}}}

# Bulk fetch NVD corpus (200K+ CVEs)
fetch-corpus:
    cd {{BACKEND}} && python -m scripts.fetch_nvd_corpus

# Resume NVD corpus fetch from checkpoint
fetch-corpus-resume:
    cd {{BACKEND}} && python -m scripts.fetch_nvd_corpus --resume

# Build unified training NPZ from NVD corpus
build-corpus +args="":
    cd {{BACKEND}} && python -m scripts.build_training_corpus {{args}}

# Build CWE hierarchy JSON (downloads MITRE XML first)
build-cwe:
    cd {{BACKEND}} && python -m scripts.build_cwe_hierarchy --download

# Build vendor popularity index
build-vendor-index:
    cd {{BACKEND}} && python -m scripts.build_vendor_index

# --- ML Training ---

# Full XGBoost training pipeline (gather + train)
train-xgboost +args="":
    cd {{BACKEND}} && python -m ml.train_xgboost {{args}}

# Train Pre-Tier RandomForest classifier
train-pretier:
    cd {{BACKEND}} && python -m ml.train_pre_tier

# Train EPSS substitution model v3
train-epss:
    cd {{BACKEND}} && python -m ml.train_epss_v3

# Fetch EPSS training data
fetch-epss-data:
    cd {{BACKEND}} && python -m ml.fetch_epss_data

# Generate supplemental hostnames for Pre-Tier training
generate-hostnames:
    cd {{BACKEND}} && python -m ml.generate_supplemental_hostnames

# Ingest documents into LanceDB vector store
ingest-docs:
    cd {{BACKEND}} && python -m ml.ingest_docs

# --- Analysis ---

# ML calibration audit
audit-calibration:
    cd {{BACKEND}} && python -m analysis.calibration_audit

# EPSS substitution accuracy evaluation
audit-epss:
    cd {{BACKEND}} && python -m analysis.epss_eval

# Feature vector contract compliance check
audit-features:
    cd {{BACKEND}} && python -m analysis.feature_parity_check

# Data schema conversion validation
audit-schema:
    cd {{BACKEND}} && python -m analysis.validate_conversion

# Run all audits sequentially
audit-all: audit-calibration audit-epss audit-features audit-schema
    @echo "All audits complete."

# --- Graphify (sibling project) ---

# Regenerate graphify knowledge artifacts (writes to graphify_output/)
graphify:
    cd ../../graphify && python3 generators/file_tree.py && \
    python3 generators/api_deps.py && \
    python3 generators/knowledge_graph.py && \
    python3 generators/ml_inventory.py

# --- Database ---

# Open SQLite shell on the project database
db-shell:
    sqlite3 triagemate.db

# Show vulnerability count
db-count:
    sqlite3 triagemate.db "SELECT COUNT(*) FROM vulnerabilities;"

# Show database schema
db-schema:
    sqlite3 triagemate.db ".schema"

# --- Full Sprint Gate ---

# Run full sprint quality gate: lint → test → audit-all
gate: lint test audit-all
    @echo "============================================"
    @echo "Sprint quality gate passed."
    @echo "============================================"
