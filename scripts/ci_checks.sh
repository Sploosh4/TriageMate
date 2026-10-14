#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
(
  cd backend
  python -m scripts.run_backend_tests tests/ -v --cov --cov-config=.coveragerc --cov-report=term-missing --cov-fail-under=30
)
python backend/scripts/run_backend_tests.py standalone -v
# Contributor-only full suite using an explicitly prepared synthetic target.
python -m pytest scripts/test_ci_*.py scripts/test_browser_checks.py ui-engine/scripts/test_build_parser.py -q
python -m unittest discover -s ui-engine/postgres -p 'test_*.py' -v
python -m pytest ui-engine/postgres/epss -q
python -m pytest app/tests -q
python scripts/check_conventions.py
npm --prefix ui-engine run build
python -m scripts.browser_checks
ruff check backend standalone
ruff format --check backend standalone
ruff check app ui-engine/scripts ui-engine/postgres scripts/ci_*.py scripts/test_ci_*.py
ruff format --check app ui-engine/scripts ui-engine/postgres scripts/ci_*.py scripts/test_ci_*.py
cd "$ROOT"
git diff --check
python scripts/check_secret_patterns.py
