"""
Test configuration and fixtures for TriageMate.
Uses a temporary SQLite database to isolate tests from development data.
"""

import os
import sys
import tempfile

# Disable LLM API key before any app imports to prevent real API calls
# from Tier 2 semantic analysis during tests.
# Force-set (not setdefault) so it takes precedence over .env file and shell env.
os.environ["TRIAGEMATE_LLM_API_KEY"] = ""
os.environ["TRIAGEMATE_LLM_PROVIDER"] = "openai"

# Ensure the backend directory is on sys.path so imports work
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402


def _ensure_tier_1_features_column(db_path: str):
    """Add tier_1_features column if Alembic didn't apply it.

    Alembic migration 005 has a pre-existing conflict (column added by
    migration 003 already), causing Alembic to fail and fall back to
    inline DDL which uses CREATE TABLE IF NOT EXISTS. Since the tables
    already exist from the partial Alembic run, the column is missing.
    This function applies the column directly as a workaround.
    """
    import sqlite3

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT tier_1_features FROM vulnerabilities LIMIT 1")
        cursor.close()
        conn.close()
    except sqlite3.OperationalError:
        conn = sqlite3.connect(db_path)
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN tier_1_features TEXT")
        conn.commit()
        conn.close()


def _ensure_pretier_features_column(db_path: str):
    """Add pre_tier_features column if not already present.

    This mirrors the ALTER TABLE logic in database.py for SQLite.
    """
    import sqlite3

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT pre_tier_features FROM vulnerabilities LIMIT 1")
        cursor.close()
        conn.close()
    except sqlite3.OperationalError:
        conn = sqlite3.connect(db_path)
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN pre_tier_features TEXT")
        conn.execute(
            "ALTER TABLE resolved_vulnerabilities ADD COLUMN pre_tier_features TEXT"
        )
        conn.commit()
        conn.close()


def _ensure_epss_features_column(db_path: str):
    """Add epss_features column if not already present.

    This mirrors the ALTER TABLE logic in database.py for SQLite.
    """
    import sqlite3

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT epss_features FROM vulnerabilities LIMIT 1")
        cursor.close()
        conn.close()
    except sqlite3.OperationalError:
        conn = sqlite3.connect(db_path)
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN epss_features TEXT")
        conn.execute(
            "ALTER TABLE resolved_vulnerabilities ADD COLUMN epss_features TEXT"
        )
        conn.commit()
        conn.close()


def _ensure_security_context_contribution_column(db_path: str):
    """Add security_context_contribution column if Alembic didn't apply it.

    Migration 008 added telemetry_json and network_context_json but not
    the security_context_contribution column. This ensures the column is
    present for seed_data insertion.
    """
    import sqlite3

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT security_context_contribution FROM vulnerabilities LIMIT 1"
        )
        cursor.close()
        conn.close()
    except sqlite3.OperationalError:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "ALTER TABLE vulnerabilities ADD COLUMN security_context_contribution INTEGER DEFAULT 0"
        )
        conn.execute(
            "ALTER TABLE resolved_vulnerabilities ADD COLUMN security_context_contribution INTEGER DEFAULT 0"
        )
        conn.commit()
        conn.close()


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initialize and seed a temporary test database.

    Overrides database.DB_PATH with a temp file to isolate tests
    from development data in triagemate.db.
    """
    import database
    from seed_data import seed

    _tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    _tmp_db.close()

    database.DB_PATH = _tmp_db.name

    database.init_db()
    _ensure_tier_1_features_column(database.DB_PATH)
    _ensure_pretier_features_column(database.DB_PATH)
    _ensure_epss_features_column(database.DB_PATH)
    _ensure_security_context_contribution_column(database.DB_PATH)
    seed()

    yield

    os.unlink(_tmp_db.name)


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_records():
    """Delete any CVE-TEST-* records after the full test session.

    Runs after all tests complete to prevent test data from leaking.
    """
    yield
    import sqlite3
    import database

    if not os.path.isfile(database.DB_PATH):
        return
    try:
        conn = sqlite3.connect(database.DB_PATH)
        conn.execute(
            "DELETE FROM vulnerabilities WHERE vulnerability_id LIKE 'CVE-TEST-%'"
        )
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        pass


@pytest.fixture
async def client():
    """Async HTTP client against the FastAPI app (no network needed)."""
    from main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def isolated_registry(monkeypatch, tmp_path):
    """Redirect all model registry paths to a temp copy for test isolation.

    Copies the real ``model_registry.json`` to a ``tmp_path``-backed location
    and patches ``routers.models.REGISTRY_PATH``, ``scheduler.XGBOOST_REGISTRY``,
    and ``ml.xgboost_predictor.REGISTRY_PATH`` so API calls and direct file
    access both use the isolated copy.
    """
    import shutil
    from pathlib import Path

    import routers.models
    import scheduler
    import ml.xgboost_predictor

    _backend_dir = Path(__file__).resolve().parent.parent
    real_reg = _backend_dir / "ml" / "model_registry.json"
    temp_reg = tmp_path / "model_registry.json"
    if real_reg.exists():
        shutil.copy2(str(real_reg), str(temp_reg))
    else:
        # Write a minimal empty registry so downstream code doesn't break
        temp_reg.write_text('{"active_version": null, "versions": []}')

    monkeypatch.setattr(routers.models, "REGISTRY_PATH", temp_reg)
    monkeypatch.setattr(scheduler, "XGBOOST_REGISTRY", temp_reg)
    monkeypatch.setattr(ml.xgboost_predictor, "REGISTRY_PATH", temp_reg)

    return temp_reg
