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
