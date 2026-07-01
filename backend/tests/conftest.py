"""
Test configuration and fixtures for TriageMate.
"""

import os
import sys

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


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initialize and seed the test database if empty.

    This runs once per test session (before any tests).
    Uses the existing triagemate.db at the configured DB_PATH.
    """
    from database import init_db, get_db

    # Change to backend directory so SQLite path resolves correctly
    orig_cwd = os.getcwd()
    os.chdir(_backend_dir)

    init_db()

    # Seed if the database is empty
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as cnt FROM vulnerabilities")
    count = cursor.fetchone()["cnt"]
    conn.close()

    if count == 0:
        from seed_data import seed

        seed()

    os.chdir(orig_cwd)
    yield


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_records():
    """Delete any CVE-TEST-* records after the full test session.

    Runs after all tests complete to prevent test data from leaking into
    development or demonstration use of the database.
    """
    yield
    import sqlite3

    db_path = os.path.join(_backend_dir, "triagemate.db")
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM vulnerabilities WHERE vulnerability_id LIKE 'CVE-TEST-%'")
    conn.commit()
    conn.close()


@pytest.fixture
async def client():
    """Async HTTP client against the FastAPI app (no network needed)."""
    from main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
