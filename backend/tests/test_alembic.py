"""Tests for Alembic migration system."""

from pathlib import Path
import pytest
from database import get_db


class TestAlembicMigration:
    def test_pre_tier_features_column_exists(self):
        db = get_db()
        # Check vulnerabilities table
        row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='vulnerabilities'"
        ).fetchone()
        assert row is not None
        assert "pre_tier_features" in row[0]
        db.close()

    def test_epss_features_column_exists(self):
        db = get_db()
        row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='vulnerabilities'"
        ).fetchone()
        assert row is not None
        assert "epss_features" in row[0]
        db.close()

    def test_resolved_vulnerabilities_has_new_columns(self):
        db = get_db()
        row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='resolved_vulnerabilities'"
        ).fetchone()
        assert row is not None
        assert "pre_tier_features" in row[0]
        assert "epss_features" in row[0]
        db.close()

    def test_alembic_head_applied(self):
        """Verify Alembic reports 009 as the current head.

        Runs `alembic upgrade head` first so the test is self-contained
        regardless of whether migrations were already applied (CI) or not.
        """
        import subprocess
        import sys

        test_dir = Path(__file__).resolve().parent.parent  # points to backend/
        alembic_ini = test_dir / "alembic.ini"
        if not alembic_ini.exists():
            pytest.skip("Alembic config not available in this environment")

        # Ensure migrations are applied so alembic current returns a version.
        # This may fail (e.g., fresh checkout, no DB) — that's fine; alembic
        # current will still report the head from the migration files.
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            capture_output=True,
            text=True,
            cwd=str(test_dir),
        )

        result = subprocess.run(
            [sys.executable, "-m", "alembic", "current"],
            capture_output=True,
            text=True,
            cwd=str(test_dir),
        )
        assert result.returncode == 0, (
            f"alembic current failed: rc={result.returncode}, "
            f"stderr={result.stderr.strip()}"
        )
        assert "009" in result.stdout, (
            f"Expected '009' in alembic current output, "
            f"got stdout={result.stdout!r} stderr={result.stderr!r}. "
            f"Run 'alembic upgrade head' locally to apply migrations."
        )
