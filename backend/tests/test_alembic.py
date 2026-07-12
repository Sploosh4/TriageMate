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
        """Verify Alembic reports 009 as the current head."""
        import subprocess
        import sys

        test_dir = Path(__file__).resolve().parent.parent  # points to backend/
        alembic_ini = test_dir / "alembic.ini"
        if not alembic_ini.exists():
            pytest.skip("Alembic config not available in this environment")

        result = subprocess.run(
            [sys.executable, "-m", "alembic", "current"],
            capture_output=True,
            text=True,
            cwd=str(test_dir),
        )
        assert result.returncode == 0
        assert "009" in result.stdout
