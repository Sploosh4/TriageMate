"""Tests for Alembic migration system."""

from pathlib import Path
import subprocess
import sys
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
        """Verify Alembic reports the expected current head after upgrade.

        Runs `alembic upgrade head` first so the test is self-contained
        regardless of whether migrations were already applied (CI) or not.

        The expected head is read dynamically from the latest migration
        file in backend/alembic/versions/ so this test stays correct as
        new migrations are added.
        """
        test_dir = Path(__file__).resolve().parent.parent  # points to backend/
        alembic_ini = test_dir / "alembic.ini"
        if not alembic_ini.exists():
            pytest.skip("Alembic config not available in this environment")

        # Determine expected head from the latest migration file
        versions_dir = test_dir / "alembic" / "versions"
        migration_files = sorted(versions_dir.glob("[0-9][0-9][0-9]_*.py"))
        assert migration_files, f"No migration files found in {versions_dir}"

        # Parse the revision identifier from the last migration file
        last_migration = migration_files[-1].stem  # e.g. "012_fix_resolved_timestamps"
        expected_revision = last_migration.split("_")[0]  # e.g. "012"
        # Also check for a revision line inside the file
        import re

        content = migration_files[-1].read_text()
        rev_match = re.search(
            r'^revision\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE
        )
        if rev_match:
            expected_revision = rev_match.group(1)

        # Ensure migrations are applied. Use check=True so a failed upgrade
        # (e.g. SQLite-incompatible DDL) raises immediately.
        upgrade_result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            capture_output=True,
            text=True,
            cwd=str(test_dir),
        )
        assert upgrade_result.returncode == 0, (
            f"alembic upgrade head failed: rc={upgrade_result.returncode}\n"
            f"stdout={upgrade_result.stdout.strip()}\n"
            f"stderr={upgrade_result.stderr.strip()}"
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
        assert expected_revision in result.stdout, (
            f"Expected {expected_revision!r} in alembic current output, "
            f"got stdout={result.stdout!r} stderr={result.stderr!r}. "
            f"Run 'alembic upgrade head' locally to apply migrations."
        )
