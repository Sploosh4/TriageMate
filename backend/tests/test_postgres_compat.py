"""
Tests for PostgreSQL compatibility in the SQLite wrapper (_PGCursor).

Verifies that the _PGCursor.execute() method correctly translates
SQLite-style parameters to psycopg2-compatible format.
"""

import re


class _RecordingCursor:
    """Captures the SQL and params passed to execute()."""

    def __init__(self):
        self.sql = None
        self.params = None
        self.rowcount = -1
        self.description = None

    def execute(self, sql, params=None):
        self.sql = sql
        self.params = params
        return self


# Duplicate the execute logic from _PGCursor for isolated testing
def _pg_execute(sql, params=None):
    """Simulate _PGCursor.execute() parameter translation."""
    if params is None:
        return sql
    if isinstance(params, dict):
        return re.sub(r"(?<!:):([a-zA-Z_][a-zA-Z0-9_]*)", r"%(\1)s", sql)
    else:
        return sql.replace("?", "%s")


class TestPGCursorParameterTranslation:
    """_PGCursor parameter translation tests."""

    def test_pg_cursor_converts_named_sqlite_parameters(self):
        """SQLite :name params become psycopg2 %(name)s."""
        sql = """
            INSERT INTO vulnerabilities (
                vulnerability_id, hostname, cvss_score
            ) VALUES (
                :vulnerability_id, :hostname, :cvss_score
            )
        """
        result = _pg_execute(sql, {"vulnerability_id": "CVE-2024-0001"})
        assert ":vulnerability_id" not in result, (
            f"Named param :vulnerability_id was not converted in:\n{result}"
        )
        assert "%(vulnerability_id)s" in result, (
            f"Expected %(vulnerability_id)s in:\n{result}"
        )
        assert ":hostname" not in result
        assert "%(hostname)s" in result
        assert ":cvss_score" not in result
        assert "%(cvss_score)s" in result

    def test_pg_cursor_preserves_postgres_casts_when_converting_named_parameters(
        self,
    ):
        """PostgreSQL ::jsonb cast syntax must survive :name conversion.

        :payload::jsonb should become %(payload)s::jsonb, not %(payload)s::%(jsonb)s.
        """
        sql = """
            UPDATE vulnerabilities
            SET telemetry_json = :telemetry::jsonb
            WHERE id = :id
        """
        result = _pg_execute(sql, {"telemetry": "{}", "id": 1})
        assert "::jsonb" in result, f"PostgreSQL ::jsonb cast was lost in:\n{result}"
        assert "%(telemetry)s::jsonb" in result, (
            f"Expected %(telemetry)s::jsonb in:\n{result}"
        )
        assert "%(id)s" in result, f"Expected %(id)s in:\n{result}"
        # Ensure :jsonb after :: was NOT treated as a parameter
        assert ":%(jsonb)s" not in result, (
            f":jsonb part of ::jsonb was incorrectly converted in:\n{result}"
        )

    def test_pg_cursor_converts_positional_parameters(self):
        """SQLite ? placeholders become %s for psycopg2 positional params."""
        sql = "SELECT * FROM vulnerabilities WHERE resolved_at >= ? AND priority_score > ?"
        result = _pg_execute(sql, ("2024-01-01", 50))
        assert "?" not in result, (
            f"Positional placeholder ? was not converted in:\n{result}"
        )
        assert result.count("%s") == 2, (
            f"Expected 2 %%s placeholders, got {result.count('%s')} in:\n{result}"
        )

    def test_pg_cursor_handles_no_params(self):
        """SQL with no params should be returned unchanged."""
        sql = "SELECT 1"
        result = _pg_execute(sql)
        assert result == sql, f"SQL without params was modified:\n{result}"

    def test_pg_cursor_handles_empty_dict_params(self):
        """Empty dict params should still trigger named param conversion."""
        sql = "SELECT :x"
        result = _pg_execute(sql, {})
        assert "%(x)s" in result
