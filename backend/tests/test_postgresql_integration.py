"""PostgreSQL integration smoke test.

Requires DATABASE_URL to point to a running PostgreSQL instance.
Marked @pytest.mark.integration so it can be skipped in the default gate.
"""

import os
import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.getenv("DATABASE_URL", "").startswith("postgresql://"),
        reason="DATABASE_URL not set to a PostgreSQL URL",
    ),
]


class TestPostgreSQLIntegration:
    """Smoke tests for the PostgreSQL compatibility layer."""

    def test_connection_and_init(self):
        """Connect to PostgreSQL, init schema, verify tables exist."""
        from database import DatabaseManager

        dm = DatabaseManager()
        assert dm.using_postgres, "DatabaseManager should detect PostgreSQL URL"
        conn = dm.get_connection()
        try:
            dm.init_db()
            # Verify a table exists
            cur = conn.cursor()
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
            tables = [row[0] for row in cur.fetchall()]
            assert "vulnerabilities" in tables, (
                f"vulnerabilities table not found in: {tables}"
            )
        finally:
            conn.close()

    def test_named_parameter_insert_and_query(self):
        """Insert a row with named parameters, then query it back."""
        from database import DatabaseManager

        dm = DatabaseManager()
        dm.init_db()
        conn = dm.get_connection()
        try:
            # Use named parameters for INSERT (as seed_data.py does)
            conn.execute(
                "INSERT INTO vulnerabilities "
                "(vulnerability_id, hostname, cvss_score, priority_score, risk_band) "
                "VALUES (:vuln_id, :host, :cvss, :score, :band)",
                {
                    "vuln_id": "CVE-PG-TEST-0001",
                    "host": "pg-test-host.wa.gov.au",
                    "cvss": 5.0,
                    "score": 50,
                    "band": "medium",
                },
            )
            conn.commit()

            # Query with positional parameters
            cur = conn.cursor()
            cur.execute(
                "SELECT vulnerability_id, hostname, priority_score "
                "FROM vulnerabilities WHERE vulnerability_id = ?",
                ("CVE-PG-TEST-0001",),
            )
            row = cur.fetchone()
            assert row is not None
            assert row["vulnerability_id"] == "CVE-PG-TEST-0001"
            assert row["hostname"] == "pg-test-host.wa.gov.au"
            assert row["priority_score"] == 50

            # Clean up
            conn.execute(
                "DELETE FROM vulnerabilities WHERE vulnerability_id = ?",
                ("CVE-PG-TEST-0001",),
            )
            conn.commit()
        finally:
            conn.close()

    def test_positional_parameter_query(self):
        """Query with positional ? parameters."""
        from database import DatabaseManager

        dm = DatabaseManager()
        conn = dm.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 AS val UNION ALL SELECT 2 AS val WHERE ? = ?",
                (1, 1),
            )
            rows = cur.fetchall()
            assert len(rows) >= 1
        finally:
            conn.close()

    def test_postgres_cast_syntax(self):
        """Verify ::jsonb cast works through the wrapper."""
        from database import DatabaseManager

        dm = DatabaseManager()
        conn = dm.get_connection()
        try:
            # ::jsonb is a PostgreSQL-specific cast
            cur = conn.cursor()
            cur.execute("SELECT '{}'::jsonb AS payload")
            row = cur.fetchone()
            assert row is not None
            assert row["payload"] == {}
        finally:
            conn.close()
