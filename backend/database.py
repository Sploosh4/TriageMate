"""
Database module for TriageMate.
Supports both SQLite (default/local) and PostgreSQL (production).

Controlled by the DATABASE_URL environment variable:
  - Unset or empty → SQLite (file: triagemate.db)
  - postgresql://user:pass@host:port/dbname → PostgreSQL via psycopg2

Usage:
    from database import get_db, init_db
    conn = get_db()
    conn.execute(...)
    conn.commit()
    conn.close()

All existing callers of get_db() work unchanged.
"""

import os
from pathlib import Path
import sqlite3
import logging

logger = logging.getLogger("triagemate.database")

# Default SQLite database path (can be overridden by tests)
DB_PATH = str(Path(__file__).resolve().parent / "triagemate.db")

# ---- Singleton instance ----
_instance = None

# ---------------------------------------------------------------------------
#  PostgreSQL compatibility layer
# ---------------------------------------------------------------------------

try:
    import psycopg2
    import psycopg2.extras

    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False


class _PGCompatRow:
    """Row that supports both dict-like (r['col']) and tuple-like (r[0]) access,
    and can be converted to dict via dict(r).  Mirrors sqlite3.Row behaviour."""

    __slots__ = ("_keys", "_values", "_key_index")

    def __init__(self, keys, values):
        self._keys = tuple(keys)
        self._values = tuple(values)
        self._key_index = {k: i for i, k in enumerate(self._keys)}

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self._values[key]
        if isinstance(key, str):
            return self._values[self._key_index[key]]
        raise TypeError(f"Row index must be int or str, not {type(key).__name__}")

    def __iter__(self):
        return iter(self._keys)

    def keys(self):
        return self._keys

    def values(self):
        return self._values

    def items(self):
        return zip(self._keys, self._values)

    def __len__(self):
        return len(self._values)

    def __contains__(self, key):
        if isinstance(key, str):
            return key in self._key_index
        return False

    def __repr__(self):
        return f"<{type(self).__name__} {dict(zip(self._keys, self._values))}>"


class _PGCursor:
    """Wraps a psycopg2 cursor so that fetchone/fetchall/__iter__ return
    _PGCompatRow objects (dict + tuple access)."""

    def __init__(self, cursor):
        self._cursor = cursor
        self.rowcount = 0
        self.description = cursor.description

    def execute(self, sql, params=None):
        # Convert ? placeholders (SQLite style) to %s (psycopg2 style)
        if params is not None:
            pg_sql = sql.replace("?", "%s")
            self._cursor.execute(pg_sql, params)
        else:
            self._cursor.execute(sql)
        self.rowcount = self._cursor.rowcount
        self.description = self._cursor.description
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        keys = [d[0] for d in self._cursor.description]
        return _PGCompatRow(keys, row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows:
            return []
        keys = [d[0] for d in self._cursor.description]
        return [_PGCompatRow(keys, r) for r in rows]

    def __iter__(self):
        keys = None
        for row in self._cursor:
            if keys is None:
                keys = [d[0] for d in self._cursor.description]
            yield _PGCompatRow(keys, row)

    @property
    def lastrowid(self):
        return self._cursor.lastrowid if self._cursor else None


class _PGConnection:
    """Wrapper around a psycopg2 connection that adds an ``execute()``
    shortcut method (like sqlite3.Connection) while preserving the
    standard ``cursor()``, ``commit()``, ``close()`` interface."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return _PGCursor(self._conn.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    # Context manager – delegates to psycopg2's native behaviour
    # (commit on success, rollback on exception).
    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._conn.__exit__(exc_type, exc_val, exc_tb)


# ---------------------------------------------------------------------------
#  DatabaseManager
# ---------------------------------------------------------------------------


class DatabaseManager:
    """Manages database connections for SQLite and PostgreSQL backends.

    Behaviour is controlled by the ``DATABASE_URL`` environment variable:
    unset / empty / anything other than ``postgresql://...`` → SQLite.
    """

    def __init__(self):
        self._db_url = os.getenv("DATABASE_URL", "").strip()
        self._is_postgres = self._db_url.startswith("postgresql://")

        if self._is_postgres and not _HAS_PSYCOPG2:
            raise ImportError(
                "DATABASE_URL is set to a PostgreSQL URL but psycopg2 is not "
                "installed.  Run: pip install psycopg2-binary"
            )

    @property
    def using_postgres(self):
        return self._is_postgres

    # ------------------------------------------------------------------
    #  Connection factory
    # ------------------------------------------------------------------

    def get_connection(self):
        """Return a database connection.

        SQLite connections have ``row_factory = sqlite3.Row`` set.
        PostgreSQL connections are wrapped in ``_PGConnection``
        (adds ``execute()`` shortcut + dict/tuple-compatible rows).

        Both flavours support the ``with conn:`` context manager.
        """
        if self._is_postgres:
            return self._get_pg_connection()
        return self._get_sqlite_connection()

    def _get_sqlite_connection(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _get_pg_connection(self):
        raw = psycopg2.connect(self._db_url)
        return _PGConnection(raw)

    # ------------------------------------------------------------------
    #  Alembic migrations
    # ------------------------------------------------------------------

    @staticmethod
    def run_migrations():
        """Run Alembic migrations if Alembic is available."""
        try:
            from alembic.config import Config
            from alembic import command
            import os as _os

            alembic_cfg = Config(
                _os.path.join(_os.path.dirname(__file__), "alembic.ini")
            )
            # Override DB URL with runtime path (supports test isolation via DB_PATH)
            _db_url = _os.getenv("DATABASE_URL", "").strip()
            if _db_url:
                alembic_cfg.set_main_option("sqlalchemy.url", _db_url)
            else:
                alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{DB_PATH}")
            command.upgrade(alembic_cfg, "head")
            return True
        except ImportError:
            return False
        except Exception as e:
            logging.warning(
                "Alembic migration failed: %s. Falling back to inline DDL.", e
            )
            return False

    # ------------------------------------------------------------------
    #  Schema initialisation
    # ------------------------------------------------------------------

    def init_db(self):
        """Create tables if they do not exist.  Uses SQL-dialect-aware DDL."""
        if self.run_migrations():
            return
        conn = self.get_connection()
        try:
            if self._is_postgres:
                self._init_db_pg(conn)
            else:
                self._init_db_sqlite(conn)
        finally:
            conn.close()

    # ---- SQLite schema -------------------------------------------------

    def _init_db_sqlite(self, conn):
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id TEXT NOT NULL,
                hostname TEXT NOT NULL,

                -- Tier 0 inputs
                cvss_score REAL NOT NULL,
                cvss_vector TEXT,
                cisa_kev BOOLEAN DEFAULT FALSE,
                epss_score REAL,

                -- Pre-Tier predictions
                mission_prevalence TEXT,
                mission_prevalence_conf REAL,
                public_wellbeing_impact TEXT,
                public_wellbeing_conf REAL,

                -- Tier 0 outputs
                tier_0_routing TEXT,
                tier_0_resolution TEXT,

                -- Tier 1 outputs
                tier_1_confidence REAL,
                tier_1_exploitation_prob REAL,
                tier_1_routing TEXT,

                -- Tier 2 outputs
                tier_2_text_conflict BOOLEAN DEFAULT FALSE,
                tier_2_conflict_note TEXT,
                tier_2_rag_result TEXT,
                tier_2_confidence REAL,
                tier_2_resolution_summary TEXT,

                -- Final scoring
                priority_score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,

                -- Dimensions
                cvss_contribution INTEGER,
                epss_contribution INTEGER,
                asset_criticality_contribution INTEGER,
                exposure_contribution INTEGER,
                patch_remediation_contribution INTEGER,
                ml_exploitation_contribution INTEGER DEFAULT 0,
                security_context_contribution INTEGER DEFAULT 0,

                -- Substitution tracking
                epss_substituted BOOLEAN DEFAULT FALSE,
                epss_substituted_value REAL,
                epss_substitution_confidence REAL,
                epss_substitution_reason TEXT,

                -- Analytics tracking
                analytics_view_count INTEGER DEFAULT 0,
                analytics_last_viewed TEXT,

                -- Asset context
                data_classification TEXT,
                network_zone TEXT,
                interface_type TEXT,
                patch_cycle TEXT,
                last_patch_date TEXT,
                last_scan_date TEXT,
                operating_system TEXT,
                role TEXT,
                business_owner TEXT,
                technical_owner TEXT,
                registered_applications TEXT,
                dependent_assets TEXT,
                service_account TEXT,

                -- Detection pipeline
                detection_tier TEXT,
                detection_reason TEXT,

                -- Full payloads (stored as JSON strings)
                scanner_output_raw TEXT,
                weakness_template_raw TEXT,
                advisory_ref_id TEXT,
                advisory_quote TEXT,
                investigation_notes TEXT,
                mitre_techniques_json TEXT,
                scoring_weights_json TEXT,
                asset_registry_json TEXT,
                summary_paragraphs_json TEXT,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                -- Operational cadence
                last_recheck_date TEXT,

                -- Background audit
                audit_selected BOOLEAN DEFAULT FALSE,
                audit_result TEXT,
                audit_date TEXT,

                -- Review queue
                flagged_for_review BOOLEAN DEFAULT FALSE,
                review_status TEXT,
                review_decision TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT,
                override_score INTEGER,
                override_band TEXT,

                -- ML drift monitoring
                tier_1_features TEXT,

                -- Pre-Tier drift monitoring (Sprint 18)
                pre_tier_features TEXT,

                -- EPSS drift monitoring (Sprint 18)
                epss_features TEXT,

                -- Security context (Sprint 17)
                telemetry_json TEXT,
                network_context_json TEXT,

                -- Prevent duplicate seed rows
                UNIQUE(vulnerability_id, hostname)
            )
        """)

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id TEXT NOT NULL,
                case_id INTEGER NOT NULL,
                analyst_decision TEXT NOT NULL,
                override_score INTEGER,
                override_band TEXT,
                notes TEXT,
                analyst_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS resolved_vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_id INTEGER,
                vulnerability_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                cvss_vector TEXT,
                cisa_kev BOOLEAN DEFAULT FALSE,
                epss_score REAL,
                mission_prevalence TEXT,
                mission_prevalence_conf REAL,
                public_wellbeing_impact TEXT,
                public_wellbeing_conf REAL,
                tier_0_routing TEXT,
                tier_0_resolution TEXT,
                tier_1_confidence REAL,
                tier_1_exploitation_prob REAL,
                tier_1_routing TEXT,
                tier_2_text_conflict BOOLEAN DEFAULT FALSE,
                tier_2_conflict_note TEXT,
                tier_2_rag_result TEXT,
                tier_2_confidence REAL,
                tier_2_resolution_summary TEXT,
                priority_score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,
                cvss_contribution INTEGER,
                epss_contribution INTEGER,
                asset_criticality_contribution INTEGER,
                exposure_contribution INTEGER,
                patch_remediation_contribution INTEGER,
                ml_exploitation_contribution INTEGER DEFAULT 0,
                security_context_contribution INTEGER DEFAULT 0,

                -- ML drift monitoring
                tier_1_features TEXT,

                -- Pre-Tier drift monitoring (Sprint 18)
                pre_tier_features TEXT,

                -- EPSS drift monitoring (Sprint 18)
                epss_features TEXT,

                -- Security context (Sprint 17)
                telemetry_json TEXT,
                network_context_json TEXT,

                epss_substituted BOOLEAN DEFAULT FALSE,
                epss_substituted_value REAL,
                epss_substitution_confidence REAL,
                epss_substitution_reason TEXT,
                data_classification TEXT,
                network_zone TEXT,
                interface_type TEXT,
                patch_cycle TEXT,
                last_patch_date TEXT,
                last_scan_date TEXT,
                operating_system TEXT,
                role TEXT,
                business_owner TEXT,
                technical_owner TEXT,
                registered_applications TEXT,
                dependent_assets TEXT,
                service_account TEXT,
                detection_tier TEXT,
                detection_reason TEXT,
                scanner_output_raw TEXT,
                weakness_template_raw TEXT,
                advisory_ref_id TEXT,
                advisory_quote TEXT,
                investigation_notes TEXT,
                mitre_techniques_json TEXT,
                scoring_weights_json TEXT,
                asset_registry_json TEXT,
                summary_paragraphs_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                last_recheck_date TEXT,
                audit_selected BOOLEAN DEFAULT FALSE,
                audit_result TEXT,
                audit_date TEXT,

                -- Review queue
                flagged_for_review BOOLEAN DEFAULT FALSE,
                review_status TEXT,
                review_decision TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT,
                override_score INTEGER,
                override_band TEXT,

                resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolution_reason TEXT DEFAULT 'demo_clear'
            )
        """)

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS synthetic_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL UNIQUE,
                ip TEXT DEFAULT '',
                agency TEXT NOT NULL,
                agency_domain TEXT DEFAULT '',
                system_name TEXT DEFAULT '',
                environment TEXT DEFAULT '',
                os_platform TEXT DEFAULT '',
                role TEXT DEFAULT '',
                network_zone TEXT DEFAULT '',
                is_internet_facing INTEGER DEFAULT 0,
                is_dc INTEGER DEFAULT 0,
                mission_prevalence TEXT NOT NULL,
                public_wellbeing_impact TEXT NOT NULL,
                confidence_mp REAL DEFAULT 0.0,
                confidence_wi REAL DEFAULT 0.0,
                in_holdout INTEGER DEFAULT 0,
                source_research_ref TEXT DEFAULT '',
                generated_at TEXT DEFAULT (datetime('now')),
                validation_status TEXT DEFAULT 'pending',
                validation_errors TEXT DEFAULT ''
            )
        """)

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS synthetic_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                cvss_score REAL DEFAULT 0.0,
                epss_score REAL DEFAULT 0.0,
                cisa_kev INTEGER DEFAULT 0,
                cwe_class TEXT DEFAULT '',
                sector TEXT DEFAULT '',
                agency TEXT NOT NULL,
                exploit_maturity INTEGER DEFAULT 0,
                has_public_poc INTEGER DEFAULT 0,
                vendor_patch_status INTEGER DEFAULT 0,
                source_research_ref TEXT DEFAULT '',
                generated_at TEXT DEFAULT (datetime('now'))
            )
        """)

        conn.executescript("""
            CREATE TABLE IF NOT EXISTS research_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ref_id TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                finding TEXT NOT NULL,
                source_url TEXT DEFAULT '',
                confidence TEXT DEFAULT 'assumed',
                notes TEXT DEFAULT ''
            )
        """)

        # Sprint 18: Pre-Tier drift monitoring — add column if not already present
        try:
            conn.execute(
                "ALTER TABLE vulnerabilities ADD COLUMN pre_tier_features TEXT"
            )
        except sqlite3.OperationalError:
            pass
        except Exception:
            logger.warning(
                "Unexpected error adding pre_tier_features to vulnerabilities",
                exc_info=True,
            )
        try:
            conn.execute(
                "ALTER TABLE resolved_vulnerabilities ADD COLUMN pre_tier_features TEXT"
            )
        except sqlite3.OperationalError:
            pass
        except Exception:
            logger.warning(
                "Unexpected error adding pre_tier_features to resolved_vulnerabilities",
                exc_info=True,
            )

        # Sprint 18: EPSS drift monitoring — add column if not already present
        try:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN epss_features TEXT")
        except sqlite3.OperationalError:
            pass
        except Exception:
            logger.warning(
                "Unexpected error adding epss_features to vulnerabilities",
                exc_info=True,
            )
        try:
            conn.execute(
                "ALTER TABLE resolved_vulnerabilities ADD COLUMN epss_features TEXT"
            )
        except sqlite3.OperationalError:
            pass
        except Exception:
            logger.warning(
                "Unexpected error adding epss_features to resolved_vulnerabilities",
                exc_info=True,
            )

        conn.commit()

    # ---- PostgreSQL schema ---------------------------------------------

    def _init_db_pg(self, conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                vulnerability_id TEXT NOT NULL,
                hostname TEXT NOT NULL,

                -- Tier 0 inputs
                cvss_score REAL NOT NULL,
                cvss_vector TEXT,
                cisa_kev BOOLEAN DEFAULT FALSE,
                epss_score REAL,

                -- Pre-Tier predictions
                mission_prevalence TEXT,
                mission_prevalence_conf REAL,
                public_wellbeing_impact TEXT,
                public_wellbeing_conf REAL,

                -- Tier 0 outputs
                tier_0_routing TEXT,
                tier_0_resolution TEXT,

                -- Tier 1 outputs
                tier_1_confidence REAL,
                tier_1_exploitation_prob REAL,
                tier_1_routing TEXT,

                -- Tier 2 outputs
                tier_2_text_conflict BOOLEAN DEFAULT FALSE,
                tier_2_conflict_note TEXT,
                tier_2_rag_result TEXT,
                tier_2_confidence REAL,
                tier_2_resolution_summary TEXT,

                -- Final scoring
                priority_score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,

                -- Dimensions
                cvss_contribution INTEGER,
                epss_contribution INTEGER,
                asset_criticality_contribution INTEGER,
                exposure_contribution INTEGER,
                patch_remediation_contribution INTEGER,
                ml_exploitation_contribution INTEGER DEFAULT 0,
                security_context_contribution INTEGER DEFAULT 0,

                -- Substitution tracking
                epss_substituted BOOLEAN DEFAULT FALSE,
                epss_substituted_value REAL,
                epss_substitution_confidence REAL,
                epss_substitution_reason TEXT,

                -- Analytics tracking
                analytics_view_count INTEGER DEFAULT 0,
                analytics_last_viewed TEXT,

                -- Asset context
                data_classification TEXT,
                network_zone TEXT,
                interface_type TEXT,
                patch_cycle TEXT,
                last_patch_date TEXT,
                last_scan_date TEXT,
                operating_system TEXT,
                role TEXT,
                business_owner TEXT,
                technical_owner TEXT,
                registered_applications TEXT,
                dependent_assets TEXT,
                service_account TEXT,

                -- Detection pipeline
                detection_tier TEXT,
                detection_reason TEXT,

                -- Full payloads (stored as JSON strings)
                scanner_output_raw TEXT,
                weakness_template_raw TEXT,
                advisory_ref_id TEXT,
                advisory_quote TEXT,
                investigation_notes TEXT,
                mitre_techniques_json TEXT,
                scoring_weights_json TEXT,
                asset_registry_json TEXT,
                summary_paragraphs_json TEXT,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                -- Operational cadence
                last_recheck_date TEXT,

                -- Background audit
                audit_selected BOOLEAN DEFAULT FALSE,
                audit_result TEXT,
                audit_date TEXT,

                -- Review queue
                flagged_for_review BOOLEAN DEFAULT FALSE,
                review_status TEXT,
                review_decision TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT,
                override_score INTEGER,
                override_band TEXT,

                -- ML drift monitoring
                tier_1_features TEXT,

                -- Pre-Tier drift monitoring (Sprint 18)
                pre_tier_features TEXT,

                -- EPSS drift monitoring (Sprint 18)
                epss_features TEXT,

                -- Security context (Sprint 17)
                telemetry_json TEXT,
                network_context_json TEXT,

                -- Prevent duplicate seed rows
                UNIQUE(vulnerability_id, hostname)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                vulnerability_id TEXT NOT NULL,
                case_id INTEGER NOT NULL,
                analyst_decision TEXT NOT NULL,
                override_score INTEGER,
                override_band TEXT,
                notes TEXT,
                analyst_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS resolved_vulnerabilities (
                id SERIAL PRIMARY KEY,
                original_id INTEGER,
                vulnerability_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                cvss_vector TEXT,
                cisa_kev BOOLEAN DEFAULT FALSE,
                epss_score REAL,
                mission_prevalence TEXT,
                mission_prevalence_conf REAL,
                public_wellbeing_impact TEXT,
                public_wellbeing_conf REAL,
                tier_0_routing TEXT,
                tier_0_resolution TEXT,
                tier_1_confidence REAL,
                tier_1_exploitation_prob REAL,
                tier_1_routing TEXT,
                tier_2_text_conflict BOOLEAN DEFAULT FALSE,
                tier_2_conflict_note TEXT,
                tier_2_rag_result TEXT,
                tier_2_confidence REAL,
                tier_2_resolution_summary TEXT,
                priority_score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,
                cvss_contribution INTEGER,
                epss_contribution INTEGER,
                asset_criticality_contribution INTEGER,
                exposure_contribution INTEGER,
                patch_remediation_contribution INTEGER,
                ml_exploitation_contribution INTEGER DEFAULT 0,
                security_context_contribution INTEGER DEFAULT 0,

                -- ML drift monitoring
                tier_1_features TEXT,

                -- Pre-Tier drift monitoring (Sprint 18)
                pre_tier_features TEXT,

                -- EPSS drift monitoring (Sprint 18)
                epss_features TEXT,

                -- Security context (Sprint 17)
                telemetry_json TEXT,
                network_context_json TEXT,
                epss_substituted BOOLEAN DEFAULT FALSE,
                epss_substituted_value REAL,
                epss_substitution_confidence REAL,
                epss_substitution_reason TEXT,
                data_classification TEXT,
                network_zone TEXT,
                interface_type TEXT,
                patch_cycle TEXT,
                last_patch_date TEXT,
                last_scan_date TEXT,
                operating_system TEXT,
                role TEXT,
                business_owner TEXT,
                technical_owner TEXT,
                registered_applications TEXT,
                dependent_assets TEXT,
                service_account TEXT,
                detection_tier TEXT,
                detection_reason TEXT,
                scanner_output_raw TEXT,
                weakness_template_raw TEXT,
                advisory_ref_id TEXT,
                advisory_quote TEXT,
                investigation_notes TEXT,
                mitre_techniques_json TEXT,
                scoring_weights_json TEXT,
                asset_registry_json TEXT,
                summary_paragraphs_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                last_recheck_date TEXT,
                audit_selected BOOLEAN DEFAULT FALSE,
                audit_result TEXT,
                audit_date TEXT,

                -- Review queue
                flagged_for_review BOOLEAN DEFAULT FALSE,
                review_status TEXT,
                review_decision TEXT,
                reviewed_by TEXT,
                reviewed_at TEXT,
                override_score INTEGER,
                override_band TEXT,

                resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolution_reason TEXT DEFAULT 'demo_clear'
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS synthetic_assets (
                id SERIAL PRIMARY KEY,
                hostname TEXT NOT NULL UNIQUE,
                ip TEXT DEFAULT '',
                agency TEXT NOT NULL,
                agency_domain TEXT DEFAULT '',
                system_name TEXT DEFAULT '',
                environment TEXT DEFAULT '',
                os_platform TEXT DEFAULT '',
                role TEXT DEFAULT '',
                network_zone TEXT DEFAULT '',
                is_internet_facing BOOLEAN DEFAULT FALSE,
                is_dc BOOLEAN DEFAULT FALSE,
                mission_prevalence TEXT NOT NULL,
                public_wellbeing_impact TEXT NOT NULL,
                confidence_mp REAL DEFAULT 0.0,
                confidence_wi REAL DEFAULT 0.0,
                in_holdout BOOLEAN DEFAULT FALSE,
                source_research_ref TEXT DEFAULT '',
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                validation_status TEXT DEFAULT 'pending',
                validation_errors TEXT DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS synthetic_findings (
                id SERIAL PRIMARY KEY,
                cve_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                cvss_score REAL DEFAULT 0.0,
                epss_score REAL DEFAULT 0.0,
                cisa_kev BOOLEAN DEFAULT FALSE,
                cwe_class TEXT DEFAULT '',
                sector TEXT DEFAULT '',
                agency TEXT NOT NULL,
                exploit_maturity INTEGER DEFAULT 0,
                has_public_poc BOOLEAN DEFAULT FALSE,
                vendor_patch_status BOOLEAN DEFAULT FALSE,
                source_research_ref TEXT DEFAULT '',
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS research_references (
                id SERIAL PRIMARY KEY,
                ref_id TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                finding TEXT NOT NULL,
                source_url TEXT DEFAULT '',
                confidence TEXT DEFAULT 'assumed',
                notes TEXT DEFAULT ''
            )
        """)

        # Sprint 18: Pre-Tier drift monitoring — add column if not already present
        conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='vulnerabilities' AND column_name='pre_tier_features'
                ) THEN
                    ALTER TABLE vulnerabilities ADD COLUMN pre_tier_features TEXT;
                END IF;
            END $$;
        """)
        conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='resolved_vulnerabilities' AND column_name='pre_tier_features'
                ) THEN
                    ALTER TABLE resolved_vulnerabilities ADD COLUMN pre_tier_features TEXT;
                END IF;
            END $$;
        """)

        # Sprint 18: EPSS drift monitoring — add column if not already present
        conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='vulnerabilities' AND column_name='epss_features'
                ) THEN
                    ALTER TABLE vulnerabilities ADD COLUMN epss_features TEXT;
                END IF;
            END $$;
        """)
        conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='resolved_vulnerabilities' AND column_name='epss_features'
                ) THEN
                    ALTER TABLE resolved_vulnerabilities ADD COLUMN epss_features TEXT;
                END IF;
            END $$;
        """)

        conn.commit()


# ---------------------------------------------------------------------------
#  Module-level convenience functions
# ---------------------------------------------------------------------------


def get_db():
    """Return a database connection.

    Behaviour depends on ``DATABASE_URL``:
      - unset / empty → SQLite (``DB_PATH``)
      - ``postgresql://...`` → PostgreSQL

    The returned connection supports ``conn.execute()``, ``conn.cursor()``,
    ``conn.commit()``, ``conn.close()``, and the ``with conn:`` context
    manager.
    """
    global _instance
    if _instance is None:
        _instance = DatabaseManager()
    return _instance.get_connection()


def init_db():
    """Create tables if they do not exist.

    Safe to call multiple times (uses ``CREATE TABLE IF NOT EXISTS``).
    """
    global _instance
    if _instance is None:
        _instance = DatabaseManager()
    _instance.init_db()
