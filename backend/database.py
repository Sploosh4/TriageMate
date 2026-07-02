import sqlite3

DB_PATH = "triagemate.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
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

            -- Substitution tracking
            epss_substituted BOOLEAN DEFAULT FALSE,
            epss_substituted_value REAL,
            epss_substitution_confidence REAL,
            epss_substitution_reason TEXT,

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
            audit_date TEXT
        );
    """)

    # Archive table for resolved/cleared vulnerabilities (Phase 4.1)
    conn.execute("""
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
            resolved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolution_reason TEXT DEFAULT 'demo_clear'
        );
    """)
    conn.commit()

    _migrate_add_column(conn, "vulnerabilities", "last_recheck_date", "TEXT")
    _migrate_add_column(
        conn, "vulnerabilities", "audit_selected", "BOOLEAN DEFAULT FALSE"
    )
    _migrate_add_column(conn, "vulnerabilities", "audit_result", "TEXT")
    _migrate_add_column(conn, "vulnerabilities", "audit_date", "TEXT")

    conn.commit()
    conn.close()


def _migrate_add_column(conn, table: str, column: str, col_type: str):
    """Add a column if it doesn't already exist (SQLite-safe migration)."""
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except sqlite3.OperationalError:
        pass
