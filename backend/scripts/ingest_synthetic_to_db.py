"""
Ingest synthetic data from a JSON file into the TriageMate database.

Usage:
    python -m scripts.ingest_synthetic_to_db data.json --table assets
    python -m scripts.ingest_synthetic_to_db data.json --table findings
    python -m scripts.ingest_synthetic_to_db data.json --table references

Tables:
    assets     -> synthetic_assets  (ON CONFLICT: skip on hostname)
    findings   -> synthetic_findings (simple INSERT, allow duplicates)
    references -> research_references (ON CONFLICT: skip on ref_id)
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from database import get_db, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.ingest_synthetic")


TABLE_CONFIG = {
    "assets": {
        "table": "synthetic_assets",
        "conflict_column": "hostname",
        "allow_duplicates": False,
    },
    "findings": {
        "table": "synthetic_findings",
        "conflict_column": None,
        "allow_duplicates": True,
    },
    "references": {
        "table": "research_references",
        "conflict_column": "ref_id",
        "allow_duplicates": False,
    },
}


def _column_names(table_name: str, data: list[dict]) -> list[str]:
    """Return the intersection of data keys with actual table columns,
    minus the auto-increment ``id`` column."""
    # Derive from the first record's keys
    if not data:
        return []
    # Known set of valid columns per table (excluding id)
    known = {
        "synthetic_assets": [
            "hostname",
            "ip",
            "agency",
            "agency_domain",
            "system_name",
            "environment",
            "os_platform",
            "role",
            "network_zone",
            "is_internet_facing",
            "is_dc",
            "in_holdout",
            "mission_prevalence",
            "public_wellbeing_impact",
            "confidence_mp",
            "confidence_wi",
            "source_research_ref",
            "generated_at",
            "validation_status",
            "validation_errors",
        ],
        "synthetic_findings": [
            "cve_id",
            "hostname",
            "cvss_score",
            "epss_score",
            "cisa_kev",
            "cwe_class",
            "sector",
            "agency",
            "exploit_maturity",
            "has_public_poc",
            "vendor_patch_status",
            "source_research_ref",
            "generated_at",
        ],
        "research_references": [
            "ref_id",
            "category",
            "finding",
            "source_url",
            "confidence",
            "notes",
        ],
    }
    cols = known.get(table_name, [])
    return [c for c in cols if c in data[0]]


def ingest_json(file_path: str, table_key: str) -> None:
    """Read JSON from *file_path* and insert into the corresponding table."""
    config = TABLE_CONFIG.get(table_key)
    if config is None:
        logger.error(
            "Unknown table key '%s'. Choose from: %s",
            table_key,
            list(TABLE_CONFIG.keys()),
        )
        sys.exit(1)

    table_name = config["table"]

    # Read JSON
    path = Path(file_path)
    if not path.exists():
        logger.error("File not found: %s", path)
        sys.exit(1)

    with open(path, "r") as f:
        rows = json.load(f)

    if not isinstance(rows, list) or not rows:
        logger.warning("JSON file contains no data (empty or non-list). Nothing to do.")
        return

    logger.info("Loaded %d rows from %s for table '%s'", len(rows), path, table_name)

    # Ensure tables exist
    init_db()

    db = get_db()
    try:
        cols = _column_names(table_name, rows)
        if not cols:
            logger.error("No valid columns found in data for table '%s'", table_name)
            return

        placeholders = ", ".join("?" for _ in cols)
        col_list = ", ".join(cols)

        inserted = 0
        skipped = 0

        if config["allow_duplicates"]:
            # Simple INSERT — allow duplicates
            sql = f"INSERT INTO {table_name} ({col_list}) VALUES ({placeholders})"
            for row in rows:
                values = [row.get(c) for c in cols]
                try:
                    db.execute(sql, values)
                    inserted += 1
                except Exception as exc:
                    logger.warning("Insert failed for row: %s — %s", row, exc)
                    skipped += 1
        else:
            conflict_col = config["conflict_column"]
            # Build ON CONFLICT DO NOTHING clause
            sql = (
                f"INSERT INTO {table_name} ({col_list}) "
                f"VALUES ({placeholders}) "
                f"ON CONFLICT ({conflict_col}) DO NOTHING"
            )
            for row in rows:
                values = [row.get(c) for c in cols]
                try:
                    cursor = db.execute(sql, values)
                    if cursor.rowcount and cursor.rowcount > 0:
                        inserted += 1
                    else:
                        skipped += 1
                except Exception as exc:
                    logger.warning("Insert failed for row: %s — %s", row, exc)
                    skipped += 1

        db.commit()
        logger.info(
            "Inserted %d rows into %s, skipped %d duplicates",
            inserted,
            table_name,
            skipped,
        )
        print(
            f"Inserted {inserted} rows into {table_name}, skipped {skipped} duplicates"
        )
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest synthetic data JSON into TriageMate database.",
    )
    parser.add_argument("file", help="Path to JSON file (array of objects)")
    parser.add_argument(
        "--table",
        required=True,
        choices=list(TABLE_CONFIG.keys()),
        help="Target table for ingestion",
    )
    args = parser.parse_args()
    ingest_json(args.file, args.table)


if __name__ == "__main__":
    main()
