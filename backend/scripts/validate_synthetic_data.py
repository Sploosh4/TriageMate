"""
Data Validation Toolkit for Synthetic WA Government Hostname Data.

Runs 10 validation checks against the ``synthetic_assets`` (or
``synthetic_findings``) table in the main application database.

Usage:
    cd backend
    python -m scripts.validate_synthetic_data                         # default table
    python -m scripts.validate_synthetic_data --table synthetic_findings
    python -m scripts.validate_synthetic_data --output /tmp/report.md
    python -m scripts.validate_synthetic_data --table synthetic_assets --output /tmp/report.md

Exit code:
    0  — all 10 checks pass (or table does not exist)
    1  — one or more checks fail
"""

import argparse
import logging
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from database import get_db

# ── Path setup: make ``backend/`` importable from ``backend/scripts/`` ──
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

# Lazy import for ml.pretier_features — will be attempted at check time
# so that the script is importable even when the ml package has issues.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.validate_synthetic_data")

REPORT_DIR = _BACKEND_DIR / "reports" / "audits"

# ── Allowed enum values ──────────────────────────────────────────────────
VALID_MISSION_PREVALENCE = {"Core", "Support", "Peripheral"}
VALID_WELLBEING_IMPACT = {"Severe", "Moderate", "Minimal"}


# ═══════════════════════════════════════════════════════════════════════════
#  Helper utilities
# ═══════════════════════════════════════════════════════════════════════════


def _table_exists(conn, table: str) -> bool:
    """Return True if *table* exists in the SQLite schema."""
    row = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return bool(row[0] > 0)


def _get_columns(conn, table: str) -> set[str]:
    """Return a set of column names for *table*."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1] for r in rows}


def _fetch_all(conn, table: str) -> list[dict]:
    """Fetch all rows from *table* as list of dicts."""
    rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════
#  Check implementations
# ═══════════════════════════════════════════════════════════════════════════

# Each check returns a dict:
#   { "name": str, "passed": bool, "failed_count": int, "failing_rows": list[dict],
#     "details": str, "skipped": bool }


def check_duplicate_hostnames(rows: list[dict]) -> dict:
    """Check 1: Duplicate hostnames."""
    hostname_counts: dict[str, list[dict]] = {}
    for r in rows:
        hn = r.get("hostname", "")
        hostname_counts.setdefault(hn, []).append(r)

    dupes = {hn: recs for hn, recs in hostname_counts.items() if len(recs) > 1}
    failing = []
    for hn, recs in dupes.items():
        for rec in recs:
            failing.append(
                {
                    "id": rec.get("id"),
                    "hostname": hn,
                    "error": f"Duplicate hostname (seen {len(recs)} times)",
                }
            )

    return {
        "name": "1. Duplicate hostnames",
        "passed": len(dupes) == 0,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": f"Found {len(dupes)} duplicate hostnames.",
        "skipped": False,
    }


def check_required_fields(rows: list[dict]) -> dict:
    """Check 2: Required fields — mission_prevalence, public_wellbeing_impact,
    hostname, agency."""
    required = {"mission_prevalence", "public_wellbeing_impact", "hostname", "agency"}
    failing = []
    for r in rows:
        errors = []
        for field in required:
            val = r.get(field)
            if val is None or (isinstance(val, str) and val.strip() == ""):
                errors.append(f"{field} is NULL or empty")
        if errors:
            failing.append(
                {
                    "id": r.get("id"),
                    "hostname": r.get("hostname", ""),
                    "error": "; ".join(errors),
                }
            )

    return {
        "name": "2. Required fields",
        "passed": len(failing) == 0,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": f"Found {len(failing)} rows with missing required fields.",
        "skipped": False,
    }


def check_label_validity(rows: list[dict]) -> dict:
    """Check 3: Label validity — mission_prevalence and public_wellbeing_impact
    must be from allowed enums."""
    failing = []
    for r in rows:
        errors = []
        mp = r.get("mission_prevalence")
        if mp is not None and mp not in VALID_MISSION_PREVALENCE:
            errors.append(
                f"mission_prevalence='{mp}' not in {sorted(VALID_MISSION_PREVALENCE)}"
            )
        wi = r.get("public_wellbeing_impact")
        if wi is not None and wi not in VALID_WELLBEING_IMPACT:
            errors.append(
                f"public_wellbeing_impact='{wi}' not in {sorted(VALID_WELLBEING_IMPACT)}"
            )
        if errors:
            failing.append(
                {
                    "id": r.get("id"),
                    "hostname": r.get("hostname", ""),
                    "error": "; ".join(errors),
                }
            )

    return {
        "name": "3. Label validity",
        "passed": len(failing) == 0,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": f"Found {len(failing)} rows with invalid label values.",
        "skipped": False,
    }


def check_feature_extraction(rows: list[dict]) -> dict:
    """Check 4: Every hostname passes through extract_features() without error."""
    try:
        from ml.pretier_features import extract_features
    except ImportError as exc:
        return {
            "name": "4. Feature extraction",
            "passed": False,
            "failed_count": len(rows),
            "failing_rows": [
                {"id": None, "hostname": "N/A", "error": f"Import failed: {exc}"}
            ],
            "details": "Could not import ml.pretier_features.extract_features.",
            "skipped": False,
        }

    failing = []
    for r in rows:
        hn = r.get("hostname", "")
        if not hn:
            continue
        try:
            extract_features(hn)
        except Exception as exc:
            failing.append(
                {
                    "id": r.get("id"),
                    "hostname": hn,
                    "error": f"extract_features() raised {type(exc).__name__}: {exc}",
                }
            )

    return {
        "name": "4. Feature extraction",
        "passed": len(failing) == 0,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": f"Found {len(failing)} hostnames that failed feature extraction.",
        "skipped": False,
    }


def check_feature_vector_diversity(rows: list[dict]) -> dict:
    """Check 5: Feature vector diversity — no more than 10% of rows share
    the exact same 60-dim vector (rounded to 4 decimal places)."""
    try:
        from ml.pretier_features import extract_features, feature_vector_to_array
    except ImportError as exc:
        return {
            "name": "5. Feature vector diversity",
            "passed": False,
            "failed_count": len(rows),
            "failing_rows": [
                {"id": None, "hostname": "N/A", "error": f"Import failed: {exc}"}
            ],
            "details": "Could not import ml.pretier_features.",
            "skipped": False,
        }

    vector_counter: Counter[tuple] = Counter()
    hostname_to_vec: dict[str, tuple] = {}
    vec_to_hostnames: dict[tuple, list[str]] = {}

    for r in rows:
        hn = r.get("hostname", "")
        if not hn:
            continue
        try:
            feats = extract_features(hn)
            vec = tuple(round(v, 4) for v in feature_vector_to_array(feats))
            vector_counter[vec] += 1
            hostname_to_vec[hn] = vec
            vec_to_hostnames.setdefault(vec, []).append(hn)
        except Exception:
            # Failed extraction is caught by check 4; skip for diversity
            pass

    if not vector_counter:
        return {
            "name": "5. Feature vector diversity",
            "passed": True,
            "failed_count": 0,
            "failing_rows": [],
            "details": (
                "No feature vectors produced (table empty or all hostnames "
                "failed extraction)."
            ),
            "skipped": False,
        }

    total = len(rows)
    threshold = total * 0.10
    # Find the most common vector
    most_common_vec, most_common_count = vector_counter.most_common(1)[0]
    diversity_ok = most_common_count <= threshold

    failing = []
    if not diversity_ok:
        for hn in vec_to_hostnames.get(most_common_vec, []):
            failing.append(
                {
                    "id": next(
                        (r.get("id") for r in rows if r.get("hostname") == hn),
                        None,
                    ),
                    "hostname": hn,
                    "error": (
                        f"Shares the most-common vector with {most_common_count} other "
                        f"rows (>{threshold:.0f} = 10% threshold)"
                    ),
                }
            )

    return {
        "name": "5. Feature vector diversity",
        "passed": diversity_ok,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": (
            f"Most common vector appears {most_common_count}/{total} times "
            f"(threshold: {threshold:.0f}). "
            f"Unique vectors: {len(vector_counter)}."
        ),
        "skipped": False,
    }


def check_hostname_format(rows: list[dict]) -> dict:
    """Check 6: Hostname format — must contain at least one dot and one hyphen,
    no double hyphens, no leading/trailing hyphens."""
    failing = []
    for r in rows:
        hn = r.get("hostname", "")
        if not hn:
            errors = ["hostname is empty"]
            failing.append(
                {
                    "id": r.get("id"),
                    "hostname": hn,
                    "error": "; ".join(errors),
                }
            )
            continue

        errors = []
        if "." not in hn:
            errors.append("No domain (missing dot)")
        if "-" not in hn:
            errors.append("No components (missing hyphen)")
        if "--" in hn:
            errors.append("Contains double hyphens")
        if hn.startswith("-") or hn.endswith("-"):
            errors.append("Leading or trailing hyphen")
        if hn.startswith(".") or hn.endswith("."):
            errors.append("Leading or trailing dot")

        if errors:
            failing.append(
                {
                    "id": r.get("id"),
                    "hostname": hn,
                    "error": "; ".join(errors),
                }
            )

    return {
        "name": "6. Hostname format",
        "passed": len(failing) == 0,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": f"Found {len(failing)} rows with invalid hostname format.",
        "skipped": False,
    }


def check_label_distribution(rows: list[dict]) -> dict:
    """Check 7: No single class >80% for mission_prevalence or
    public_wellbeing_impact."""
    total = len(rows)
    if total == 0:
        return {
            "name": "7. Label distribution",
            "passed": True,
            "failed_count": 0,
            "failing_rows": [],
            "details": "No rows to check.",
            "skipped": False,
        }

    threshold = total * 0.80
    mp_counts: dict[str, int] = {}
    wi_counts: dict[str, int] = {}
    failing_labels = []

    for r in rows:
        mp = r.get("mission_prevalence")
        wi = r.get("public_wellbeing_impact")
        if mp:
            mp_counts[mp] = mp_counts.get(mp, 0) + 1
        if wi:
            wi_counts[wi] = wi_counts.get(wi, 0) + 1

    for label, count in mp_counts.items():
        if count > threshold:
            failing_labels.append(
                f"mission_prevalence='{label}' has {count}/{total} ({count / total * 100:.1f}%)"
            )
    for label, count in wi_counts.items():
        if count > threshold:
            failing_labels.append(
                f"public_wellbeing_impact='{label}' has {count}/{total} ({count / total * 100:.1f}%)"
            )

    passed = len(failing_labels) == 0
    failing = []
    if not passed:
        failing.append(
            {
                "id": None,
                "hostname": "N/A",
                "error": "; ".join(failing_labels),
            }
        )

    return {
        "name": "7. Label distribution",
        "passed": passed,
        "failed_count": 1 if not passed else 0,
        "failing_rows": failing[:5],
        "details": (
            f"Distribution — MP: {dict(mp_counts)}, "
            f"WI: {dict(wi_counts)}. "
            f"Threshold (80%): {threshold:.0f}."
        ),
        "skipped": False,
    }


def check_research_traceability(rows: list[dict]) -> dict:
    """Check 8: Every source_research_ref exists in research_references table.

    source_research_ref may contain comma-separated IDs like
    "AGENCY-001, SOFTWARE-012". A row passes if AT LEAST ONE of its
    comma-separated refs exists in research_references.
    """
    conn = get_db()
    try:
        if not _table_exists(conn, "research_references"):
            return {
                "name": "8. Research traceability",
                "passed": True,
                "failed_count": 0,
                "failing_rows": [],
                "details": (
                    "research_references table does not exist — skipping check."
                ),
                "skipped": True,
            }

        refs_with_data = [r for r in rows if r.get("source_research_ref")]
        if not refs_with_data:
            return {
                "name": "8. Research traceability",
                "passed": True,
                "failed_count": 0,
                "failing_rows": [],
                "details": "No rows have source_research_ref set.",
                "skipped": False,
            }

        # Build set of all valid ref_ids
        valid_refs = {
            row[0]
            for row in conn.execute("SELECT ref_id FROM research_references").fetchall()
        }

        failing = []
        for r in refs_with_data:
            ref_raw = r["source_research_ref"]
            parts = [p.strip() for p in ref_raw.split(",")]
            # Row passes if ANY of its comma-separated refs exist
            found_any = any(p in valid_refs for p in parts)
            if not found_any:
                failing.append(
                    {
                        "id": r.get("id"),
                        "hostname": r.get("hostname", ""),
                        "error": (
                            f"source_research_ref='{ref_raw}' — none of its "
                            f"refs found in research_references"
                        ),
                    }
                )

        return {
            "name": "8. Research traceability",
            "passed": len(failing) == 0,
            "failed_count": len(failing),
            "failing_rows": failing[:5],
            "details": (
                f"Checked {len(refs_with_data)} rows with references. "
                f"Found {len(failing)} orphan references."
            ),
            "skipped": False,
        }
    finally:
        conn.close()


def check_confidence_bounds(rows: list[dict]) -> dict:
    """Check 9: All confidence values in [0.0, 1.0]."""
    confidence_fields = ["confidence_mp", "confidence_wi"]
    failing = []
    for r in rows:
        errors = []
        for field in confidence_fields:
            val = r.get(field)
            if val is not None:
                try:
                    fval = float(val)
                    if fval < 0.0 or fval > 1.0:
                        errors.append(f"{field}={fval} outside [0.0, 1.0]")
                except (TypeError, ValueError):
                    errors.append(f"{field}='{val}' is not a valid float")
        if errors:
            failing.append(
                {
                    "id": r.get("id"),
                    "hostname": r.get("hostname", ""),
                    "error": "; ".join(errors),
                }
            )

    return {
        "name": "9. Confidence bounds",
        "passed": len(failing) == 0,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": f"Found {len(failing)} rows with out-of-bounds confidence values.",
        "skipped": False,
    }


def check_holdout_integrity(rows: list[dict], columns: set[str]) -> dict:
    """Check 10: Blind holdout integrity — if ``in_holdout`` column exists,
    verify it's ~20% ±5% of total."""
    if "in_holdout" not in columns:
        return {
            "name": "10. Blind holdout integrity",
            "passed": True,
            "failed_count": 0,
            "failing_rows": [],
            "details": (
                "No 'in_holdout' column found in table schema — skipping check."
            ),
            "skipped": True,
        }

    total = len(rows)
    if total == 0:
        return {
            "name": "10. Blind holdout integrity",
            "passed": True,
            "failed_count": 0,
            "failing_rows": [],
            "details": "No rows to check.",
            "skipped": False,
        }

    holdout_count = sum(1 for r in rows if r.get("in_holdout") == 1)
    pct = (holdout_count / total) * 100
    passed = 15.0 <= pct <= 25.0

    failing = []
    if not passed:
        failing.append(
            {
                "id": None,
                "hostname": "N/A",
                "error": (
                    f"Holdout is {holdout_count}/{total} ({pct:.1f}%), "
                    f"expected ~20% ±5% (15-25%)"
                ),
            }
        )

    return {
        "name": "10. Blind holdout integrity",
        "passed": passed,
        "failed_count": len(failing),
        "failing_rows": failing[:5],
        "details": (
            f"Holdout: {holdout_count}/{total} ({pct:.1f}%). Target range: 15-25%."
        ),
        "skipped": False,
    }


# ═══════════════════════════════════════════════════════════════════════════
#  Report generation
# ═══════════════════════════════════════════════════════════════════════════


def _build_label_summary(rows: list[dict]) -> str:
    """Build a markdown table summarising label distributions."""
    mp_counts: dict[str, int] = {}
    wi_counts: dict[str, int] = {}
    for r in rows:
        mp = r.get("mission_prevalence")
        wi = r.get("public_wellbeing_impact")
        if mp:
            mp_counts[mp] = mp_counts.get(mp, 0) + 1
        if wi:
            wi_counts[wi] = wi_counts.get(wi, 0) + 1

    total = len(rows)
    lines = ["### Label Distribution\n", "| Dimension | Value | Count | % |"]
    lines.append("|---|---|---:|--:|")

    for label, count in sorted(mp_counts.items()):
        pct = count / total * 100 if total else 0
        lines.append(f"| mission_prevalence | {label} | {count} | {pct:.1f}% |")
    # Total row for MP
    lines.append(
        f"| mission_prevalence | **Total** | **{sum(mp_counts.values())}** | |"
    )
    lines.append("")
    for label, count in sorted(wi_counts.items()):
        pct = count / total * 100 if total else 0
        lines.append(f"| public_wellbeing_impact | {label} | {count} | {pct:.1f}% |")
    lines.append(
        f"| public_wellbeing_impact | **Total** | **{sum(wi_counts.values())}** | |"
    )
    return "\n".join(lines)


def _generate_report(
    total_rows: int,
    results: list[dict],
    rows: list[dict],
) -> str:
    """Produce a markdown validation report."""
    passed_checks = sum(1 for r in results if r["passed"] or r["skipped"])
    failed_checks = sum(1 for r in results if not r["passed"] and not r["skipped"])
    total_failed_rows = sum(r["failed_count"] for r in results)
    overall_failed = any(not r["passed"] and not r["skipped"] for r in results)
    overall = "**FAILED**" if overall_failed else "**PASSED**"

    lines = [
        "# Synthetic Data Validation Report",
        "",
        f"**Date:** {date.today().isoformat()}",
        f"**Total rows checked:** {total_rows}",
        f"**Rows with failures:** {total_failed_rows}",
        f"**Checks passed:** {passed_checks}/{len(results)}",
        f"**Checks failed:** {failed_checks}/{len(results)}",
        f"**Overall:** {overall}",
        "",
        "---",
        "",
        "## Per-Check Breakdown",
        "",
        "| # | Check | Rows Failed | Status |",
        "|---|---:|---:|:---:|",
    ]

    for r in results:
        status = "✅ PASS" if r["passed"] else ("⏭️ SKIP" if r["skipped"] else "❌ FAIL")
        lines.append(
            f"| {r['name'].split()[0]} | {r['name']} | {r['failed_count']} | {status} |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Check Details")
    lines.append("")

    for r in results:
        lines.append(f"### {r['name']}")
        lines.append("")
        lines.append(
            f"**Status:** {'✅ PASS' if r['passed'] else '⏭️ SKIP' if r['skipped'] else '❌ FAIL'}"
        )
        lines.append("")
        lines.append(f"**Detail:** {r['details']}")
        lines.append("")
        if r["failing_rows"]:
            lines.append("**Sample of up to 5 failing rows:**")
            lines.append("")
            lines.append("| ID | Hostname | Error |")
            lines.append("|---|---|---|")
            for fr in r["failing_rows"]:
                fr_id = str(fr.get("id", "")) if fr.get("id") is not None else "N/A"
                hn = fr.get("hostname", "")
                err = fr.get("error", "")
                lines.append(f"| {fr_id} | {hn} | {err} |")
            lines.append("")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(_build_label_summary(rows))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"## Overall: {overall}")
    lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  Database update
# ═══════════════════════════════════════════════════════════════════════════


def _update_validation_results(
    conn,
    table: str,
    rows: list[dict],
    results: list[dict],
) -> None:
    """Update validation_status and validation_errors on each row.

    Rows are cumulative — a row failing multiple checks has all errors
    concatenated (semicolon-separated).
    """
    columns = _get_columns(conn, table)

    if "validation_status" not in columns or "validation_errors" not in columns:
        logger.warning(
            "Table '%s' lacks validation_status/validation_errors columns — "
            "skipping DB updates.",
            table,
        )
        return

    # Collect errors per row id
    row_errors: dict[int, list[str]] = {}
    rows_that_failed: set[int] = set()
    for r in results:
        for fr in r["failing_rows"]:
            fr_id = fr.get("id")
            if fr_id is not None:
                rows_that_failed.add(fr_id)
                row_errors.setdefault(fr_id, []).append(fr["error"])

    # Mark failed rows
    for row_id, errors in row_errors.items():
        combined = "; ".join(errors)
        conn.execute(
            f"UPDATE {table} SET validation_status = 'failed', "
            f"validation_errors = ? WHERE id = ?",
            (combined, row_id),
        )

    # Mark passed rows (those checked but not in any failure)
    checked_ids = {r.get("id") for r in rows if r.get("id") is not None}
    passed_ids = checked_ids - rows_that_failed
    if passed_ids:
        placeholders = ",".join("?" for _ in passed_ids)
        conn.execute(
            f"UPDATE {table} SET validation_status = 'passed', "
            f"validation_errors = '' WHERE id IN ({placeholders})",
            tuple(passed_ids),
        )

    conn.commit()
    logger.info(
        "Validation results written: %d failed, %d passed.",
        len(rows_that_failed),
        len(passed_ids),
    )


# ═══════════════════════════════════════════════════════════════════════════
#  Main orchestrator
# ═══════════════════════════════════════════════════════════════════════════


def run_all_checks(
    table: str = "synthetic_assets",
    output: str | None = None,
) -> int:
    """Run all 10 validation checks.

    Args:
        table: Database table to validate.
        output: Path for the markdown report.  If None, uses the default
            ``backend/reports/audits/synthetic-data-validation-{date}.md``.

    Returns:
        0 if all checks pass, 1 if any fail.
    """
    logger.info("Starting validation for table '%s'...", table)

    conn = get_db()
    try:
        if not _table_exists(conn, table):
            msg = (
                f"Table '{table}' does not exist in the database. "
                f"No validation performed."
            )
            logger.warning(msg)
            # Write a minimal report so the CI pipeline sees a valid file
            report_path = output or str(
                REPORT_DIR / f"synthetic-data-validation-{date.today().isoformat()}.md"
            )
            report_content = (
                f"# Synthetic Data Validation Report\n\n"
                f"**Date:** {date.today().isoformat()}\n\n"
                f"**Table '{table}' not found — no data to validate.**\n\n"
                f"## Overall: **NOT APPLICABLE**\n"
            )
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            Path(report_path).write_text(report_content)
            logger.info("Report written to %s", report_path)
            return 0

        rows = _fetch_all(conn, table)
        total = len(rows)
        columns = _get_columns(conn, table)
        logger.info("Fetched %d rows from '%s'.", total, table)

        if total == 0:
            logger.info("Table '%s' is empty — all checks pass trivially.", table)

        # ── Run all 10 checks ──────────────────────────────────────────────
        results: list[dict] = [
            check_duplicate_hostnames(rows),
            check_required_fields(rows),
            check_label_validity(rows),
            check_feature_extraction(rows),
            check_feature_vector_diversity(rows),
            check_hostname_format(rows),
            check_label_distribution(rows),
            check_research_traceability(rows),
            check_confidence_bounds(rows),
            check_holdout_integrity(rows, columns),
        ]

        # ── Update DB ──────────────────────────────────────────────────────
        _update_validation_results(conn, table, rows, results)

        # ── Report ─────────────────────────────────────────────────────────
        report_content = _generate_report(total, results, rows)
        report_path = output or str(
            REPORT_DIR / f"synthetic-data-validation-{date.today().isoformat()}.md"
        )
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(report_content)
        logger.info("Report written to %s", report_path)

        # ── Print summary to stdout ────────────────────────────────────────
        passed = sum(1 for r in results if r["passed"] or r["skipped"])
        total_failed_rows = sum(r["failed_count"] for r in results)

        print(f"\n{'=' * 60}")
        print(f"  Synthetic Data Validation — {table}")
        print(f"  Rows: {total}, Checks: {passed}/{len(results)} passed")
        print(f"  Failed rows: {total_failed_rows}")
        overall_failed = any(not r["passed"] and not r["skipped"] for r in results)
        print(f"  Overall: {'❌ FAILED' if overall_failed else '✅ PASSED'}")
        print(f"  Report: {report_path}")
        print(f"{'=' * 60}\n")

        for r in results:
            icon = "✅" if r["passed"] else ("⏭️" if r["skipped"] else "❌")
            print(f"  {icon} {r['name']}: {r['failed_count']} failed — {r['details']}")

        return 1 if overall_failed else 0

    finally:
        conn.close()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Validate synthetic WA government hostname data.",
    )
    parser.add_argument(
        "--table",
        default="synthetic_assets",
        choices=["synthetic_assets", "synthetic_findings"],
        help="Table to validate (default: synthetic_assets).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Output path for the markdown report. "
            "Default: backend/reports/audits/synthetic-data-validation-{date}.md"
        ),
    )
    args = parser.parse_args()

    exit_code = run_all_checks(table=args.table, output=args.output)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
