#!/usr/bin/env python3
"""ML Gate A: Gather Evidence and Integrity Check.

Validates that a completed gather (NPZ + training log) contains all required
evidence lines and that per-split class distributions are balanced. Produces
a reproducible JSON evidence record.

Usage:
    python -m scripts.ml_gate_a_check \\
        --npz-path <path> \\
        --gather-log <path> \\
        --output-path <path>

Exit codes:
    0 — inputs parsed, all required evidence lines present
    1 — missing/corrupt inputs, incomplete evidence, or single-class split
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

SCRIPT_VERSION = "1.1.0"
REQUIRED_NPZ_KEYS = ("X", "y", "dates", "cve_ids", "feature_names")

# Regex patterns for gather log evidence lines
PAT_OBS_WINDOW = re.compile(
    r"(?:KEV observation window|observation_window|OBS_WINDOW|KEV lag)[:\s]*(\d+)\s*(?:days?|d)?",
    re.IGNORECASE,
)
PAT_PRIMARY_COHORT = re.compile(r"Primary cohort:\s*([\d,]+)\s*CVEs")
PAT_PROSPECTIVE_COHORT = re.compile(r"Prospective cohort:\s*([\d,]+)\s*CVEs")
PAT_CENSORED = re.compile(r"Censored negatives:\s*([\d,]+)")
PAT_SPLIT = re.compile(
    r"(Train|Val|Test)\s+set:\s*([\d,]+)\s+records,\s*([\d,]+)\s+KEV-positive\s*\(([\d.]+)%\)"
)
PAT_FINAL_POSITIVE_RATE = re.compile(r"Final positive rate.*?(\d+)\s*/\s*(\d+)")


def parse_args() -> argparse.Namespace:
    """Parse and validate CLI arguments. Exits with code 1 if missing."""
    parser = argparse.ArgumentParser(
        description="ML Gate A: Gather Evidence and Integrity Check"
    )
    parser.add_argument(
        "--npz-path",
        required=True,
        help="Path to the training_data.npz file produced by --gather",
    )
    parser.add_argument(
        "--gather-log",
        required=True,
        help="Path to the console log from the --gather run",
    )
    parser.add_argument(
        "--output-path",
        required=True,
        help="Path for the output JSON evidence record",
    )
    return parser.parse_args()


def load_npz_metadata(npz_path: Path) -> dict:
    """Load NPZ and return structured metadata.

    Returns dict with:
        file_size_bytes, last_modified_iso, num_records, feature_dimension,
        date_range_min, date_range_max, feature_name_count, feature_name_fingerprint
    """
    stat = npz_path.stat()
    file_size_bytes = stat.st_size
    last_modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

    artifact_hasher = hashlib.sha256()
    with npz_path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            artifact_hasher.update(chunk)

    with np.load(str(npz_path), allow_pickle=False) as data:
        missing_keys = [key for key in REQUIRED_NPZ_KEYS if key not in data]
        if missing_keys:
            raise ValueError(f"missing required arrays: {', '.join(missing_keys)}")

        X = data["X"]
        y = data["y"]
        dates = data["dates"]
        cve_ids = data["cve_ids"]
        feature_names = data["feature_names"]

        if X.ndim != 2:
            raise ValueError(f"X must be 2-dimensional, got shape {X.shape}")

        num_records, feature_dim = X.shape
        row_counts = {
            "X": num_records,
            "y": len(y),
            "dates": len(dates),
            "cve_ids": len(cve_ids),
        }
        if len(set(row_counts.values())) != 1:
            raise ValueError(f"row counts do not align: {row_counts}")
        if len(feature_names) != feature_dim:
            raise ValueError(
                "feature_names count does not match X width: "
                f"{len(feature_names)} != {feature_dim}"
            )

        non_empty = dates[dates != ""]
        date_range_min = str(min(non_empty)) if len(non_empty) else None
        date_range_max = str(max(non_empty)) if len(non_empty) else None
        positive_count = int(np.count_nonzero(y > 0))
        feature_name_count = int(len(feature_names))
        concat = "|".join(str(name) for name in feature_names)
        feature_name_fingerprint = hashlib.sha256(concat.encode("utf-8")).hexdigest()

    return {
        "file_size_bytes": file_size_bytes,
        "last_modified_iso": last_modified,
        "artifact_sha256": artifact_hasher.hexdigest(),
        "num_records": int(num_records),
        "positive_count": positive_count,
        "feature_dimension": int(feature_dim),
        "date_range_min": date_range_min,
        "date_range_max": date_range_max,
        "feature_name_count": feature_name_count,
        "feature_name_fingerprint": feature_name_fingerprint,
    }


def parse_gather_log(log_path: Path) -> dict:
    """Parse the gather console log for evidence lines.

    Returns dict with keys:
        observation_window_days
        primary_cohort_count
        prospective_cohort_count
        censored_negatives_count
        splits: list of {name, records, kev_positive, pct}
        final_positive_rate_numerator
        final_positive_rate_denominator
        evidence_lines_found: list of matched line snippets
    """
    text = log_path.read_text(encoding="utf-8", errors="replace")
    evidence_lines_found = []

    def _capture(pattern, text, group_index=1):
        m = pattern.search(text)
        if m:
            evidence_lines_found.append(m.group(0).strip())
            return m.group(group_index)
        return None

    obs_window = _capture(PAT_OBS_WINDOW, text)
    primary_cohort = _capture(PAT_PRIMARY_COHORT, text)
    prospective_cohort = _capture(PAT_PROSPECTIVE_COHORT, text)
    censored = _capture(PAT_CENSORED, text)

    splits = []
    for m in PAT_SPLIT.finditer(text):
        name = m.group(1)
        records = int(m.group(2).replace(",", ""))
        kev_pos = int(m.group(3).replace(",", ""))
        pct = float(m.group(4))
        splits.append(
            {
                "name": name,
                "records": records,
                "kev_positive": kev_pos,
                "pct": pct,
            }
        )
        evidence_lines_found.append(m.group(0).strip())

    final_match = PAT_FINAL_POSITIVE_RATE.search(text)
    final_pos_num = None
    final_pos_den = None
    if final_match:
        evidence_lines_found.append(final_match.group(0).strip())
        final_pos_num, final_pos_den = final_match.group(1), final_match.group(2)

    return {
        "observation_window_days": int(obs_window) if obs_window else None,
        "primary_cohort_count": int(primary_cohort.replace(",", ""))
        if primary_cohort
        else None,
        "prospective_cohort_count": int(prospective_cohort.replace(",", ""))
        if prospective_cohort
        else None,
        "censored_negatives_count": int(censored.replace(",", ""))
        if censored
        else None,
        "splits": splits,
        "final_positive_rate_numerator": int(final_pos_num) if final_pos_num else None,
        "final_positive_rate_denominator": int(final_pos_den)
        if final_pos_den
        else None,
        "evidence_lines_found": evidence_lines_found,
    }


def validate(npz_meta: dict, log_parsed: dict) -> list:
    """Run all validations. Returns list of warning/error strings.

    Checks:
      - Both inputs exist and are readable (pre-parse, done before calling)
      - All required evidence lines are present
      - No split is single-class (both classes in train/val/test)
    """
    warnings = []

    # Check all required evidence fields are non-None
    required_log_fields = [
        ("observation_window_days", "observation window value"),
        ("primary_cohort_count", "primary cohort count"),
        ("prospective_cohort_count", "prospective cohort count"),
        ("censored_negatives_count", "censored negatives count"),
        ("final_positive_rate_numerator", "final positive rate"),
        ("final_positive_rate_denominator", "final positive rate"),
    ]
    for field, label in required_log_fields:
        if log_parsed.get(field) is None:
            warnings.append(f"Missing evidence line in gather log: {label}")

    # Check all three splits are present
    split_names_found = {s["name"] for s in log_parsed["splits"]}
    for required_split in ("Train", "Val", "Test"):
        if required_split not in split_names_found:
            warnings.append(
                f"Missing split evidence line in gather log: {required_split}"
            )

    # Check no split is single-class
    for split in log_parsed["splits"]:
        total = split["records"]
        positive = split["kev_positive"]
        negative = total - positive
        if positive == 0 or negative == 0:
            warnings.append(
                f"Single-class split detected: {split['name']} has "
                f"{total} records with {positive} KEV-positive and {negative} KEV-negative. "
                f"Split is degenerate."
            )

    split_total = sum(split["records"] for split in log_parsed["splits"])
    split_positive = sum(split["kev_positive"] for split in log_parsed["splits"])
    primary_count = log_parsed.get("primary_cohort_count")
    final_positive = log_parsed.get("final_positive_rate_numerator")
    final_denominator = log_parsed.get("final_positive_rate_denominator")

    count_checks = (
        (npz_meta["num_records"], primary_count, "NPZ rows vs primary cohort"),
        (npz_meta["num_records"], final_denominator, "NPZ rows vs final denominator"),
        (split_total, primary_count, "split rows vs primary cohort"),
        (
            npz_meta["positive_count"],
            final_positive,
            "NPZ positives vs final positives",
        ),
        (split_positive, final_positive, "split positives vs final positives"),
    )
    for actual, expected, label in count_checks:
        if expected is not None and actual != expected:
            warnings.append(f"{label} mismatch: {actual} != {expected}")

    return warnings


def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()

    npz_path = Path(args.npz_path)
    log_path = Path(args.gather_log)
    output_path = Path(args.output_path)

    # --- Validate inputs exist ---
    errors = []
    if not npz_path.exists():
        errors.append(f"NPZ file not found: {npz_path}")
    if not log_path.exists():
        errors.append(f"Gather log not found: {log_path}")

    if errors:
        report = {
            "script_version": SCRIPT_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "npz_path": str(npz_path),
            "gather_log_path": str(log_path),
            "output_path": str(output_path),
            "errors": errors,
            "npz_metadata": None,
            "gather_log_parsed": None,
            "warnings": [],
            "exit_code": 1,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Gate A FAILED — input errors found. See {output_path}")
        for e in errors:
            print(f"  ERROR: {e}")
        return 1

    # --- Load NPZ metadata ---
    try:
        npz_meta = load_npz_metadata(npz_path)
    except Exception as e:
        report = _error_report(
            npz_path, log_path, output_path, f"Failed to load NPZ: {e}"
        )
        _write_report(report, output_path)
        return 1

    # --- Parse gather log ---
    try:
        log_parsed = parse_gather_log(log_path)
    except Exception as e:
        report = _error_report(
            npz_path, log_path, output_path, f"Failed to parse gather log: {e}"
        )
        _write_report(report, output_path)
        return 1

    # --- Validate ---
    warnings = validate(npz_meta, log_parsed)

    # Determine exit code
    exit_code = 0 if not warnings else 1

    # --- Build report ---
    report = {
        "script_version": SCRIPT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "npz_path": str(npz_path),
        "gather_log_path": str(log_path),
        "output_path": str(output_path),
        "errors": [],
        "npz_metadata": npz_meta,
        "gather_log_parsed": log_parsed,
        "warnings": warnings,
        "exit_code": exit_code,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    if exit_code == 0:
        print(f"Gate A PASSED — evidence record written to {output_path}")
    else:
        print(f"Gate A FAILED — warnings found. See {output_path}")
        for w in warnings:
            print(f"  WARNING: {w}")

    return exit_code


def _error_report(npz_path, log_path, output_path, error_msg: str) -> dict:
    return {
        "script_version": SCRIPT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "npz_path": str(npz_path),
        "gather_log_path": str(log_path),
        "output_path": str(output_path),
        "errors": [error_msg],
        "npz_metadata": None,
        "gather_log_parsed": None,
        "warnings": [],
        "exit_code": 1,
    }


def _write_report(report: dict, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)


if __name__ == "__main__":
    sys.exit(main())
