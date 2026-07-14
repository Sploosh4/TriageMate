"""
ML Gate A: Pre-training evidence check.

Auditable script that verifies training data readiness before running
--train. Checks gather-log consistency, NPZ existence/recency,
temporal split representativeness, and KEV rate reasonableness.

Usage:
    python -m scripts.ml_gate_a \\
        --npz-path backend/ml/training_data.npz \\
        --gather-log /tmp/sprint29-post-policy-gather.log \\
        --output /tmp/ml-gate-a-report.json
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_VERSION = "1.0"


def parse_int_comma(text: str) -> int:
    """Parse an integer string that may contain commas."""
    return int(text.replace(",", ""))


def parse_gather_log(log_path: str) -> dict:
    """Parse the gather log and return a dict of extracted statistics.

    Returns
    -------
    dict with keys:
        primary_count, prospective_count, censored_count,
        train_count, train_kev, train_kev_pct,
        val_count, val_kev, val_kev_pct,
        test_count, test_kev, test_kev_pct,
        total_cves, kev_total, kev_pct
    """
    with open(log_path, "r") as f:
        text = f.read()

    stats = {}

    # Primary cohort: 116,133 CVEs
    m = re.search(r"Primary cohort:\s*([\d,]+)\s*CVEs?", text)
    if m:
        stats["primary_count"] = parse_int_comma(m.group(1))

    # Prospective cohort: 144,503 CVEs
    m = re.search(r"Prospective cohort:\s*([\d,]+)\s*CVEs?", text)
    if m:
        stats["prospective_count"] = parse_int_comma(m.group(1))

    # Censored negatives: 144,237
    m = re.search(r"Censored negatives:\s*([\d,]+)", text)
    if m:
        stats["censored_count"] = parse_int_comma(m.group(1))

    # Train set: N,NNN records, NNN KEV-positive (N.NN%)
    m = re.search(
        r"Train set:\s*([\d,]+)\s*records?,\s*([\d,]+)\s*KEV-positive\s*\(([\d.]+)%\)",
        text,
    )
    if m:
        stats["train_count"] = parse_int_comma(m.group(1))
        stats["train_kev"] = parse_int_comma(m.group(2))
        stats["train_kev_pct"] = float(m.group(3))

    # Val set
    m = re.search(
        r"Val set:\s*([\d,]+)\s*records?,\s*([\d,]+)\s*KEV-positive\s*\(([\d.]+)%\)",
        text,
    )
    if m:
        stats["val_count"] = parse_int_comma(m.group(1))
        stats["val_kev"] = parse_int_comma(m.group(2))
        stats["val_kev_pct"] = float(m.group(3))

    # Test set
    m = re.search(
        r"Test set:\s*([\d,]+)\s*records?,\s*([\d,]+)\s*KEV-positive\s*\(([\d.]+)%\)",
        text,
    )
    if m:
        stats["test_count"] = parse_int_comma(m.group(1))
        stats["test_kev"] = parse_int_comma(m.group(2))
        stats["test_kev_pct"] = float(m.group(3))

    # DATA QUALITY REPORT section
    # Total CVEs: 116,133
    m = re.search(r"Total CVEs:\s+([\d,]+)", text)
    if m:
        stats["total_cves"] = parse_int_comma(m.group(1))

    # In KEV (label>0): 973  (0.838%)
    m = re.search(r"In KEV \(label>0\):\s+([\d,]+)\s+\(([\d.]+)%\)", text)
    if m:
        stats["kev_total"] = parse_int_comma(m.group(1))
        stats["kev_pct"] = float(m.group(2))

    return stats


def check_npz(npz_path: str) -> dict:
    """Check NPZ file existence, size, and mtime.

    Returns dict with keys: exists, size_mb, mtime, mtime_iso
    """
    result = {"exists": False, "size_mb": 0, "mtime": None, "mtime_iso": None}
    path = Path(npz_path)
    if path.exists() and path.is_file():
        stat = path.stat()
        result["exists"] = True
        result["size_mb"] = round(stat.st_size / (1024 * 1024), 1)
        result["mtime"] = stat.st_mtime
        result["mtime_iso"] = datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat()
    return result


def check_gather_log_recency(log_path: str) -> dict:
    """Check gather log existence and recency.

    Returns dict with keys: exists, mtime, mtime_iso, recent_7d
    """
    result = {"exists": False, "mtime": None, "mtime_iso": None, "recent_7d": False}
    path = Path(log_path)
    if path.exists() and path.is_file():
        stat = path.stat()
        result["exists"] = True
        result["mtime"] = stat.st_mtime
        result["mtime_iso"] = datetime.fromtimestamp(
            stat.st_mtime, tz=timezone.utc
        ).isoformat()
        # Check if within last 7 days
        age_seconds = datetime.now(tz=timezone.utc).timestamp() - stat.st_mtime
        result["recent_7d"] = age_seconds <= 7 * 24 * 3600
    return result


def run_gates(stats: dict, npz_info: dict, log_info: dict) -> dict:
    """Evaluate all gate checks.

    Parameters
    ----------
    stats : dict from parse_gather_log()
    npz_info : dict from check_npz()
    log_info : dict from check_gather_log_recency()

    Returns
    -------
    dict with gate name keys, each with pass and detail.
    """
    gates = {}

    # gate_split_representative: val_count >= 5000 AND test_count >= 5000
    val_count = stats.get("val_count", 0)
    test_count = stats.get("test_count", 0)
    split_pass = val_count >= 5000 and test_count >= 5000
    gates["gate_split_representative"] = {
        "pass": split_pass,
        "detail": f"val_count={val_count}, test_count={test_count}",
    }

    # gate_kev_rate_reasonable: 0.3% <= train_kev_pct <= 2.0%
    train_kev_pct = stats.get("train_kev_pct", 0)
    kev_rate_pass = 0.3 <= train_kev_pct <= 2.0
    gates["gate_kev_rate_reasonable"] = {
        "pass": kev_rate_pass,
        "detail": f"train_kev_pct={train_kev_pct}%",
    }

    # gate_val_not_degenerate: val_kev_pct > 0 AND val_kev_pct < 10%
    val_kev_pct = stats.get("val_kev_pct", 0)
    val_nondeg_pass = val_kev_pct > 0 and val_kev_pct < 10.0
    gates["gate_val_not_degenerate"] = {
        "pass": val_nondeg_pass,
        "detail": f"val_kev_pct={val_kev_pct}%",
    }

    # gate_test_not_degenerate: test_kev_pct > 0 AND test_kev_pct < 10%
    test_kev_pct = stats.get("test_kev_pct", 0)
    test_nondeg_pass = test_kev_pct > 0 and test_kev_pct < 10.0
    gates["gate_test_not_degenerate"] = {
        "pass": test_nondeg_pass,
        "detail": f"test_kev_pct={test_kev_pct}%",
    }

    # gate_npz_exists: NPZ file exists and size > 10MB
    npz_exists = npz_info.get("exists", False)
    npz_size_mb = npz_info.get("size_mb", 0)
    npz_pass = npz_exists and npz_size_mb > 10
    npz_detail = f"size={npz_size_mb}MB, mtime={npz_info.get('mtime_iso', 'N/A')}"
    gates["gate_npz_exists"] = {
        "pass": npz_pass,
        "detail": npz_detail,
    }

    # gate_gather_log_recent: gather log mtime within last 7 days
    log_recent = log_info.get("recent_7d", False)
    log_mtime_iso = log_info.get("mtime_iso", "N/A")
    gates["gate_gather_log_recent"] = {
        "pass": log_recent,
        "detail": f"mtime={log_mtime_iso}",
    }

    # gate_primary_prospective_balanced: both > 50000
    primary = stats.get("primary_count", 0)
    prospective = stats.get("prospective_count", 0)
    balanced_pass = primary > 50000 and prospective > 50000
    gates["gate_primary_prospective_balanced"] = {
        "pass": balanced_pass,
        "detail": f"primary={primary}, prospective={prospective}",
    }

    return gates


def build_report(
    npz_path: str,
    gather_log_path: str,
    stats: dict,
    npz_info: dict,
    log_info: dict,
    gates: dict,
) -> dict:
    """Build the full JSON report."""
    # Gather statistics sub-dict in the flattened structure
    gather_statistics = {
        "primary_count": stats.get("primary_count"),
        "prospective_count": stats.get("prospective_count"),
        "censored_count": stats.get("censored_count"),
        "total_cves": stats.get("total_cves"),
        "kev_total": stats.get("kev_total"),
        "kev_pct": stats.get("kev_pct"),
        "train": {
            "count": stats.get("train_count"),
            "kev": stats.get("train_kev"),
            "kev_pct": stats.get("train_kev_pct"),
        },
        "val": {
            "count": stats.get("val_count"),
            "kev": stats.get("val_kev"),
            "kev_pct": stats.get("val_kev_pct"),
        },
        "test": {
            "count": stats.get("test_count"),
            "kev": stats.get("test_kev"),
            "kev_pct": stats.get("test_kev_pct"),
        },
    }

    overall_pass = all(g["pass"] for g in gates.values())

    return {
        "script_version": SCRIPT_VERSION,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "npz_path": npz_path,
        "gather_log_path": gather_log_path,
        "gather_statistics": gather_statistics,
        "gates": gates,
        "overall_pass": overall_pass,
    }


def main():
    parser = argparse.ArgumentParser(
        description="ML Gate A: Pre-training evidence check"
    )
    parser.add_argument(
        "--npz-path",
        required=True,
        help="Path to training_data.npz",
    )
    parser.add_argument(
        "--gather-log",
        required=True,
        help="Path to the gather log file",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the JSON report",
    )
    args = parser.parse_args()

    # Gather info
    npz_info = check_npz(args.npz_path)
    log_info = check_gather_log_recency(args.gather_log)

    # Parse gather log
    if log_info["exists"]:
        stats = parse_gather_log(args.gather_log)
    else:
        print(f"ERROR: gather log not found at {args.gather_log}", file=sys.stderr)
        stats = {}

    # Evaluate gates
    gates = run_gates(stats, npz_info, log_info)

    # Build and write report
    report = build_report(
        args.npz_path, args.gather_log, stats, npz_info, log_info, gates
    )

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Gate A report written to {args.output}")
    print(f"Overall pass: {report['overall_pass']}")
    for g_name, g_result in gates.items():
        status = "PASS" if g_result["pass"] else "FAIL"
        print(f"  {status}: {g_name} — {g_result['detail']}")

    sys.exit(0 if report["overall_pass"] else 1)


if __name__ == "__main__":
    main()
