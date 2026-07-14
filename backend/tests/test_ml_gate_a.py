"""
Tests for scripts.ml_gate_a — Gate A evidence check.

Uses synthetic fixtures (tmp_path) to avoid any dependency on real
gather artifacts or NPZ files.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure backend is importable
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.ml_gate_a import (
    SCRIPT_VERSION,
    build_report,
    check_gather_log_recency,
    check_npz,
    parse_gather_log,
    run_gates,
)


# ── Fixtures ──


@pytest.fixture
def sample_gather_log(tmp_path) -> str:
    """Create a synthetic gather log with known values."""
    content = """============================================================
PHASE 1: GATHER DATA
============================================================

  Censored negatives: 144,237 (label-0 CVEs published after 2023-01-25).
  Primary cohort: 116,133 CVEs (44.6% of pre-filter).
  Prospective cohort: 144,503 CVEs (newer than the observation cutoff).

  Train set: 69,223 records, 641 KEV-positive (0.93%)
  Val set: 20,144 records, 200 KEV-positive (0.99%)
  Test set: 26,766 records, 132 KEV-positive (0.49%)

============================================================
DATA QUALITY REPORT (multi-window KEV)
============================================================

  Total CVEs:           116,133
  In KEV (label>0):     973  (0.838%)

  Train set:           69,223 CVEs  (positives: 641 = 0.93%)
    Val set:           20,144 CVEs  (positives: 200 = 0.99%)
   Test set:           26,766 CVEs  (positives: 132 = 0.49%)
"""
    path = tmp_path / "gather.log"
    path.write_text(content)
    return str(path)


@pytest.fixture
def edge_gather_log(tmp_path) -> str:
    """Synthetic log with edge-case KEV rates (0% and 100%)."""
    content = """Primary cohort: 100,000 CVEs
Prospective cohort: 80,000 CVEs
Censored negatives: 50,000
Train set: 50,000 records, 0 KEV-positive (0.00%)
Val set: 10,000 records, 0 KEV-positive (0.00%)
Test set: 10,000 records, 5,000 KEV-positive (50.00%)
Total CVEs:           100,000
In KEV (label>0):     500  (0.500%)
"""
    path = tmp_path / "edge_gather.log"
    path.write_text(content)
    return str(path)


@pytest.fixture
def valid_npz(tmp_path) -> str:
    """Create a valid NPZ file > 10MB."""
    path = tmp_path / "training_data.npz"
    # Write enough data to exceed 10MB
    size_bytes = 11 * 1024 * 1024  # 11MB
    with open(path, "wb") as f:
        f.write(b"0" * size_bytes)
    return str(path)


@pytest.fixture
def small_npz(tmp_path) -> str:
    """Create a small NPZ file (< 10MB)."""
    path = tmp_path / "small.npz"
    path.write_text("not a real npz but tiny")
    return str(path)


# ── Tests for parse_gather_log ──


class TestParseGatherLog:
    def test_parses_main_fields(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        assert stats["primary_count"] == 116133
        assert stats["prospective_count"] == 144503
        assert stats["censored_count"] == 144237
        assert stats["total_cves"] == 116133
        assert stats["kev_total"] == 973
        assert stats["kev_pct"] == 0.838

    def test_parses_split_fields(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        assert stats["train_count"] == 69223
        assert stats["train_kev"] == 641
        assert stats["train_kev_pct"] == 0.93
        assert stats["val_count"] == 20144
        assert stats["val_kev"] == 200
        assert stats["val_kev_pct"] == 0.99
        assert stats["test_count"] == 26766
        assert stats["test_kev"] == 132
        assert stats["test_kev_pct"] == 0.49

    def test_empty_log_returns_empty(self, tmp_path):
        path = tmp_path / "empty.log"
        path.write_text("")
        stats = parse_gather_log(str(path))
        assert stats == {}


# ── Tests for check_npz ──


class TestCheckNpz:
    def test_npz_exists_and_large(self, valid_npz):
        info = check_npz(valid_npz)
        assert info["exists"] is True
        assert info["size_mb"] > 10

    def test_npz_exists_but_small(self, small_npz):
        info = check_npz(small_npz)
        assert info["exists"] is True
        assert info["size_mb"] < 1

    def test_npz_missing(self, tmp_path):
        path = tmp_path / "nonexistent.npz"
        info = check_npz(str(path))
        assert info["exists"] is False
        assert info["size_mb"] == 0


# ── Tests for check_gather_log_recency ──


class TestCheckGatherLogRecency:
    def test_log_exists(self, sample_gather_log):
        info = check_gather_log_recency(sample_gather_log)
        assert info["exists"] is True
        assert info["mtime_iso"] is not None

    def test_log_missing(self, tmp_path):
        path = tmp_path / "nope.log"
        info = check_gather_log_recency(str(path))
        assert info["exists"] is False
        assert info["recent_7d"] is False

    def test_log_recently_created(self, tmp_path):
        """A log just created should be within 7 days."""
        path = tmp_path / "fresh.log"
        path.write_text("test")
        info = check_gather_log_recency(str(path))
        assert info["exists"] is True
        assert info["recent_7d"] is True


# ── Tests for run_gates ──


class TestRunGates:
    def test_all_pass(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        npz_info = {
            "exists": True,
            "size_mb": 155.5,
            "mtime_iso": "2026-07-14T00:00:00",
        }
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        for g_name, g_result in gates.items():
            assert g_result["pass"], f"{g_name} should pass: {g_result['detail']}"

    def test_split_representative_fails(self, sample_gather_log):
        """Test that gate_split_representative fails with tiny splits."""
        stats = parse_gather_log(sample_gather_log)
        stats["val_count"] = 100
        stats["test_count"] = 200
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_split_representative"]["pass"] is False
        assert "val_count=100" in gates["gate_split_representative"]["detail"]

    def test_kev_rate_too_low(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        stats["train_kev_pct"] = 0.1
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_kev_rate_reasonable"]["pass"] is False

    def test_kev_rate_too_high(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        stats["train_kev_pct"] = 5.0
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_kev_rate_reasonable"]["pass"] is False

    def test_val_degenerate_zero(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        stats["val_kev_pct"] = 0.0
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_val_not_degenerate"]["pass"] is False

    def test_val_degenerate_100(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        stats["val_kev_pct"] = 100.0
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_val_not_degenerate"]["pass"] is False

    def test_primary_prospective_unbalanced(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        stats["primary_count"] = 100
        stats["prospective_count"] = 200
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_primary_prospective_balanced"]["pass"] is False

    def test_npz_not_exists(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        npz_info = {"exists": False, "size_mb": 0, "mtime_iso": None}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_npz_exists"]["pass"] is False

    def test_gather_log_not_recent(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        npz_info = {"exists": True, "size_mb": 150, "mtime_iso": "2026-07-14T00:00:00"}
        log_info = {
            "exists": True,
            "mtime_iso": "2026-06-01T00:00:00",
            "recent_7d": False,
        }
        gates = run_gates(stats, npz_info, log_info)
        assert gates["gate_gather_log_recent"]["pass"] is False


# ── Tests for build_report ──


class TestBuildReport:
    def test_report_structure(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        npz_info = {
            "exists": True,
            "size_mb": 155.5,
            "mtime": 1000,
            "mtime_iso": "2026-07-14T00:00:00",
        }
        log_info = {
            "exists": True,
            "mtime": 1000,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)

        report = build_report(
            "/path/to/training_data.npz",
            "/path/to/gather.log",
            stats,
            npz_info,
            log_info,
            gates,
        )
        assert report["script_version"] == SCRIPT_VERSION
        assert "timestamp" in report
        assert report["npz_path"] == "/path/to/training_data.npz"
        assert report["gather_log_path"] == "/path/to/gather.log"
        assert "gather_statistics" in report
        assert "gates" in report
        assert "overall_pass" in report
        assert isinstance(report["overall_pass"], bool)

    def test_overall_pass_mirrors_gates(self, sample_gather_log):
        stats = parse_gather_log(sample_gather_log)
        npz_info = {
            "exists": True,
            "size_mb": 155.5,
            "mtime": 1000,
            "mtime_iso": "2026-07-14T00:00:00",
        }
        log_info = {
            "exists": True,
            "mtime": 1000,
            "mtime_iso": "2026-07-14T00:00:00",
            "recent_7d": True,
        }
        gates = run_gates(stats, npz_info, log_info)
        report = build_report("a", "b", stats, npz_info, log_info, gates)
        assert report["overall_pass"] is True

        # Make a gate fail
        gates["gate_npz_exists"]["pass"] = False
        report = build_report("a", "b", stats, npz_info, log_info, gates)
        assert report["overall_pass"] is False


# ── Integration test: end-to-end with synthetic artifacts ──


class TestEndToEnd:
    def test_script_flow_with_synthetic_artifacts(self, tmp_path, sample_gather_log):
        """Run the full flow: parse log, create NPZ, run gates, write report."""
        from scripts.ml_gate_a import main as gate_main
        from unittest.mock import patch

        npz_path = tmp_path / "test_training_data.npz"
        # Create a 12MB NPZ
        with open(npz_path, "wb") as f:
            f.write(b"0" * (12 * 1024 * 1024))

        output_path = tmp_path / "report.json"

        # Simulate CLI call
        test_args = [
            "ml_gate_a",
            "--npz-path",
            str(npz_path),
            "--gather-log",
            sample_gather_log,
            "--output",
            str(output_path),
        ]

        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", test_args):
                gate_main()

        assert output_path.exists()
        with open(output_path) as f:
            report = json.load(f)

        assert report["script_version"] == SCRIPT_VERSION
        assert report["npz_path"] == str(npz_path)
        assert report["gather_log_path"] == sample_gather_log
        assert report["gather_statistics"]["primary_count"] == 116133
        assert report["overall_pass"] is True
        for g_name, g_result in report["gates"].items():
            assert g_result["pass"], f"{g_name} should pass: {g_result['detail']}"

    def test_script_flow_missing_npz(self, tmp_path, sample_gather_log):
        """Test overall_pass is False when NPZ is missing."""
        from scripts.ml_gate_a import main as gate_main
        from unittest.mock import patch

        missing_npz = tmp_path / "nonexistent.npz"
        output_path = tmp_path / "report_missing.json"

        test_args = [
            "ml_gate_a",
            "--npz-path",
            str(missing_npz),
            "--gather-log",
            sample_gather_log,
            "--output",
            str(output_path),
        ]

        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", test_args):
                gate_main()

        with open(output_path) as f:
            report = json.load(f)

        # npz gate should fail, so overall_pass should be False
        assert report["gates"]["gate_npz_exists"]["pass"] is False
        assert report["overall_pass"] is False
