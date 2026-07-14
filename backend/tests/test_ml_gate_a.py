"""Tests for ml_gate_a_check.py — ML Gate A evidence and integrity checks.

Uses synthetic fixtures (not real data) to test the validation script
in isolation. Synthetic gather logs are constructed with known patterns
matching the regexes in ml_gate_a_check.py.
"""

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

# Path to the Gate A script
SCRIPT_DIR = Path(__file__).resolve().parent.parent / "scripts"
GATE_A_SCRIPT = SCRIPT_DIR / "ml_gate_a_check.py"


# ─── Synthetic Fixture Builders ──────────────────────────────────────────


def make_synthetic_npz(path: Path, n_records: int = 100, n_features: int = 419):
    """Create a synthetic NPZ file with random data.

    Matches the shape and key structure of real training_data.npz.
    Feature dimension is arbitrary for testing (matches common 35+384=419 pattern).
    """
    rng = np.random.default_rng(seed=42)
    X = rng.standard_normal((n_records, n_features)).astype(np.float32)
    y = np.zeros(n_records, dtype=np.int32)
    positive_count = min(10, n_records)
    y[:positive_count] = (np.arange(positive_count) % 4) + 1

    dates = np.array(
        [
            f"202{i % 3}-{j % 12 + 1:02d}-{(j * 7) % 28 + 1:02d}"
            for j, i in enumerate(range(n_records))
        ],
        dtype=str,
    )
    cve_ids = np.array([f"CVE-2024-{1000 + i}" for i in range(n_records)], dtype=str)

    # Feature names: 35 tabular + 384 sbert
    tabular_names = [f"feat_{i}" for i in range(35)]
    sbert_names = [f"sbert_{i}" for i in range(n_features - 35)]
    feature_names = np.array(tabular_names + sbert_names, dtype=str)

    np.savez_compressed(
        path, X=X, y=y, dates=dates, cve_ids=cve_ids, feature_names=feature_names
    )


def make_gather_log(
    path: Path,
    obs_window: int = 227,
    primary_count: int = 100,
    prospective_count: int = 20,
    censored_count: int = 15,
    splits: list | None = None,
    final_pos_numerator: int = 10,
    final_pos_denominator: int = 100,
):
    """Create a synthetic gather log with the evidence patterns Gate A expects.

    Args:
        splits: list of (name, records, kev_positive, pct) tuples.
    """
    if splits is None:
        splits = [
            ("Train", 60, 6, 10.0),
            ("Val", 20, 2, 10.0),
            ("Test", 20, 2, 10.0),
        ]

    lines = [
        "=" * 60,
        "PHASE 1: GATHER DATA",
        "=" * 60,
        "",
        "  enriched_cves.json found — skipping NVD/EPSS/KEV fetch.",
        "  Loading enriched CVEs from enriched_cves.json ... 85000 records.",
        "",
        "  KEV observation window: {} days (median lag from {} KEV entries)".format(
            obs_window, 1200
        ),
        f"  Censored negatives: {censored_count:,} (label-0 CVEs published after ...).",
        f"  Primary cohort: {primary_count:,} CVEs ({primary_count / (primary_count + prospective_count):.1%} of pre-filter).",
        f"  Prospective cohort: {prospective_count:,} CVEs (newer than the observation cutoff).",
    ]

    for name, records, kev_pos, pct in splits:
        lines.append(
            f"  {name} set: {records:,} records, {kev_pos:,} KEV-positive ({pct:.2f}%)"
        )

    lines.append(
        f"  Final positive rate (any KEV): {final_pos_numerator}/{final_pos_denominator} ({final_pos_numerator / final_pos_denominator:.1%})"
    )

    lines.append("")
    lines.append("=" * 60)
    lines.append("DATA QUALITY REPORT (multi-window KEV)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Total CVEs:           {primary_count:,}")
    lines.append(
        f"  In KEV (label>0):     {final_pos_numerator:,}  ({final_pos_numerator / primary_count:.3%})"
    )

    path.write_text("\n".join(lines) + "\n")


# ─── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def valid_npz(tmp_path):
    """Create a valid synthetic NPZ and return its path."""
    path = tmp_path / "training_data.npz"
    make_synthetic_npz(path)
    return path


@pytest.fixture
def valid_log(tmp_path):
    """Create a valid synthetic gather log and return its path."""
    path = tmp_path / "gather.log"
    make_gather_log(path)
    return path


@pytest.fixture
def valid_output(tmp_path):
    """Return a path for the output JSON."""
    return tmp_path / "gate_a_report.json"


# ─── Helper ────────────────────────────────────────────────────────────────


def run_gate_a(
    npz_path: Path, log_path: Path, output_path: Path
) -> subprocess.CompletedProcess:
    """Run the Gate A script as a subprocess and return the result."""
    return subprocess.run(
        [
            sys.executable,
            str(GATE_A_SCRIPT),
            "--npz-path",
            str(npz_path),
            "--gather-log",
            str(log_path),
            "--output-path",
            str(output_path),
        ],
        capture_output=True,
        text=True,
    )


# ─── Tests ─────────────────────────────────────────────────────────────────


class TestGateAValidInputs:
    """Tests with valid synthetic inputs."""

    def test_valid_inputs_exit_zero(self, valid_npz, valid_log, valid_output):
        """Valid NPZ and gather log should exit with code 0."""
        result = run_gate_a(valid_npz, valid_log, valid_output)
        assert result.returncode == 0, (
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert valid_output.exists()

    def test_output_json_has_required_keys(self, valid_npz, valid_log, valid_output):
        """Output JSON should contain all required top-level keys."""
        run_gate_a(valid_npz, valid_log, valid_output)
        with open(valid_output) as f:
            report = json.load(f)

        assert "script_version" in report
        assert "timestamp" in report
        assert "npz_path" in report
        assert "gather_log_path" in report
        assert "output_path" in report
        assert "errors" in report
        assert "npz_metadata" in report
        assert "gather_log_parsed" in report
        assert "warnings" in report
        assert "exit_code" in report

    def test_npz_metadata_contains_all_fields(self, valid_npz, valid_log, valid_output):
        """NPZ metadata dict should have all expected fields."""
        run_gate_a(valid_npz, valid_log, valid_output)
        with open(valid_output) as f:
            report = json.load(f)

        meta = report["npz_metadata"]
        assert meta["file_size_bytes"] > 0
        assert meta["last_modified_iso"] is not None
        assert len(meta["artifact_sha256"]) == 64
        assert meta["num_records"] == 100
        assert meta["positive_count"] == 10
        assert meta["feature_dimension"] == 419
        assert meta["date_range_min"] is not None
        assert meta["date_range_max"] is not None
        assert meta["feature_name_count"] == 419
        assert meta["feature_name_fingerprint"] is not None
        assert len(meta["feature_name_fingerprint"]) == 64

    def test_gather_log_parsed_contains_splits(
        self, valid_npz, valid_log, valid_output
    ):
        """Gather log parsed data should contain split records."""
        run_gate_a(valid_npz, valid_log, valid_output)
        with open(valid_output) as f:
            report = json.load(f)

        parsed = report["gather_log_parsed"]
        assert parsed["observation_window_days"] == 227
        assert parsed["primary_cohort_count"] == 100
        assert parsed["prospective_cohort_count"] == 20
        assert parsed["censored_negatives_count"] == 15
        assert len(parsed["splits"]) == 3
        assert parsed["final_positive_rate_numerator"] == 10
        assert parsed["final_positive_rate_denominator"] == 100

        split_names = {s["name"] for s in parsed["splits"]}
        assert split_names == {"Train", "Val", "Test"}

    def test_feature_name_fingerprint_is_stable(
        self, valid_npz, valid_log, valid_output
    ):
        """Same feature names should produce same fingerprint."""
        run_gate_a(valid_npz, valid_log, valid_output)
        with open(valid_output) as f:
            report1 = json.load(f)

        # Create another NPZ with same feature names
        npz2 = valid_npz.parent / "training_data_v2.npz"
        make_synthetic_npz(npz2)
        log2 = valid_log.parent / "gather_v2.log"
        make_gather_log(log2)
        out2 = valid_log.parent / "gate_a_report_v2.json"
        run_gate_a(npz2, log2, out2)

        with open(out2) as f:
            report2 = json.load(f)

        assert (
            report1["npz_metadata"]["feature_name_fingerprint"]
            == report2["npz_metadata"]["feature_name_fingerprint"]
        )


class TestGateAErrorHandling:
    """Tests for error conditions."""

    def test_missing_npz_exits_one(self, valid_log, valid_output):
        """Missing NPZ file should exit with code 1."""
        bad_npz = valid_log.parent / "does_not_exist.npz"
        result = run_gate_a(bad_npz, valid_log, valid_output)
        assert result.returncode == 1

    def test_missing_log_exits_one(self, valid_npz, valid_output):
        """Missing gather log should exit with code 1."""
        bad_log = valid_npz.parent / "does_not_exist.log"
        result = run_gate_a(valid_npz, bad_log, valid_output)
        assert result.returncode == 1

    def test_both_missing_produces_errors_in_output(self, valid_output):
        """Both missing files should include errors in output JSON."""
        bad_npz = valid_output.parent / "missing.npz"
        bad_log = valid_output.parent / "missing.log"
        result = run_gate_a(bad_npz, bad_log, valid_output)
        assert result.returncode == 1
        with open(valid_output) as f:
            report = json.load(f)
        assert len(report["errors"]) == 2

    def test_missing_cli_args_fails(self):
        """Running without required CLI args should fail with exit 2."""
        result = subprocess.run(
            [sys.executable, str(GATE_A_SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2  # argparse exits with 2 on missing required args


class TestGateASingleClassSplit:
    """Tests for single-class split detection."""

    def test_single_class_val_produces_warning(self, tmp_path):
        """A val set with 0 KEV-positives should produce a warning and exit 1."""
        npz_path = tmp_path / "training_data.npz"
        log_path = tmp_path / "gather_single_class.log"
        out_path = tmp_path / "gate_a_report.json"

        make_synthetic_npz(npz_path)
        # Val has 0 KEV-positives → single-class
        make_gather_log(
            log_path,
            splits=[
                ("Train", 60, 8, 13.33),
                ("Val", 20, 0, 0.0),
                ("Test", 20, 2, 10.0),
            ],
        )

        result = run_gate_a(npz_path, log_path, out_path)
        assert result.returncode == 1

        with open(out_path) as f:
            report = json.load(f)
        assert len(report["warnings"]) > 0
        warning_text = report["warnings"][0]
        assert "Single-class" in warning_text
        assert "Val" in warning_text
        assert "0 KEV-positive" in warning_text

    def test_single_class_train_produces_warning(self, tmp_path):
        """A train set with 0 negatives should produce a warning and exit 1."""
        npz_path = tmp_path / "training_data.npz"
        log_path = tmp_path / "gather_single_class_train.log"
        out_path = tmp_path / "gate_a_report.json"

        make_synthetic_npz(npz_path)
        # Train has all KEV-positives → single-class (no negatives)
        make_gather_log(
            log_path,
            splits=[
                ("Train", 60, 60, 100.0),
                ("Val", 20, 2, 10.0),
                ("Test", 20, 2, 10.0),
            ],
        )

        result = run_gate_a(npz_path, log_path, out_path)
        assert result.returncode == 1

        with open(out_path) as f:
            report = json.load(f)
        assert len(report["warnings"]) > 0
        assert any("Single-class" in w for w in report["warnings"])


class TestGateAMissingLogLines:
    """Tests for missing evidence lines in the log."""

    def test_missing_observation_window_produces_warning(self, tmp_path):
        """A log missing the observation window line should warn and exit 1."""
        npz_path = tmp_path / "training_data.npz"
        log_path = tmp_path / "gather_no_obs.log"
        out_path = tmp_path / "gate_a_report.json"

        make_synthetic_npz(npz_path)
        # Write a log without the obs window line
        lines = [
            "PHASE 1: GATHER DATA",
            "  Primary cohort: 80000 CVEs",
            "  Prospective cohort: 20000 CVEs",
            "  Train set: 50000 records, 4500 KEV-positive (9.00%)",
            "  Val set: 15000 records, 2000 KEV-positive (13.33%)",
            "  Test set: 15000 records, 1500 KEV-positive (10.00%)",
            "  Final positive rate (any KEV): 8000/80000 (10.0%)",
        ]
        log_path.write_text("\n".join(lines) + "\n")

        result = run_gate_a(npz_path, log_path, out_path)
        assert result.returncode == 1

        with open(out_path) as f:
            report = json.load(f)
        warnings_text = " ".join(report["warnings"])
        assert "observation window" in warnings_text.lower()


class TestGateAArtifactIntegrity:
    """Tests for NPZ schema and NPZ/log consistency."""

    def test_corrupt_npz_exits_one(self, tmp_path, valid_log):
        npz_path = tmp_path / "corrupt.npz"
        output_path = tmp_path / "report.json"
        npz_path.write_bytes(b"not-an-npz")

        result = run_gate_a(npz_path, valid_log, output_path)

        assert result.returncode == 1
        report = json.loads(output_path.read_text())
        assert "Failed to load NPZ" in report["errors"][0]

    def test_missing_required_array_exits_one(self, tmp_path, valid_log):
        npz_path = tmp_path / "missing-arrays.npz"
        output_path = tmp_path / "report.json"
        np.savez_compressed(npz_path, X=np.zeros((100, 4), dtype=np.float32))

        result = run_gate_a(npz_path, valid_log, output_path)

        assert result.returncode == 1
        report = json.loads(output_path.read_text())
        assert "missing required arrays" in report["errors"][0]

    def test_misaligned_rows_exit_one(self, tmp_path, valid_log):
        npz_path = tmp_path / "misaligned.npz"
        output_path = tmp_path / "report.json"
        np.savez_compressed(
            npz_path,
            X=np.zeros((100, 4), dtype=np.float32),
            y=np.zeros(99, dtype=np.int32),
            dates=np.array(["2020-01-01"] * 100),
            cve_ids=np.array([f"CVE-2020-{i}" for i in range(100)]),
            feature_names=np.array([f"feature-{i}" for i in range(4)]),
        )

        result = run_gate_a(npz_path, valid_log, output_path)

        assert result.returncode == 1
        report = json.loads(output_path.read_text())
        assert "row counts do not align" in report["errors"][0]

    def test_feature_names_must_match_x_width(self, tmp_path, valid_log):
        npz_path = tmp_path / "bad-features.npz"
        output_path = tmp_path / "report.json"
        np.savez_compressed(
            npz_path,
            X=np.zeros((100, 4), dtype=np.float32),
            y=np.zeros(100, dtype=np.int32),
            dates=np.array(["2020-01-01"] * 100),
            cve_ids=np.array([f"CVE-2020-{i}" for i in range(100)]),
            feature_names=np.array(["only-one"]),
        )

        result = run_gate_a(npz_path, valid_log, output_path)

        assert result.returncode == 1
        report = json.loads(output_path.read_text())
        assert "feature_names count" in report["errors"][0]

    def test_npz_and_log_counts_must_match(self, tmp_path, valid_npz, valid_output):
        log_path = tmp_path / "mismatch.log"
        make_gather_log(
            log_path,
            primary_count=101,
            final_pos_denominator=101,
        )

        result = run_gate_a(valid_npz, log_path, valid_output)

        assert result.returncode == 1
        report = json.loads(valid_output.read_text())
        assert any("mismatch" in warning for warning in report["warnings"])


class TestGateACLI:
    """Tests for CLI argument handling."""

    def test_help_flag(self):
        """--help should exit with 0."""
        result = subprocess.run(
            [sys.executable, str(GATE_A_SCRIPT), "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "usage:" in result.stdout.lower() or "usage:" in result.stderr.lower()

    def test_missing_all_args_fails(self):
        """Running without any arguments should fail with exit 2."""
        result = subprocess.run(
            [sys.executable, str(GATE_A_SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_missing_one_arg_fails(self, valid_npz):
        """Running with only --npz-path should fail."""
        result = subprocess.run(
            [sys.executable, str(GATE_A_SCRIPT), "--npz-path", str(valid_npz)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_script_module_accessible(self):
        """The script should be accessible as a Python module."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.ml_gate_a_check",
                "--help",
            ],
            capture_output=True,
            text=True,
            cwd=str(SCRIPT_DIR.parent),  # backend/
        )
        assert result.returncode == 0
