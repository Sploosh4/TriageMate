"""Performance benchmarks for critical TriageMate code paths.
Run with: python -m pytest tests/test_benchmark.py --benchmark-save=baseline
Compare with: python -m pytest tests/test_benchmark.py --benchmark-compare=baseline --benchmark-compare-fail=min:10%
"""

import pytest

try:
    pytest.importorskip("pytest_benchmark")
    _BENCHMARK_AVAILABLE = True
except ImportError:
    _BENCHMARK_AVAILABLE = False

from scoring import calculate_final_score


pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.skipif(
        not _BENCHMARK_AVAILABLE,
        reason="pytest-benchmark not installed — run: pip install pytest-benchmark",
    ),
]


class TestScoringBenchmarks:
    """Benchmark the scoring calculator — the most frequently called function."""

    def test_benchmark_scoring_calculation(self, benchmark):
        """Time 1000 iterations of calculate_final_score with realistic data."""

        def run_scoring():
            return calculate_final_score(
                cvss_score=9.8,
                epss_score=0.95,
                mission_prevalence="Core",
                public_wellbeing="Severe",
                data_classification="OFFICIAL Sensitive",
                internet_facing=True,
                patch_available=True,
                patch_applied=False,
                telemetry_threat_score=8.0,
                network_blast_radius=0.7,
                vulnerable_code_loaded=True,
            )

        result = benchmark(run_scoring)
        assert result["total"] > 0
        assert 0 <= result["total"] <= 100

    def test_benchmark_scoring_all_zero(self, benchmark):
        """Time scoring with all minimum inputs."""

        def run_scoring():
            return calculate_final_score(
                cvss_score=0.0,
                epss_score=0.0,
                mission_prevalence="Peripheral",
                public_wellbeing="Minimal",
                data_classification="UNOFFICIAL",
                internet_facing=False,
            )

        result = benchmark(run_scoring)
        # exposure contributes 3 for non-internet-facing assets,
        # so total will be 3, not 0
        assert result["total"] == 3

    def test_benchmark_scoring_all_max(self, benchmark):
        """Time scoring with all maximum inputs."""

        def run_scoring():
            return calculate_final_score(
                cvss_score=10.0,
                epss_score=1.0,
                mission_prevalence="Core",
                public_wellbeing="Severe",
                data_classification="OFFICIAL Sensitive",
                internet_facing=True,
                patch_available=True,
                patch_applied=True,
                tier_1_result={"exploitation_probability": 0.99},
                telemetry_threat_score=10.0,
                network_blast_radius=1.0,
                vulnerable_code_loaded=True,
            )

        result = benchmark(run_scoring)
        assert result["total"] >= 0
