"""Check benchmark regression against stored baseline.
Called by CI pipeline after benchmarks run.
"""

import json
import sys
from pathlib import Path

BASELINE_FILE = (
    Path(__file__).resolve().parent.parent / "tests" / "benchmark_baseline.json"
)
REGRESSION_THRESHOLD_PCT = 10.0  # Fail if any benchmark is 10%+ slower


def check_regression(current_file: str = "benchmark_results.json") -> bool:
    """Compare current benchmark results against baseline.

    Returns True if all pass, False if any regression detected.
    """
    baseline_path = BASELINE_FILE

    if not baseline_path.exists():
        print(f"NO BASELINE FOUND at {baseline_path}. Run 'just bench' first.")
        return False

    with open(baseline_path) as f:
        baseline = json.load(f)

    current_path = Path(current_file)
    if not current_path.exists():
        print(f"Current results not found at {current_path}")
        return False

    with open(current_path) as f:
        current = json.load(f)

    all_pass = True
    for bench_name, baseline_stats in baseline.get("benchmarks", {}).items():
        if bench_name in current.get("benchmarks", {}):
            current_stats = current["benchmarks"][bench_name]
            baseline_mean = baseline_stats["stats"]["mean"]
            current_mean = current_stats["stats"]["mean"]

            if baseline_mean > 0:
                regression_pct = ((current_mean - baseline_mean) / baseline_mean) * 100
                status = "PASS" if regression_pct < REGRESSION_THRESHOLD_PCT else "FAIL"

                if status == "FAIL":
                    all_pass = False

                print(
                    f"{status}: {bench_name} "
                    f"{baseline_mean * 1000:.2f}ms -> {current_mean * 1000:.2f}ms "
                    f"({regression_pct:+.1f}%)"
                )

    return all_pass


if __name__ == "__main__":
    success = check_regression()
    sys.exit(0 if success else 1)
