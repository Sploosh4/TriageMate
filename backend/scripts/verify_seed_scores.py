#!/usr/bin/env python3
"""Verify seed data scores match canonical contract.

Loads seed_data.py demo CVEs, runs the scoring pipeline,
and compares calculated scores to the canonical baselines
in test_model_versions.py (hardcoded in routers/models.py).

Usage:
    python -m scripts.verify_seed_scores
"""

import json
import re
import sys
from pathlib import Path


def load_canonical_scores() -> dict:
    """Read canonical scores from routers/models.py.

    Returns dict of {cve_id: expected_score} in seed-data order.
    The canonical baseline is hardcoded in routers/models.py:89.
    """
    models_path = Path(__file__).resolve().parent.parent / "routers" / "models.py"

    with open(models_path) as f:
        content = f.read()

    # Find the baseline_scores list — hardcoded as [98, 91, 73, 66, 58, 44, 26]
    match = re.search(r'"baseline_scores"\s*:\s*\[([^\]]+)\]', content)
    if not match:
        print("ERROR: Could not find baseline_scores in routers/models.py")
        sys.exit(1)

    scores = [int(x.strip()) for x in match.group(1).split(",")]

    if len(scores) != 7:
        print(f"ERROR: Expected 7 baseline scores, got {len(scores)}")
        sys.exit(1)

    # CVEs in seed-data row order (from seed_data.py SEED_ROWS)
    cves = [
        "CVE-2023-34362",
        "CVE-2023-4966",
        "CVE-2023-27350",
        "CVE-2024-1709",
        "CVE-2023-36884",
        "CVE-2023-22515",
        "CVE-2022-47966",
    ]

    return dict(zip(cves, scores))


def run_pipeline_and_get_scores() -> dict:
    """Run the scoring pipeline on seed data.

    Reads seed_data.py demo CVEs, runs calculate_final_score,
    and returns dict of {cve_id: actual_score}.
    """
    # Ensure backend/ is on path
    backend_dir = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(backend_dir))

    from scoring import calculate_final_score
    from seed_data import SEED_ROWS

    scores = {}
    for vuln in SEED_ROWS:
        cve_id = vuln["vulnerability_id"]

        # ── Parse telemetry_json for threat_score ──
        telemetry_threat_score = 0.0
        raw_telemetry = vuln.get("telemetry_json")
        if raw_telemetry:
            try:
                telemetry = (
                    json.loads(raw_telemetry)
                    if isinstance(raw_telemetry, str)
                    else raw_telemetry
                )
                telemetry_threat_score = float(telemetry.get("threat_score", 0.0))
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        # ── Parse network_context_json for blast_radius_score ──
        network_blast_radius = 0.0
        raw_network = vuln.get("network_context_json")
        if raw_network:
            try:
                network_ctx = (
                    json.loads(raw_network)
                    if isinstance(raw_network, str)
                    else raw_network
                )
                network_blast_radius = float(network_ctx.get("blast_radius_score", 0.0))
            except (json.JSONDecodeError, TypeError, ValueError):
                pass

        # ── Derive internet_facing from interface_type ──
        interface_type = str(vuln.get("interface_type", ""))
        internet_facing = "Internet-facing" in interface_type

        # ── Patch status ──
        # All demo CVEs have patches available; none are confirmed applied
        patch_available = True
        patch_applied = False

        # ── Tier 1 result ──
        tier_1_result = None
        tier_1_prob = vuln.get("tier_1_exploitation_prob")
        if tier_1_prob is not None:
            tier_1_result = {"exploitation_probability": float(tier_1_prob)}

        # ── Tier 2 result (no score_adjustment available in seed data) ──
        tier_2_result = None

        # ── EPSS substitution ──
        substituted_epss = None
        if (
            vuln.get("epss_substituted")
            and vuln.get("epss_substituted_value") is not None
        ):
            substituted_epss = float(vuln["epss_substituted_value"])

        # ── Calculate final score ──
        result = calculate_final_score(
            cvss_score=float(vuln.get("cvss_score", 0)),
            epss_score=float(vuln.get("epss_score", 0)),
            mission_prevalence=vuln.get("mission_prevalence", "Support"),
            public_wellbeing=vuln.get("public_wellbeing_impact", "Minimal"),
            data_classification=vuln.get("data_classification", "OFFICIAL"),
            internet_facing=internet_facing,
            patch_available=patch_available,
            patch_applied=patch_applied,
            tier_1_result=tier_1_result,
            tier_2_result=tier_2_result,
            substituted_epss=substituted_epss,
            telemetry_threat_score=telemetry_threat_score,
            network_blast_radius=network_blast_radius,
        )

        scores[cve_id] = result["total"]

    return scores


def verify_seed_scores(tolerance: float = 3.0) -> dict:
    """Compare seed data scores to canonical contract.

    Returns dict with per-CVE results and overall pass/fail.
    """
    canonical = load_canonical_scores()
    actual = run_pipeline_and_get_scores()

    results = {}
    all_pass = True

    print("=" * 60)
    print("Seed Data Score Verification")
    print("=" * 60)
    print(
        f"{'CVE ID':<22} {'Expected':<10} {'Actual':<10} {'Delta':<10} {'Status':<10}"
    )
    print("-" * 60)

    for cve_id in sorted(canonical.keys()):
        expected = canonical.get(cve_id)
        actual_score = actual.get(cve_id)

        if expected is None or actual_score is None:
            print(f"{cve_id:<22} {'N/A':<10} {'N/A':<10} {'N/A':<10} {'SKIP':<10}")
            continue

        delta = abs(actual_score - expected)
        passed = delta <= tolerance
        if not passed:
            all_pass = False

        status = "PASS" if passed else "FAIL"
        print(
            f"{cve_id:<22} {expected:<10} {actual_score:<10} {delta:<10.1f} {status:<10}"
        )

        results[cve_id] = {
            "expected": expected,
            "actual": actual_score,
            "delta": round(delta, 1),
            "pass": passed,
        }

    print("-" * 60)
    if all_pass:
        print("RESULT: All seed scores match canonical contract \u2713")
    else:
        print("RESULT: Some seed scores drifted from canonical contract \u2717")
        print("Check if scoring changes in this sprint affected expected values.")

    print("=" * 60)

    return {"results": results, "all_pass": all_pass}


def main():
    result = verify_seed_scores()
    if not result["all_pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
