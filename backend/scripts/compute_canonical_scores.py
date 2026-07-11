#!/usr/bin/env python3
"""
Compute canonical scores from seed data using the live scoring pipeline.

Reads all 7 demo rows from seed_data.py, calls calculate_final_score()
with every available parameter (including vulnerable_code_loaded),
and compares results against all conflicting score contracts.

Usage:
    python -m scripts.compute_canonical_scores
"""

import json
import sys
from pathlib import Path

# Ensure backend/ is on path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from scoring import calculate_final_score  # noqa: E402 — sys.path.insert above required for local script
from seed_data import SEED_ROWS  # noqa: E402


# ── The 4 conflicting score contracts ──────────────────────────────────────

CVE_ORDER = [
    "CVE-2023-34362",  # 0: MOVEit Transfer SQLi
    "CVE-2023-4966",  # 1: Citrix Bleed
    "CVE-2023-27350",  # 2: PaperCut Auth Bypass
    "CVE-2024-1709",  # 3: ConnectWise ScreenConnect
    "CVE-2023-36884",  # 4: Office/Windows Search RCE
    "CVE-2023-22515",  # 5: Confluence Broken Access Control
    "CVE-2022-47966",  # 6: ManageEngine SAML RCE
]

# Contract A: Stored in seed_data.py priority_score field
STORED_SCORES = {row["vulnerability_id"]: row["priority_score"] for row in SEED_ROWS}

# Contract B: Hardcoded in routers/models.py baseline_scores (CI gate)
CI_BASELINE = {
    cve: score for cve, score in zip(CVE_ORDER, [99, 97, 74, 91, 82, 97, 80])
}

# Contract C: Referenced in system prompt guideline 6
PROMPT_BASELINE = {
    cve: score for cve, score in zip(CVE_ORDER, [94, 87, 71, 55, 63, 41, 22])
}


def parse_telemetry_threat_score(vuln: dict) -> float:
    """Parse threat_score from telemetry_json."""
    raw = vuln.get("telemetry_json")
    if not raw:
        return 0.0
    try:
        telemetry = json.loads(raw) if isinstance(raw, str) else raw
        return float(telemetry.get("threat_score", 0.0))
    except (json.JSONDecodeError, TypeError, ValueError):
        return 0.0


def parse_network_blast_radius(vuln: dict) -> float:
    """Parse blast_radius_score from network_context_json."""
    raw = vuln.get("network_context_json")
    if not raw:
        return 0.0
    try:
        ctx = json.loads(raw) if isinstance(raw, str) else raw
        return float(ctx.get("blast_radius_score", 0.0))
    except (json.JSONDecodeError, TypeError, ValueError):
        return 0.0


def parse_vulnerable_code_loaded(vuln: dict) -> bool | None:
    """Parse is_loaded from telemetry_json → process_evidence."""
    raw = vuln.get("telemetry_json")
    if not raw:
        return None
    try:
        telemetry = json.loads(raw) if isinstance(raw, str) else raw
        process_evidence = telemetry.get("process_evidence", {})
        is_loaded = process_evidence.get("is_loaded")
        if is_loaded is None:
            return None
        return bool(is_loaded)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def compute_all_scores() -> dict:
    """Compute scores for all 7 seed rows using the live pipeline.

    Returns dict keyed by CVE ID, containing:
        computed_total, band, context_multiplier, dimensions dict,
        and all extracted inputs for transparency.
    """
    results = {}

    for vuln in SEED_ROWS:
        cve_id = vuln["vulnerability_id"]

        # ── Extract all input parameters ──
        cvss_score = float(vuln.get("cvss_score", 0))
        epss_score = float(vuln.get("epss_score", 0))
        mission_prevalence = vuln.get("mission_prevalence", "Support")
        public_wellbeing = vuln.get("public_wellbeing_impact", "Minimal")
        data_classification = vuln.get("data_classification", "OFFICIAL")

        interface_type = str(vuln.get("interface_type", ""))
        internet_facing = False
        if "Internet-facing" in interface_type or "internet" in interface_type.lower():
            internet_facing = True

        patch_available = True
        patch_applied = False

        # Tier 1 result (ML exploitation probability)
        tier_1_result = None
        tier_1_prob = vuln.get("tier_1_exploitation_prob")
        if tier_1_prob is not None:
            tier_1_result = {"exploitation_probability": float(tier_1_prob)}

        # Tier 2 result — not available in seed data (needs LLM call)
        tier_2_result = None

        # EPSS substitution
        substituted_epss = None
        if (
            vuln.get("epss_substituted")
            and vuln.get("epss_substituted_value") is not None
        ):
            substituted_epss = float(vuln["epss_substituted_value"])

        telemetry_threat_score = parse_telemetry_threat_score(vuln)
        network_blast_radius = parse_network_blast_radius(vuln)
        vulnerable_code_loaded = parse_vulnerable_code_loaded(vuln)

        # ── Call the scoring engine ──
        result = calculate_final_score(
            cvss_score=cvss_score,
            epss_score=epss_score,
            mission_prevalence=mission_prevalence,
            public_wellbeing=public_wellbeing,
            data_classification=data_classification,
            internet_facing=internet_facing,
            patch_available=patch_available,
            patch_applied=patch_applied,
            tier_1_result=tier_1_result,
            tier_2_result=tier_2_result,
            substituted_epss=substituted_epss,
            telemetry_threat_score=telemetry_threat_score,
            network_blast_radius=network_blast_radius,
            vulnerable_code_loaded=vulnerable_code_loaded,
        )

        results[cve_id] = {
            "computed_total": result["total"],
            "band": result["band"],
            "context_multiplier": result["context_multiplier"],
            "dimensions": result["dimensions"],
            # Input parameters for debugging
            "inputs": {
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "mission_prevalence": mission_prevalence,
                "public_wellbeing": public_wellbeing,
                "data_classification": data_classification,
                "internet_facing": internet_facing,
                "telemetry_threat_score": telemetry_threat_score,
                "network_blast_radius": network_blast_radius,
                "vulnerable_code_loaded": vulnerable_code_loaded,
                "substituted_epss": substituted_epss,
                "tier_1_prob": tier_1_prob,
            },
        }

    return results


def print_comparison_table(computed: dict):
    """Print comparison of all 4 score contracts."""
    header = (
        f"{'CVE':<22} {'Stored':>7} {'Computed':>9} {'CI_Baseline':>12} "
        f"{'Prompt':>7} {'Diff_Stored':>11} {'Diff_CI':>9}"
    )
    sep = "-" * len(header)

    print("=" * len(header))
    print("CANONICAL SCORE COMPARISON — Phase 0, Sprint 23")
    print("=" * len(header))
    print()
    print("Contracts comparison:")
    print(header)
    print(sep)

    for cve in CVE_ORDER:
        c = computed[cve]
        stored = STORED_SCORES.get(cve, "N/A")
        computed_val = c["computed_total"]
        ci_base = CI_BASELINE.get(cve, "N/A")
        prompt_base = PROMPT_BASELINE.get(cve, "N/A")

        if stored != "N/A":
            diff_stored = computed_val - stored
            diff_stored_str = f"{diff_stored:+d}"
        else:
            diff_stored_str = "N/A"

        if ci_base != "N/A":
            diff_ci = computed_val - ci_base
            diff_ci_str = f"{diff_ci:+d}"
        else:
            diff_ci_str = "N/A"

        print(
            f"{cve:<22} {stored:>7} {computed_val:>9} {ci_base:>12} "
            f"{prompt_base:>7} {diff_stored_str:>11} {diff_ci_str:>9}"
        )

    print(sep)
    print()

    # ── Per-CVE dimension breakdown ──
    print("=" * 80)
    print("DIMENSION BREAKDOWN PER CVE")
    print("=" * 80)
    print()

    for cve in CVE_ORDER:
        c = computed[cve]
        dims = c["dimensions"]
        inputs = c["inputs"]
        print(
            f"{cve}  →  computed={c['computed_total']}  band={c['band']}  "
            f"context_mult={c['context_multiplier']}"
        )
        print(
            f"    Stored priority_score = {STORED_SCORES[cve]}, CI baseline = {CI_BASELINE[cve]}"
        )
        print(
            f"    Inputs: cvss={inputs['cvss_score']}, epss={inputs['epss_score']}, "
            f"mission={inputs['mission_prevalence']}, wellbeing={inputs['public_wellbeing']}, "
            f"data_class={inputs['data_classification']}, internet={inputs['internet_facing']}"
        )
        print(
            f"    Telemetry: threat_score={inputs['telemetry_threat_score']:.4f}, "
            f"blast_radius={inputs['network_blast_radius']:.4f}, "
            f"code_loaded={inputs['vulnerable_code_loaded']}"
        )
        print(
            f"    Substituted EPSS={inputs['substituted_epss']}, "
            f"Tier 1 prob={inputs['tier_1_prob']}"
        )
        print(
            f"    Dimensions: cvss={dims['cvss']}, epss={dims['epss']}, "
            f"criticality={dims['criticality']}, exposure={dims['exposure']}, "
            f"patch={dims['patch']}, ml_exploitation={dims['ml_exploitation']}, "
            f"security_context={dims['security_context']}"
        )
        print()


def print_summary(computed: dict):
    """Print summary of findings and recommended canonical contract."""
    print("=" * 80)
    print("SUMMARY AND ANALYSIS")
    print("=" * 80)
    print()

    print("--- Agreements ---")
    for cve in CVE_ORDER:
        c = computed[cve]
        stored = STORED_SCORES[cve]
        ci_base = CI_BASELINE[cve]
        prompt_base = PROMPT_BASELINE[cve]

        matches_stored = c["computed_total"] == stored
        matches_ci = c["computed_total"] == ci_base
        matches_prompt = c["computed_total"] == prompt_base

        agreements = []
        if matches_stored:
            agreements.append("Stored")
        if matches_ci:
            agreements.append("CI_Baseline")
        if matches_prompt:
            agreements.append("Prompt")

        if agreements:
            print(
                f"  {cve}: computed={c['computed_total']} — matches {', '.join(agreements)}"
            )
        else:
            print(
                f"  {cve}: computed={c['computed_total']} — matches NONE "
                f"(stored={stored}, ci={ci_base}, prompt={prompt_base})"
            )

    print()
    print("--- Discrepancy Analysis ---")
    print()

    for cve in CVE_ORDER:
        c = computed[cve]
        stored = STORED_SCORES[cve]
        ci_base = CI_BASELINE[cve]

        if c["computed_total"] == stored and c["computed_total"] == ci_base:
            print(f"  {cve}: ✓ All aligned at {c['computed_total']}")
            continue

        issues = []
        if c["computed_total"] != stored:
            issues.append(f"computed({c['computed_total']}) ≠ stored({stored})")
        if c["computed_total"] != ci_base:
            issues.append(f"computed({c['computed_total']}) ≠ CI_baseline({ci_base})")

        print(f"  {cve}: {'; '.join(issues)}")

        # Root cause analysis
        dims = c["dimensions"]
        inputs = c["inputs"]
        raw_total_before_mult = (
            dims["cvss"]
            + dims["epss"]
            + dims["criticality"]
            + dims["exposure"]
            + dims["patch"]
            + dims["ml_exploitation"]
        )
        print(
            f"    Raw dim sum={raw_total_before_mult}, "
            f"mult={c['context_multiplier']}, "
            f"after_mult={round(raw_total_before_mult * c['context_multiplier'])}"
        )

        # Check if the stored score_calc suggests old additive security_context
        print(
            f"    Context multiplier logic: "
            f"telemetry_active={inputs['telemetry_threat_score'] >= 3.0}, "
            f"code_loaded={inputs['vulnerable_code_loaded']}"
        )

        if c["context_multiplier"] == 1.0:
            print(
                f"    → Neutral (1.00x) because telemetry_active=False "
                f"(threat_score={inputs['telemetry_threat_score']:.4f} < 3.0 threshold)"
            )
        elif c["context_multiplier"] == 1.10:
            print("    → Partial evidence (1.10x) — telemetry or code_loaded")
        elif c["context_multiplier"] == 1.20:
            print("    → Active threat (1.20x) — telemetry AND code_loaded")

        # Compare with stored dimension breakdown
        print(
            f"    Stored dimensions: cvss={vuln_row(cve).get('cvss_contribution')}, "
            f"epss={vuln_row(cve).get('epss_contribution')}, "
            f"criticality={vuln_row(cve).get('asset_criticality_contribution')}, "
            f"exposure={vuln_row(cve).get('exposure_contribution')}, "
            f"patch={vuln_row(cve).get('patch_remediation_contribution')}, "
            f"ml={vuln_row(cve).get('ml_exploitation_contribution')}, "
            f"secctx={vuln_row(cve).get('security_context_contribution')}"
        )
        print()

    print("--- Root Cause Summary ---")
    print()
    print("The main discrepancies arise from:")
    print("  1. Sprint 21 change: additive Security Context dimension")
    print(
        "     replaced by proportional context multiplier (1.20/1.10/1.00/0.85/0.70)."
    )
    print(
        "     The stored seed_data.py priority_score was NOT updated after this change."
    )
    print("  2. The CI baseline in routers/models.py is a manually-set snapshot that")
    print("     has drifted from both the stored values AND current pipeline output.")
    print("  3. The Prompt guideline 6 values appear to be aspirational targets,")
    print("     not the actual computed scores.")
    print()

    print("--- Recommended Canonical Contract ---")
    print()
    computed_list = [computed[cve]["computed_total"] for cve in CVE_ORDER]
    print("  The pipeline-computed scores are the single source of truth:")
    print(f"  {computed_list}")
    print()
    print("  These should replace:")
    print(
        f"    - seed_data.py priority_score (currently {[STORED_SCORES[cve] for cve in CVE_ORDER]})"
    )
    print(
        f"    - routers/models.py baseline_scores (currently {[CI_BASELINE[cve] for cve in CVE_ORDER]})"
    )
    print("    - Any hardcoded prompt constraints")
    print()


def vuln_row(cve_id: str) -> dict:
    """Get the seed_data row for a CVE ID."""
    for row in SEED_ROWS:
        if row["vulnerability_id"] == cve_id:
            return row
    return {}


def main():
    computed = compute_all_scores()
    print_comparison_table(computed)
    print_summary(computed)

    # Print just the canonical scores for easy copying
    print("=" * 80)
    print("CANONICAL SCORES (computed by pipeline)")
    print("=" * 80)
    for cve in CVE_ORDER:
        c = computed[cve]
        print(f"  {cve:<22} → {c['computed_total']:>3} ({c['band']})")


if __name__ == "__main__":
    main()
