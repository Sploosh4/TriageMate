#!/usr/bin/env python3
"""Validate enriched_cves.json against build_tabular_features expectations."""

import json
import sys
import importlib.util
import numpy as np
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
ML_DIR = BASE / "ml"
DATA_DIR = BASE / "data"

FEATURE_NAMES = [
    "cvss_av",
    "cvss_ac",
    "cvss_pr",
    "cvss_ui",
    "cvss_s",
    "cvss_c",
    "cvss_i",
    "cvss_a",
    "epss_score",
    "patch_available",
    "patch_applied",
    "internet_facing",
    "domain_joined",
    "data_classification",
    "mission_prevalence",
    "public_wellbeing_impact",
    "lateral_reachability",
    "boundary_reachability",
    "downstream_assets",
    "patch_lag_days",
    "exploitdb_has_poc",
    "metasploit_has_payload",
    "threat_intel_pulses",
    "nvd_reference_count",
    "cve_desc_tokens",
    "vulnerability_age_days",
    "vendor_popularity_index",
    "cvss_exploitability_sub",
    "cvss_impact_sub",
    "is_top_25_cwe",
    "is_rce_signature",
    "is_privesc_signature",
    "is_bypass_signature",
    "is_dos_signature",
    "is_traversal_signature",
]


def dynamic_import_build_tabular_features():
    spec = importlib.util.spec_from_file_location(
        "train_xgboost", ML_DIR / "train_xgboost.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_tabular_features


def main():
    enriched_path = ML_DIR / "enriched_cves.json"
    print(f"Loading {enriched_path} ... ", end="", flush=True)
    with open(enriched_path) as f:
        all_cves = json.load(f)
    print(f"{len(all_cves)} total entries.")

    sample = all_cves[:500]
    print(f"Using first {len(sample)} entries.\n")

    print(
        "Importing build_tabular_features from train_xgboost.py ... ",
        end="",
        flush=True,
    )
    build_tabular_features = dynamic_import_build_tabular_features()
    print("OK.\n")

    X = build_tabular_features(sample)
    print(f"Feature matrix shape: {X.shape}\n")

    assert X.shape[1] == 35, f"Expected 35 features, got {X.shape[1]}"

    report_lines = []
    dead_features = []
    suspicious_features = []

    for idx in range(35):
        col = X[:, idx]
        non_zero = int(np.count_nonzero(col))
        mean_val = float(col.mean())
        min_val = float(col.min())
        max_val = float(col.max())
        unique_vals = sorted(set(col.tolist()))
        n_unique = len(unique_vals)

        observations = []
        if non_zero == 0:
            observations.append("DEAD — zero for ALL entries")
            dead_features.append(idx)
        elif non_zero < 10:
            observations.append(f"SUSPICIOUS — only {non_zero} entries non-zero")
            suspicious_features.append(idx)
        if n_unique == 1:
            observations.append(f"Constant value ({unique_vals[0]:.4f})")
            suspicious_features.append(idx)
        if max_val == min_val and max_val == 0:
            observations.append("Zero variance")
        if non_zero == len(sample):
            observations.append("All entries non-zero")

        line = (
            f"  [{idx:2d}] {FEATURE_NAMES[idx]:28s}  "
            f"non_zero={non_zero:5d}/{len(sample):5d}  "
            f"mean={mean_val:.4f}  min={min_val:.4f}  max={max_val:.4f}  "
            f"unique={n_unique:2d}"
        )
        if observations:
            line += "  ⚠  " + "; ".join(observations)
        report_lines.append(line)

    print("Feature-level report (index, name, non-zero count, mean, min, max, unique):")
    print("─" * 120)
    for line in report_lines:
        print(line)

    # ─── Specific checks ─────────────────────────────────────────────────────
    print("\n" + "=" * 120)
    print("SPECIFIC FLAGS")
    print("=" * 120)

    # 1) Dead features
    print(f"\nDead features (zero for ALL {len(sample)} entries): {dead_features}")
    for idx in dead_features:
        print(f"  [{idx}] {FEATURE_NAMES[idx]}")

    # 2) Feature 9 — patch_available
    patch_col = X[:, 9]
    patch_nonzero = int(np.count_nonzero(patch_col))
    print(
        f"\n[d 9] patch_available: {patch_nonzero}/{len(sample)} entries have patch_available==1  ({patch_nonzero / len(sample) * 100:.1f}%)"
    )

    # 3) Feature 8 — epss_score
    epss_col = X[:, 8]
    epss_nonzero = int(np.count_nonzero(epss_col))
    print(
        f"\n[d 8] epss_score:       {epss_nonzero}/{len(sample)} entries non-zero  ({epss_nonzero / len(sample) * 100:.1f}%)"
    )

    # 4) Feature 23 — reference_count
    ref_col = X[:, 23]
    ref_nonzero = int(np.count_nonzero(ref_col))
    ref_unique = len(set(ref_col.tolist()))
    print(
        f"\n[d23] nvd_reference_count: {ref_nonzero}/{len(sample)} entries non-zero  ({ref_nonzero / len(sample) * 100:.1f}%)"
    )
    print(
        f"      Unique values: {ref_unique}, Range: {float(ref_col.min())} – {float(ref_col.max())}"
    )

    # 5) Features 29-34 — CWE/text pattern flags
    print("\nCWE/pattern flags (indices 29-34):")
    for idx in range(29, 35):
        col = X[:, idx]
        nz = int(np.count_nonzero(col))
        print(
            f"  [{idx:2d}] {FEATURE_NAMES[idx]:28s}  non_zero={nz:5d}/{len(sample):5d}  ({nz / len(sample) * 100:.1f}%)"
        )

    # 6) Feature 26 — vendor_popularity_index (should be 0 as per code)
    vp_col = X[:, 26]
    vp_nonzero = int(np.count_nonzero(vp_col))
    print(
        f"\n[d26] vendor_popularity_index: {vp_nonzero}/{len(sample)} non-zero (expected 0)"
    )

    # ─── Overall verdict ─────────────────────────────────────────────────────
    print("\n" + "=" * 120)
    print("VERDICT")
    print("=" * 120)

    # Known accepted dead features (documented limitations)
    ACCEPTED_DEAD_FEATURES = {
        26
    }  # vendor_popularity_index — hardcoded 0.0 in training (no OS data available)
    critical_dead = [i for i in dead_features if i not in ACCEPTED_DEAD_FEATURES]

    failures = []
    warnings = []

    if len(critical_dead) > 0:
        failures.append(
            f"{len(critical_dead)} dead features (all-zero): {[FEATURE_NAMES[i] for i in critical_dead]}"
        )
    if len(dead_features) > 0 and len(critical_dead) == 0:
        warnings.append(
            f"Known accepted dead features: {[FEATURE_NAMES[i] for i in dead_features]} (documented limitation)"
        )

    if patch_nonzero == 0:
        failures.append(
            "patch_available (index 9) is 0 for ALL entries. "
            "The enriched_cves.json has references=[] (emptied during conversion), "
            "so _compute_patch_available() cannot detect patch tags. "
            "FIX: Either (a) preserve NVD references in enriched_cves.json, "
            "or (b) add a 'patch_available' boolean field to the enriched schema "
            "derived from the original nvd_corpus.json patch_available flag, "
            "or (c) modify _compute_patch_available to check a direct flag before falling back to refs."
        )

    if epss_nonzero == 0:
        failures.append(
            "epss_score (index 8) is 0 for ALL entries — EPSS merge failed."
        )
    elif epss_nonzero < len(sample) * 0.5:
        warnings.append(
            f"epss_score only {epss_nonzero / len(sample) * 100:.1f}% non-zero — low EPSS coverage."
        )

    if ref_nonzero == 0:
        failures.append(
            "nvd_reference_count (index 23) is 0 for ALL entries — references not preserved."
        )
    else:
        nz_pct_23 = ref_nonzero / len(sample) * 100
        if nz_pct_23 < 80:
            warnings.append(
                f"nvd_reference_count only {nz_pct_23:.1f}% non-zero — expected most CVEs to have refs."
            )

    cwe_flag_29 = int(np.count_nonzero(X[:, 29]))
    if cwe_flag_29 == 0:
        warnings.append(
            "is_top_25_cwe (index 29) is 0 for ALL entries — no CWE matches (possible but unlikely)."
        )

    pattern_flags_30_34 = [int(np.count_nonzero(X[:, i])) for i in range(30, 35)]
    if sum(pattern_flags_30_34) == 0:
        warnings.append(
            "All description-pattern flags (indices 30-34) are 0 — no RCE/PrivEsc/Bypass/DoS/Traversal matches in descriptions."
        )

    if failures:
        verdict = "FAIL"
    elif warnings:
        verdict = "WARN"
    else:
        verdict = "PASS"

    print(f"\n  Verdict: {verdict}")
    if failures:
        print(f"\n  Failures ({len(failures)}):")
        for f in failures:
            print(f"    ✗ {f}")
    if warnings:
        print(f"\n  Warnings ({len(warnings)}):")
        for w in warnings:
            print(f"    ⚠ {w}")

    if verdict == "FAIL" and patch_nonzero == 0:
        print("""
FIX for patch_available dead feature:
─────────────────────────────────────
Root cause: enriched_cves.json stores references=[] for every CVE, but
reference_count retains the original non-zero count. During conversion
from the NVD API response, the actual reference objects (which contain
'tags' fields) were stripped/emptied.

As a result, _compute_patch_available() at train_xgboost.py:687-695
cannot find Patch/Vendor Advisory tags in the empty references list.

Options:
  (A) Preserve full NVD reference objects in enriched_cves.json:
      In fetch_nvd_cves(), store actual reference dicts with tags.

  (B) Add a direct 'patch_available' field to enriched_cves.json
      derived from NVD reference tags at fetch time, then modify
      _compute_patch_available() to check cve.get('patch_available', 0)
      before falling back to scanning references.

  (C) Re-derive patch_available from the original nvd_corpus.json,
      which already has a 'patch_available' boolean field per entry.
""")

    return 0 if verdict in ("PASS", "WARN") else 2


if __name__ == "__main__":
    sys.exit(main())
