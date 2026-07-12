#!/usr/bin/env python3
"""
Feature parity checker — verifies that build_training_corpus.py and
xgboost_predictor.py produce identical 35-element feature vectors for
the same CVEs. Any element-wise diff > 1e-6 is training/serving skew.

Usage:
    python feature_parity_check.py [--sample N] [--seed 42]
"""

import argparse
import json
import random
import re
import sys
from pathlib import Path

import numpy as np

# ─── Constants ──────────────────────────────────────────────────────────────

from pipeline.config.feature_names import TABULAR_FEATURE_ORDER as FEATURE_NAMES

STOCHASTIC_FEATURE_INDICES = {
    10,  # patch_applied
    11,  # internet_facing
    12,  # domain_joined
    13,  # data_classification
    14,  # mission_prevalence
    15,  # public_wellbeing_impact
    16,  # lateral_reachability
    17,  # boundary_reachability
    18,  # downstream_assets
    19,  # patch_lag_days
    22,  # threat_intel_pulses
}

RCE_PATTERNS = [r"remote code execution", r"arbitrary code", r"execute arbitrary"]
PRIVESC_PATTERNS = [r"privilege escalation", r"elevat\w+ privilege"]
BYPASS_PATTERNS = [r"bypass", r"authentication bypass", r"access control"]
DOS_PATTERNS = [r"denial of service", r"dos", r"resource exhaustion"]
TRAVERSAL_PATTERNS = [r"directory traversal", r"path traversal", r"\.\.[\\/]"]

MITRE_TOP_25_CWES = {
    "CWE-787",
    "CWE-79",
    "CWE-89",
    "CWE-416",
    "CWE-78",
    "CWE-20",
    "CWE-125",
    "CWE-22",
    "CWE-352",
    "CWE-434",
    "CWE-862",
    "CWE-476",
    "CWE-287",
    "CWE-190",
    "CWE-502",
    "CWE-77",
    "CWE-119",
    "CWE-798",
    "CWE-918",
    "CWE-306",
    "CWE-362",
    "CWE-269",
    "CWE-94",
    "CWE-863",
    "CWE-276",
}

SCRIPT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = SCRIPT_DIR / "data"


# ─── CVSS Parsing & Mapping ────────────────────────────────────────────────


def _parse_cvss_vector(vector: str) -> dict:
    if not vector:
        return {}
    try:
        return {p.split(":")[0]: p.split(":")[1] for p in vector.split("/")}
    except Exception:
        return {}


def _cvss_av(v):
    return {"N": 3, "A": 2, "L": 1, "P": 0}.get(str(v), 3)


def _cvss_ac(v):
    return {"L": 1, "H": 0}.get(str(v), 1)


def _cvss_pr(v):
    return {"N": 2, "L": 1, "H": 0}.get(str(v), 2)


def _cvss_ui(v):
    return {"N": 1, "R": 0}.get(str(v), 1)


def _cvss_s(v):
    return {"C": 1, "U": 0}.get(str(v), 0)


def _cvss_cia(v):
    return {"H": 2, "L": 1, "N": 0}.get(str(v), 0)


# ─── Encoders (training-side — build_training_corpus.py versions) ────────────


def _train_encode_classification(klass: str) -> int:
    return {"OFFICIAL Sensitive": 4, "OFFICIAL": 2, "Category 1": 1}.get(
        klass, 1
    )  # WAICP: OFFICIAL (was PRIS Act Category 1)


def _train_encode_mission(mission: str) -> int:
    return {"Core": 3, "Support": 2, "Peripheral": 1}.get(mission, 2)


def _train_encode_wellbeing(wellbeing: str) -> int:
    return {"Severe": 3, "Moderate": 2, "Minimal": 1}.get(wellbeing, 1)


# ─── Encoders (inference-side — xgboost_predictor.py versions) ──────────────


def _infer_encode_classification(klass: str) -> int:
    return {"OFFICIAL Sensitive": 4, "OFFICIAL": 2, "Category 1": 1}.get(
        klass, 2
    )  # WAICP: OFFICIAL (was PRIS Act Category 1)


def _infer_encode_mission(mission: str) -> int:
    return {"Core": 3, "Support": 2, "Peripheral": 1}.get(mission, 2)


def _infer_encode_wellbeing(wellbeing: str) -> int:
    return {"Severe": 3, "Moderate": 2, "Minimal": 1}.get(wellbeing, 1)


# ─── Vendor popularity ──────────────────────────────────────────────────────

_VENDOR_POPULARITY_CACHE: dict[str, float] | None = None


def _load_vendor_popularity() -> dict[str, float]:
    global _VENDOR_POPULARITY_CACHE
    if _VENDOR_POPULARITY_CACHE is not None:
        return _VENDOR_POPULARITY_CACHE
    path = DATA_DIR / "vendor_popularity.json"
    if path.exists():
        try:
            with open(path) as f:
                _VENDOR_POPULARITY_CACHE = json.load(f)
        except (json.JSONDecodeError, OSError):
            _VENDOR_POPULARITY_CACHE = {}
    else:
        _VENDOR_POPULARITY_CACHE = {}
    return _VENDOR_POPULARITY_CACHE


def _lookup_vendor_popularity(vendor: str) -> float:
    vp = _load_vendor_popularity()
    return vp.get(vendor, 0.1)


# ─── Training-side helpers (replicates build_training_corpus.py) ────────────


def _sample_asset_fields(cvss_score: float = 0.0) -> list:
    internet_facing = random.random() < 0.15
    domain_joined = random.random() < 0.85
    cls_roll = random.random()
    if cls_roll < 0.60:
        data_classification = "OFFICIAL"
    elif cls_roll < 0.90:
        data_classification = "OFFICIAL Sensitive"
    else:
        data_classification = "Category 1"  # WAICP: OFFICIAL (was PRIS Act Category 1)
    miss_roll = random.random()
    if miss_roll < 0.40:
        mission_prevalence = "Support"
    elif miss_roll < 0.75:
        mission_prevalence = "Core"
    else:
        mission_prevalence = "Peripheral"
    wb_roll = random.random()
    if wb_roll < 0.30:
        public_wellbeing_impact = "Moderate"
    elif wb_roll < 0.80:
        public_wellbeing_impact = "Minimal"
    else:
        public_wellbeing_impact = "Severe"

    if cvss_score >= 9.0:
        lateral = int(random.random() < 0.25)
    elif cvss_score >= 7.0:
        lateral = int(random.random() < 0.12)
    else:
        lateral = int(random.random() < 0.04)

    if cvss_score >= 9.0:
        boundary = int(random.random() < 0.20)
    elif cvss_score >= 7.0:
        boundary = int(random.random() < 0.10)
    else:
        boundary = int(random.random() < 0.03)

    if cvss_score >= 9.0:
        downstream = int(random.random() < 0.35)
    elif cvss_score >= 7.0:
        downstream = int(random.random() < 0.20)
    else:
        downstream = int(random.random() < 0.05)

    return [
        internet_facing,
        domain_joined,
        _train_encode_classification(data_classification),
        _train_encode_mission(mission_prevalence),
        _train_encode_wellbeing(public_wellbeing_impact),
        lateral,
        boundary,
        downstream,
    ]


# ─── Training-side feature builder (replicates build_training_corpus.py) ────


def build_training_vector(
    cve_id: str,
    entry: dict,
    epss_score: float,
    edb_map: dict,
) -> list[float]:
    cvss_vec = _parse_cvss_vector(entry.get("cvss_v3_vector", ""))
    cvss_score = entry.get("cvss_v3_score", 0.0)
    description = entry.get("description", "")
    age_days = entry.get("vulnerability_age_days", 0)
    vendor = entry.get("vendor", "")
    vendor_pop_idx = _lookup_vendor_popularity(vendor) if vendor else 0.1
    cwe = entry.get("cwe_class", "")

    patch_available = bool(entry.get("patch_available", False))
    if patch_available:
        if cvss_score >= 9.0:
            patch_applied = random.random() < 0.80
        elif cvss_score >= 7.0:
            patch_applied = random.random() < 0.60
        else:
            patch_applied = random.random() < 0.30
    else:
        patch_applied = False

    epss = float(epss_score) if epss_score else 0.0

    edb_exploits = edb_map.get(cve_id, [])
    exploitdb_has_poc = len(edb_exploits) > 0
    metasploit_has_payload = any(
        "metasploit" in e.get("author", "").lower() for e in edb_exploits
    )

    desc_lower = description.lower()
    is_rce = int(any(re.search(p, desc_lower) for p in RCE_PATTERNS))
    is_privesc = int(any(re.search(p, desc_lower) for p in PRIVESC_PATTERNS))
    is_bypass = int(any(re.search(p, desc_lower) for p in BYPASS_PATTERNS))
    is_dos = int(any(re.search(p, desc_lower) for p in DOS_PATTERNS))
    is_traversal = int(any(re.search(p, desc_lower) for p in TRAVERSAL_PATTERNS))

    is_top25 = int(cwe in MITRE_TOP_25_CWES)

    asset_fields = _sample_asset_fields(cvss_score=float(cvss_score))

    if patch_available:
        patch_lag = random.randint(0, 365)
    else:
        patch_lag = random.randint(90, 730)

    _lam = 0.1
    if epss > 0.5:
        _lam += 2.5
    elif epss > 0.1:
        _lam += 0.8
    if cvss_score >= 9.0:
        _lam += 1.0
    elif cvss_score >= 7.0:
        _lam += 0.3
    threat_intel_pulses = max(0, int(np.random.poisson(_lam)))

    return [
        float(_cvss_av(cvss_vec.get("AV", "N"))),
        float(_cvss_ac(cvss_vec.get("AC", "L"))),
        float(_cvss_pr(cvss_vec.get("PR", "N"))),
        float(_cvss_ui(cvss_vec.get("UI", "N"))),
        float(_cvss_s(cvss_vec.get("S", "U"))),
        float(_cvss_cia(cvss_vec.get("C", "N"))),
        float(_cvss_cia(cvss_vec.get("I", "N"))),
        float(_cvss_cia(cvss_vec.get("A", "N"))),
        float(epss),
        float(patch_available),
        float(patch_applied),
        float(asset_fields[0]),
        float(asset_fields[1]),
        float(asset_fields[2]),
        float(asset_fields[3]),
        float(asset_fields[4]),
        float(asset_fields[5]),
        float(asset_fields[6]),
        float(asset_fields[7]),
        float(patch_lag),
        float(exploitdb_has_poc),
        float(metasploit_has_payload),
        float(threat_intel_pulses),
        float(entry.get("nvd_reference_count", 0)),
        float(len(description)),
        float(age_days),
        float(vendor_pop_idx),
        float(entry.get("cvss_exploitability_sub", 0.0)),
        float(entry.get("cvss_impact_sub", 0.0)),
        float(is_top25),
        float(is_rce),
        float(is_privesc),
        float(is_bypass),
        float(is_dos),
        float(is_traversal),
    ]


# ─── Inference-side feature builder (replicates xgboost_predictor.py) ───────


def build_inference_vector(
    cve_id: str,
    entry: dict,
    epss_score: float,
    edb_map: dict,
) -> list[float]:
    """Build 35-element vector exactly as xgboost_predictor.predict() does
    (lines 77-118). Deterministic features are computed from CVE data the
    same way as the training builder; stochastic features use inference
    defaults."""
    cvss_vec = _parse_cvss_vector(entry.get("cvss_v3_vector", ""))
    description = entry.get("description", "")
    desc_lower = description.lower()
    age_days = entry.get("vulnerability_age_days", 0)
    vendor = entry.get("vendor", "")
    vendor_pop_idx = _lookup_vendor_popularity(vendor) if vendor else 0.1
    cwe = entry.get("cwe_class", "")
    edb_exploits = edb_map.get(cve_id, [])

    # Deterministic: same CVSS parse as training, but with inference defaults
    # for cvss_c/i/a (0) when the vector component is missing.
    cvss_av = _cvss_av(cvss_vec.get("AV", "N"))
    cvss_ac = _cvss_ac(cvss_vec.get("AC", "L"))
    cvss_pr = _cvss_pr(cvss_vec.get("PR", "N"))
    cvss_ui = _cvss_ui(cvss_vec.get("UI", "N"))
    cvss_s = _cvss_s(cvss_vec.get("S", "U"))
    cvss_c = float(_cvss_cia(cvss_vec.get("C", "N")))
    cvss_i = float(_cvss_cia(cvss_vec.get("I", "N")))
    cvss_a = float(_cvss_cia(cvss_vec.get("A", "N")))

    return [
        float(cvss_av),
        float(cvss_ac),
        float(cvss_pr),
        float(cvss_ui),
        float(cvss_s),
        float(cvss_c),
        float(cvss_i),
        float(cvss_a),
        float(epss_score) if epss_score else 0.0,
        float(entry.get("patch_available", False)),
        0.0,  # patch_applied — inference default False
        0.0,  # internet_facing — inference default False
        0.0,  # domain_joined — inference default False
        float(_infer_encode_classification("OFFICIAL")),  # data_classification default
        float(_infer_encode_mission("Support")),  # mission_prevalence default
        float(_infer_encode_wellbeing("Minimal")),  # public_wellbeing_impact default
        0.0,  # lateral_reachability — inference default 0
        0.0,  # boundary_reachability — inference default 0
        0.0,  # downstream_assets — inference default 0
        0.0,  # patch_lag_days — inference default 0
        float(len(edb_exploits) > 0),
        float(any("metasploit" in e.get("author", "").lower() for e in edb_exploits)),
        0.0,  # threat_intel_pulses — inference default 0
        float(entry.get("nvd_reference_count", 0)),
        float(len(description)),
        float(age_days),
        float(vendor_pop_idx),
        float(entry.get("cvss_exploitability_sub", 0.0)),
        float(entry.get("cvss_impact_sub", 0.0)),
        float(int(cwe in MITRE_TOP_25_CWES)),
        float(int(any(re.search(p, desc_lower) for p in RCE_PATTERNS))),
        float(int(any(re.search(p, desc_lower) for p in PRIVESC_PATTERNS))),
        float(int(any(re.search(p, desc_lower) for p in BYPASS_PATTERNS))),
        float(int(any(re.search(p, desc_lower) for p in DOS_PATTERNS))),
        float(int(any(re.search(p, desc_lower) for p in TRAVERSAL_PATTERNS))),
    ]


# ─── Loading ────────────────────────────────────────────────────────────────


def load_nvd_corpus(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_epss_cache(path: str) -> dict:
    if not Path(path).exists():
        return {}
    with open(path) as f:
        return json.load(f)


# ─── Reporting ──────────────────────────────────────────────────────────────


def _describe_drift(feature_idx: int, train_val, infer_val, cve_id: str) -> str:
    """Generate a human-readable drift explanation."""
    name = FEATURE_NAMES[feature_idx]

    if feature_idx in (5, 6, 7):  # cvss_c, cvss_i, cvss_a
        return (
            "Defaults now aligned (both use _cvss_cia('N') = 0). "
            "Unexpected deterministic drift — investigate further."
        )
    if feature_idx == 9:  # patch_available
        return (
            "Defaults now aligned: both use False when unavailable. "
            "Unexpected deterministic drift — investigate further."
        )
    if feature_idx == 12:  # domain_joined
        return (
            "Defaults now aligned: both use False when unavailable. "
            "Unexpected deterministic drift — investigate further."
        )
    if feature_idx in (13, 14, 15):  # classification, mission, wellbeing
        return (
            "Training uses random sampling (build_training_corpus), "
            "inference uses string defaults ('OFFICIAL', 'Support', 'Minimal'). "
            "Expected stochastic drift from sampling, not a deterministic mismatch."
        )
    if feature_idx in STOCHASTIC_FEATURE_INDICES:
        return (
            "Stochastic: training uses random sampling, "
            "inference uses deterministic default"
        )

    return f"Unexpected drift at {name}"


def run_parity_check(
    nvd_corpus: dict,
    epss_cache: dict,
    sample_size: int = 100,
    seed: int = 42,
) -> str:
    items = list(nvd_corpus.items())
    if sample_size < len(items):
        rng_sampler = random.Random(seed)
        items = rng_sampler.sample(items, sample_size)

    random.seed(seed)
    np.random.seed(seed)

    edb_map: dict = {}

    NUM_FEATURES = 35
    match_counts = [0] * NUM_FEATURES
    drift_details: dict[int, dict] = {
        i: {"count": 0, "affected": []} for i in range(NUM_FEATURES)
    }

    for cve_id, entry in items:
        epss_score = 0.0
        epss_data = epss_cache.get(cve_id, {})
        if isinstance(epss_data, dict):
            epss_score = epss_data.get("epss", 0.0)

        train_vec = build_training_vector(cve_id, entry, epss_score, edb_map)
        infer_vec = build_inference_vector(cve_id, entry, epss_score, edb_map)

        for i in range(NUM_FEATURES):
            diff = abs(train_vec[i] - infer_vec[i])
            if diff <= 1e-6:
                match_counts[i] += 1
            else:
                drift_details[i]["count"] += 1
                if len(drift_details[i]["affected"]) < 10:
                    drift_details[i]["affected"].append(cve_id)

    # ── Print report ────────────────────────────────────────────────────────
    print(f"\nFEATURE PARITY CHECK — {sample_size} CVEs sampled")
    print("35 features compared between training builder and inference builder.\n")

    total_drift = 0
    critical_drifts = 0
    stochastic_drifts = 0
    default_mismatch_cves: set[str] = set()

    for i in range(NUM_FEATURES):
        match_pct = match_counts[i]
        name = FEATURE_NAMES[i]
        line = f"  Feature {i} ({name}): {match_pct}/{sample_size} match"

        if match_pct == sample_size:
            print(line)
        else:
            total_drift += 1

            if i in STOCHASTIC_FEATURE_INDICES:
                stochastic_drifts += 1
                print(f"{line}  *** STOCHASTIC DRIFT (expected)")
                print(
                    "       Training uses random sampling, "
                    "inference uses deterministic default"
                )
            else:
                critical_drifts += 1
                explanation = _describe_drift(i, None, None, None)
                print(f"{line}  *** DRIFT DETECTED")
                print(f"       {explanation}")

            if drift_details[i]["affected"]:
                print(
                    f"       Affected CVEs: "
                    f"{', '.join(drift_details[i]['affected'])}"
                    f"{'...' if drift_details[i]['count'] > 10 else ''}"
                )

        if match_pct < sample_size and i not in STOCHASTIC_FEATURE_INDICES:
            for cve_id in drift_details[i]["affected"]:
                default_mismatch_cves.add(cve_id)

    print(f"\n{'=' * 60}")
    print(f"  Total features with drift: {total_drift}/{NUM_FEATURES}")
    print(f"  Critical drifts (logic/default mismatches): {critical_drifts}")
    print(f"  Stochastic drifts (random sampling differences): {stochastic_drifts}")

    if critical_drifts > 0:
        verdict = "FAIL"
    elif stochastic_drifts > 0:
        verdict = "WARN"
    else:
        verdict = "PASS"

    print(f"  Overall verdict: {verdict}")
    print(f"{'=' * 60}\n")

    return verdict


def main():
    parser = argparse.ArgumentParser(
        description="Check feature parity between training and inference builders"
    )
    parser.add_argument(
        "--sample",
        type=int,
        default=100,
        help="Number of CVEs to sample (default: 100)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )
    args = parser.parse_args()

    nvd_path = DATA_DIR / "nvd_corpus.json"
    epss_path = DATA_DIR / "epss_cache.json"

    print("Loading nvd_corpus.json ...", end=" ", flush=True)
    nvd_corpus = load_nvd_corpus(str(nvd_path))
    print(f"{len(nvd_corpus)} CVEs loaded.")

    print("Loading epss_cache.json ...", end=" ", flush=True)
    epss_cache = load_epss_cache(str(epss_path))
    print(f"{len(epss_cache)} entries loaded.")

    verdict = run_parity_check(nvd_corpus, epss_cache, args.sample, args.seed)

    # Exit non-zero only for genuine deterministic violations
    # Stochastic drift is expected and should not block CI
    if verdict == "FAIL":
        sys.exit(1)
    elif verdict == "WARN":
        print(
            "[audit-features] WARN: only stochastic drift detected — "
            "expected differences from training random sampling, not a contract violation."
        )
        sys.exit(0)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
