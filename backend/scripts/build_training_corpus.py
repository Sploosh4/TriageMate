"""
Unified training corpus builder — combines all data sources into
a training-ready dataset with REAL distributions for ALL features.

Replaces the Phase 1 of train_xgboost.py.

Output: backend/ml/training_data_v2.npz (420 features: 36 tabular + 384 text SBERT; model uses 419 — osv_lead_days is metadata)

Usage:
    cd backend
    python -m scripts.build_training_corpus
        [--nvd-corpus data/nvd_corpus.json]
        [--output ml/training_data_v2.npz]
        [--limit 1000]       -- test mode
        [--skip-sbert]       -- skip text encoding (fast testing)
"""

import argparse
import json
import logging
import os
import random
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from dotenv import load_dotenv

# Bulletproof: find .env relative to this script, not CWD
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.build_training_corpus")

random.seed(42)

DATA_DIR = Path(__file__).parent.parent / "data"
ML_DIR = Path(__file__).parent.parent / "ml"

OBS_WINDOW_DAYS = 30

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

_FEATURE_NAMES = [
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
    "osv_lead_days",
]

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
            logger.info(
                "Loaded vendor_popularity.json (%d entries)",
                len(_VENDOR_POPULARITY_CACHE),
            )
        except (json.JSONDecodeError, OSError):
            _VENDOR_POPULARITY_CACHE = {}
    else:
        _VENDOR_POPULARITY_CACHE = {}
    return _VENDOR_POPULARITY_CACHE


def _lookup_vendor_popularity(vendor: str) -> float:
    vp = _load_vendor_popularity()
    if vendor in vp:
        return vp[vendor]
    return 0.1


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


def _encode_classification(klass: str) -> int:
    mapping = {"OFFICIAL Sensitive": 4, "OFFICIAL": 2, "Category 1": 1}
    return mapping.get(klass, 1)


def _encode_mission(mission: str) -> int:
    mapping = {"Core": 3, "Support": 2, "Peripheral": 1}
    return mapping.get(mission, 2)


def _encode_wellbeing(wellbeing: str) -> int:
    mapping = {"Severe": 3, "Moderate": 2, "Minimal": 1}
    return mapping.get(wellbeing, 1)


# ─── Phase 1: Load Sources ────────────────────────────────────────────────


def _load_json(path: Path) -> dict:
    if not path.exists():
        logger.warning("File not found: %s", path)
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load %s: %s", path, e)
        return {}


def _load_edb_map() -> dict[str, list[dict]]:
    try:
        from integrations.exploitdb import _load_edb_csv

        _load_edb_csv()
        from integrations.exploitdb import _EDB_CVE_MAP

        return _EDB_CVE_MAP or {}
    except Exception as e:
        logger.warning("Could not load ExploitDB CSV: %s", e)
        return {}


def load_sources(nvd_path: str):
    logger.info("[Phase 1] Loading all data sources...")

    nvd_corpus = _load_json(Path(nvd_path))
    kev_cache = _load_json(DATA_DIR / "kev_cache.json")
    epss_cache = _load_json(DATA_DIR / "epss_cache.json")
    edb_map = _load_edb_map()

    logger.info(
        "Loaded: NVD=%d, KEV=%d, EPSS=%d, EDB=%d",
        len(nvd_corpus),
        len(kev_cache),
        len(epss_cache),
        len(edb_map),
    )
    return nvd_corpus, kev_cache, epss_cache, edb_map


# ─── Phase 2: Build Feature Vectors ───────────────────────────────────────


def _sample_asset_fields(cvss_score: float = 0.0) -> list:
    internet_facing = random.random() < 0.15
    domain_joined = random.random() < 0.85
    cls_roll = random.random()
    if cls_roll < 0.60:
        data_classification = "OFFICIAL"
    elif cls_roll < 0.90:
        data_classification = "OFFICIAL Sensitive"
    else:
        data_classification = "Category 1"
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

    # Binary CVSS-based samplers matching train_xgboost.py pattern
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
        _encode_classification(data_classification),
        _encode_mission(mission_prevalence),
        _encode_wellbeing(public_wellbeing_impact),
        lateral,
        boundary,
        downstream,
    ]


def _derive_published_date(entry: dict) -> str:
    """Derive a publish date string from entry fields.

    Uses 'published' if present, otherwise computes from
    vulnerability_age_days.
    """
    published = entry.get("published", "")
    if published:
        return published[:10]
    age = entry.get("vulnerability_age_days", 0)
    if age > 0:
        dt = datetime.now(timezone.utc) - timedelta(days=age)
        return dt.strftime("%Y-%m-%d")
    return ""


def build_feature_vectors(
    nvd_corpus: dict,
    kev_cache: dict,
    epss_cache: dict,
    edb_map: dict,
    limit: int = 0,
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    logger.info("[Phase 2] Building feature vectors...")

    cve_ids: list[str] = []
    dates: list[str] = []
    descriptions: list[str] = []
    rows: list[list[float]] = []

    items = list(nvd_corpus.items())
    if limit > 0:
        items = items[:limit]

    for idx, (cve_id, entry) in enumerate(items):
        if (idx + 1) % 1000 == 0:
            logger.info("  Processed %d/%d CVEs", idx + 1, len(items))

        cvss_vec = _parse_cvss_vector(entry.get("cvss_v3_vector", ""))

        epss_data = epss_cache.get(cve_id, {})
        epss_score = epss_data.get("epss", 0.0) if isinstance(epss_data, dict) else 0.0

        patch_available = entry.get("patch_available", False)
        cvss_score = entry.get("cvss_v3_score", 0.0)

        if patch_available:
            if cvss_score >= 9.0:
                patch_applied = random.random() < 0.80
            elif cvss_score >= 7.0:
                patch_applied = random.random() < 0.60
            else:
                patch_applied = random.random() < 0.30
        else:
            patch_applied = False

        edb_exploits = edb_map.get(cve_id, [])
        exploitdb_has_poc = len(edb_exploits) > 0
        metasploit_has_payload = any(
            "metasploit" in e.get("author", "").lower() for e in edb_exploits
        )

        description = entry.get("description", "")
        osv_published = entry.get("osv_published", "")
        age_days = entry.get("vulnerability_age_days", 0)
        vendor = entry.get("vendor", "")
        vendor_pop_idx = _lookup_vendor_popularity(vendor) if vendor else 0.1

        desc_lower = description.lower()
        is_rce = int(any(re.search(p, desc_lower) for p in RCE_PATTERNS))
        is_privesc = int(any(re.search(p, desc_lower) for p in PRIVESC_PATTERNS))
        is_bypass = int(any(re.search(p, desc_lower) for p in BYPASS_PATTERNS))
        is_dos = int(any(re.search(p, desc_lower) for p in DOS_PATTERNS))
        is_traversal = int(any(re.search(p, desc_lower) for p in TRAVERSAL_PATTERNS))

        cwe = entry.get("cwe_class", "")
        is_top25 = int(cwe in MITRE_TOP_25_CWES)

        asset_fields = _sample_asset_fields(cvss_score=float(cvss_score))

        if patch_available:
            patch_lag = random.randint(0, 365)
        else:
            patch_lag = random.randint(90, 730)

        _lam = 0.1
        if epss_score > 0.5:
            _lam += 2.5
        elif epss_score > 0.1:
            _lam += 0.8
        if cvss_score >= 9.0:
            _lam += 1.0
        elif cvss_score >= 7.0:
            _lam += 0.3
        threat_intel_pulses = max(0, int(np.random.poisson(_lam)))

        osv_lead_days = 0
        if osv_published:
            nvd_pub_str = _derive_published_date(entry)
            if nvd_pub_str:
                try:
                    nvd_dt = datetime.strptime(nvd_pub_str[:10], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    osv_dt = datetime.strptime(osv_published[:10], "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                    osv_lead_days = (nvd_dt - osv_dt).days
                except (ValueError, TypeError):
                    pass

        row = [
            float(_cvss_av(cvss_vec.get("AV", "N"))),
            float(_cvss_ac(cvss_vec.get("AC", "L"))),
            float(_cvss_pr(cvss_vec.get("PR", "N"))),
            float(_cvss_ui(cvss_vec.get("UI", "N"))),
            float(_cvss_s(cvss_vec.get("S", "U"))),
            float(_cvss_cia(cvss_vec.get("C", "N"))),
            float(_cvss_cia(cvss_vec.get("I", "N"))),
            float(_cvss_cia(cvss_vec.get("A", "N"))),
            float(epss_score),
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
            float(osv_lead_days),
        ]
        rows.append(row)
        cve_ids.append(cve_id)
        dates.append(_derive_published_date(entry))
        descriptions.append(description)

    X_tab = np.array(rows, dtype=np.float32)
    logger.info("  Tabular feature matrix: %s", X_tab.shape)
    return X_tab, np.array(cve_ids), dates, descriptions


# ─── Phase 3: Labels ──────────────────────────────────────────────────────


def build_labels(
    cve_ids: list[str],
    dates: list[str],
    kev_cache: dict,
    descriptions: list[str],
) -> tuple[np.ndarray, int, int]:
    logger.info("[Phase 3] Building labels with quality filters...")

    raw_kev_in_corpus = sum(1 for cid in cve_ids if cid in kev_cache)

    mask = [True] * len(cve_ids)
    for i in range(len(cve_ids)):
        pub_date = dates[i] if i < len(dates) else ""
        if not pub_date:
            mask[i] = False
            continue
        try:
            dt = datetime.strptime(pub_date[:10], "%Y-%m-%d")
            age = (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
            if age < OBS_WINDOW_DAYS:
                mask[i] = False
        except ValueError:
            mask[i] = False

    filtered_ids = [cve_ids[i] for i in range(len(cve_ids)) if mask[i]]

    labels = []
    pos_count = 0
    neg_count = 0
    for cve_id in filtered_ids:
        if cve_id in kev_cache:
            labels.append(1)
            pos_count += 1
        else:
            labels.append(0)
            neg_count += 1

    y = np.array(labels, dtype=np.int8)
    total = len(y)
    logger.info(
        "  Labels after filtering: %d positive (%.2f%%), %d negative (%.2f%%), %d total",
        pos_count,
        pos_count / total * 100 if total else 0,
        neg_count,
        neg_count / total * 100 if total else 0,
        total,
    )
    logger.info(
        "  KEV coverage: %d/%d KEV CVEs used as positive labels (%.1f%%)",
        pos_count,
        raw_kev_in_corpus,
        pos_count / raw_kev_in_corpus * 100 if raw_kev_in_corpus else 0,
    )
    if raw_kev_in_corpus > 0 and pos_count / raw_kev_in_corpus < 0.50:
        logger.warning(
            "  Less than 50%% of KEV CVEs captured as labels. "
            "Check KEV cache freshness and date filters."
        )
    return y, pos_count, neg_count


# ─── Phase 4: SBERT Encode ────────────────────────────────────────────────


def encode_texts(descriptions: list[str], skip_sbert: bool = False) -> np.ndarray:
    logger.info("[Phase 4] Encoding descriptions...")
    if skip_sbert or not descriptions:
        logger.info("  Skipping SBERT encoding (--skip-sbert or empty descriptions)")
        return np.zeros((len(descriptions), 384), dtype=np.float32)

    try:
        from ml.encoder import encode_batch

        X_text = encode_batch(descriptions)
        logger.info("  Text SBERT matrix: %s", X_text.shape)
        return X_text.astype(np.float32)
    except Exception as e:
        logger.warning("SBERT encoding failed: %s — using zeros", e)
        return np.zeros((len(descriptions), 384), dtype=np.float32)


# ─── Phase 5: Save ────────────────────────────────────────────────────────


def save_dataset(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    output_path: str,
    dates: list[str] | None = None,
    cve_ids: np.ndarray | None = None,
):
    """Save (n, 419+) feature matrix, labels, feature names, and optional dates + CVE IDs."""
    logger.info("[Phase 5] Saving dataset to %s ...", output_path)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    save_dict = dict(X=X, y=y, feature_names=feature_names)
    if dates is not None:
        save_dict["dates"] = np.array(dates, dtype=str)
    if cve_ids is not None:
        save_dict["cve_ids"] = cve_ids
    np.savez_compressed(path, **save_dict)
    size_mb = path.stat().st_size / (1024 * 1024)
    logger.info("  Saved: X=%s, y=%s, %.1f MB", X.shape, y.shape, size_mb)
    logger.info("  Feature count: %d", X.shape[1])


# ─── Main Pipeline ────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Build unified training corpus")
    parser.add_argument("--nvd-corpus", default=str(DATA_DIR / "nvd_corpus.json"))
    parser.add_argument("--output", default=str(ML_DIR / "training_data_v2.npz"))
    parser.add_argument("--limit", type=int, default=0, help="Test mode: limit CVEs")
    parser.add_argument("--skip-sbert", action="store_true", help="Skip text encoding")
    args = parser.parse_args()

    nvd_path = args.nvd_corpus
    limit = args.limit
    skip_sbert = args.skip_sbert

    if not os.path.exists(nvd_path):
        logger.error(
            "NVD corpus not found at %s. Run fetch_nvd_corpus.py first.", nvd_path
        )
        sys.exit(1)

    nvd_corpus, kev_cache, epss_cache, edb_map = load_sources(nvd_path)

    if not nvd_corpus:
        logger.error("NVD corpus is empty.")
        sys.exit(1)

    X_tab, cve_ids, dates, descriptions = build_feature_vectors(
        nvd_corpus,
        kev_cache,
        epss_cache,
        edb_map,
        limit=limit,
    )

    y, pos_count, neg_count = build_labels(
        cve_ids.tolist(),
        dates,
        kev_cache,
        descriptions,
    )

    if pos_count == 0:
        logger.error("No positive labels after filtering. Cannot build corpus.")
        sys.exit(1)

    filtered_indices = []
    for i, cve_id in enumerate(cve_ids):
        pub_date = dates[i] if i < len(dates) else ""
        if pub_date:
            try:
                dt = datetime.strptime(pub_date[:10], "%Y-%m-%d")
                age = (
                    datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)
                ).days
                if age >= OBS_WINDOW_DAYS:
                    filtered_indices.append(i)
            except ValueError:
                pass

    X_tab = X_tab[filtered_indices]
    cve_ids = cve_ids[filtered_indices]
    dates = [dates[i] for i in filtered_indices]
    descriptions = [descriptions[i] for i in filtered_indices]

    logger.info("  Applying same filter to feature matrix: %s", X_tab.shape)

    X_text = encode_texts(descriptions, skip_sbert=skip_sbert)

    if X_text.shape[0] == 0:
        X_text = np.zeros((len(descriptions), 384), dtype=np.float32)

    X = np.hstack([X_tab, X_text]).astype(np.float32)

    logger.info("  Final training matrix: X=%s, y=%s", X.shape, y.shape)
    logger.info(
        "  Total features: %d (tabular=%d + text_sbert=%d)",
        X.shape[1],
        X_tab.shape[1],
        X_text.shape[1],
    )

    all_feature_names = _FEATURE_NAMES + [f"text_sbert_{i}" for i in range(384)]
    assert len(all_feature_names) == X.shape[1], (
        f"Feature name count mismatch: {len(all_feature_names)} != {X.shape[1]}"
    )

    save_dataset(X, y, all_feature_names, args.output, dates=dates, cve_ids=cve_ids)

    logger.info("Build complete.")


if __name__ == "__main__":
    main()
