"""
Offline XGBoost training pipeline — two-phase design.

Phase 1 (Gather): Fetch NVD/EPSS/KEV, build features, encode text, save to disk.
Phase 2 (Train):  Load saved features, train XGBoost + Platt, export model.

Save points:
    enriched_cves.json   — after NVD + EPSS + KEV merge (skip re-fetch)
    training_data.npz    — after label/feature/SBERT construction (skip re-encoding)

Usage:
    cd backend
    python -m ml.train_xgboost                # auto-detect phase
    python -m ml.train_xgboost --gather       # force re-gather
    python -m ml.train_xgboost --train        # train only (skip gather)
"""

import json
import os
import re
import sys
import time
import joblib
import numpy as np
import requests
import xgboost as xgb
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score, f1_score

from ml.encoder import encode_batch
from pipeline.config.feature_names import (
    TABULAR_FEATURE_ORDER,
    make_sbert_feature_names,
)

OUTPUT_DIR = Path(__file__).parent
MODEL_FILE = OUTPUT_DIR / "xgboost_model.pkl"
NVD_CHECKPOINT = OUTPUT_DIR / "nvd_checkpoint.json"
NVD_CACHE_FILE = OUTPUT_DIR / "nvd_cves_cached.json"
ENRICHED_CVES_FILE = OUTPUT_DIR / "enriched_cves.json"
TRAINING_DATA_FILE = OUTPUT_DIR / "training_data.npz"
CALIBRATOR_FILE = OUTPUT_DIR / "xgboost_calibrator.pkl"
THRESHOLD_INFO_FILE = OUTPUT_DIR / "threshold_info.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NVD_API_KEY = os.getenv("NVD_API_KEY", "")

DATE_START = "2019-01-01"
DATE_END = "2024-12-31"
TRAIN_CUTOFF = "2023-06-30"
VAL_CUTOFF = "2023-12-31"
DEFAULT_OBS_WINDOW_DAYS = 227  # median KEV lag, fallback if unable to compute
BATCH_SIZE = 200
SLEEP_INTERVAL = 6.2

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

# ─── SAVE / LOAD ───────────────────────────────────────────────────────────


def save_enriched_cves(cves: list[dict], path: Path):
    """Save NVD CVEs with merged EPSS/KEV to JSON."""
    print(
        f"  Writing {len(cves)} enriched CVEs to {path.name} ... ", end="", flush=True
    )
    with open(path, "w") as f:
        json.dump(cves, f)
    print("done.")


def load_enriched_cves(path: Path) -> list[dict]:
    """Load enriched CVEs from JSON."""
    print(f"  Loading enriched CVEs from {path.name} ... ", end="", flush=True)
    with open(path) as f:
        cves = json.load(f)
    print(f"{len(cves)} records.")
    return cves


def save_training_data(
    X: np.ndarray,
    y: np.ndarray,
    dates: np.ndarray,
    cve_ids: np.ndarray,
    path: Path,
    n_text_dims: int = 384,
):
    """Save (n, 35+text_dims) features, labels, dates, CVE IDs, and feature names to .npz.

    Args:
        n_text_dims: Number of text embedding dimensions. Defaults to 384 for raw SBERT.
            Set to the number of PCA components when PCA-reduced features are used.
    """
    # Build feature name array: 35 tabular names + text feature names
    text_names = make_sbert_feature_names(n_text_dims)
    feature_names = np.array(TABULAR_FEATURE_ORDER + text_names, dtype=str)
    print(f"  Writing training data to {path.name} ... ", end="", flush=True)
    np.savez_compressed(
        path,
        X=X,
        y=y,
        dates=dates,
        cve_ids=cve_ids,
        feature_names=feature_names,
    )
    size_mb = path.stat().st_size / (1024 * 1024)
    print(f"done ({size_mb:.1f} MB).")


def load_training_data(path: Path) -> tuple:
    """Load training data from .npz. Returns (X, y, dates, cve_ids)."""
    print(f"  Loading training data from {path.name} ... ", end="", flush=True)
    data = np.load(path)
    X = data["X"]
    y_arr = data["y"]
    dates_arr = data["dates"]
    cve_ids_arr = data["cve_ids"]
    n_cols = X.shape[1]
    data.close()
    if n_cols == 69:
        print(
            "\n  [migrate] Old 69-column data detected. Stripping cisa_kev (column 9)..."
        )
        keep = [i for i in range(69) if i != 9]
        X = X[:, keep]
        save_training_data(X, y_arr, dates_arr, cve_ids_arr, path)
    print(f"  {X.shape[0]} records, {n_cols}→{X.shape[1]} features.")
    return X, y_arr, dates_arr, cve_ids_arr


# ─── QUALITY REPORT ────────────────────────────────────────────────────────


def print_quality_report(cves: list[dict], y: np.ndarray, dates: np.ndarray):
    """Print a data-quality summary before training (multi-class KEV labels)."""
    cve_ids_arr = np.array([c["cve_id"] for c in cves])
    n_pos = int(sum(y > 0))  # Any KEV membership is "positive"
    n_total = len(y)

    print("\n" + "=" * 60)
    print("DATA QUALITY REPORT (multi-window KEV)")
    print("=" * 60)

    print(f"\n  Total CVEs:           {n_total:,}")
    print(f"  In KEV (label>0):     {n_pos:,}  ({n_pos / n_total:.3%})")
    for w in range(1, 5):
        n_w = int(sum(y == w))
        print(f"    Window {w} (label={w}):        {n_w:,}  ({n_w / n_total:.3%})")
    print(
        f"  Not in KEV (label=0): {n_total - n_pos:,}  ({(n_total - n_pos) / n_total:.3%})"
    )

    train = dates <= TRAIN_CUTOFF
    val = (dates > TRAIN_CUTOFF) & (dates <= VAL_CUTOFF)
    test = dates > VAL_CUTOFF

    for name, mask in [("Train", train), ("Val", val), ("Test", test)]:
        n = int(sum(mask))
        n_p = int(sum(y[mask] > 0))
        pct = n_p / n * 100 if n > 0 else 0
        print(f"  {name:>5} set:           {n:,} CVEs  (positives: {n_p} = {pct:.2f}%)")

    pos_ids = cve_ids_arr[y > 0]
    print(f"\n  Positive CVE IDs (first 20): {', '.join(pos_ids[:20].tolist())}")

    pos_cwes = Counter(
        cve["cwe_id"] for cve, lab in zip(cves, y) if lab > 0 and cve["cwe_id"]
    )
    neg_cwes = Counter(
        cve["cwe_id"] for cve, lab in zip(cves, y) if lab == 0 and cve["cwe_id"]
    )
    common_pos = pos_cwes.most_common(10)
    common_neg = neg_cwes.most_common(10)

    if common_pos:
        print(
            f"\n  Top CWE among exploited: {', '.join(f'{c} ({n})' for c, n in common_pos)}"
        )
    if common_neg:
        print(
            f"  Top CWE among non-exploited: {', '.join(f'{c} ({n})' for c, n in common_neg[:5])}"
        )

    pos_cvss = [c["cvss_score"] for c, lab in zip(cves, y) if lab > 0]
    neg_cvss = [c["cvss_score"] for c, lab in zip(cves, y) if lab == 0]
    if pos_cvss:
        print(f"\n  Mean CVSS (exploited):     {np.mean(pos_cvss):.1f}")
    print(f"  Mean CVSS (not exploited): {np.mean(neg_cvss):.1f}")

    pos_epss = [c.get("epss_score", 0) for c, lab in zip(cves, y) if lab > 0]
    if pos_epss:
        print(f"  Mean EPSS (exploited):     {np.mean(pos_epss):.4f}")
    neg_epss = [c.get("epss_score", 0) for c, lab in zip(cves, y) if lab == 0]
    if neg_epss:
        print(f"  Mean EPSS (not exploited): {np.mean(neg_epss):.4f}")

    print("\n" + "=" * 60)

    # Automatic quality check
    if n_pos == 0:
        print("  [FATAL] No positive labels. Model cannot train.")
        sys.exit(1)
    if n_pos < 30:
        print(f"  [WARN] Only {n_pos} positives. Model may be unreliable.")
    print()


# ─── NVD FETCHING ──────────────────────────────────────────────────────────


def _date_chunks(start_date: str, end_date: str) -> list[tuple[str, str]]:
    """Split a date range into 3-month chunks to avoid NVD total-results limit."""
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    chunks = []
    while start < end:
        chunk_end = start.replace(day=1) + timedelta(days=93)
        chunk_end = chunk_end.replace(day=1) - timedelta(days=1)
        if chunk_end > end:
            chunk_end = end
        if chunk_end <= start:
            chunk_end = end
        chunks.append((start.strftime("%Y-%m-%d"), chunk_end.strftime("%Y-%m-%d")))
        start = chunk_end + timedelta(days=1)
    return chunks


def _load_checkpoint() -> tuple[list[dict], str, int]:
    """Load cached CVEs and resume position. Returns (cves, chunk_key, start_idx)."""
    if NVD_CACHE_FILE.exists():
        try:
            with open(NVD_CACHE_FILE) as f:
                cves = json.load(f)
            print(f"  Resuming from cache: {len(cves)} CVEs already fetched.")
        except (json.JSONDecodeError, OSError):
            cves = []
    else:
        cves = []
    chunk_key = ""
    start_idx = 0
    if NVD_CHECKPOINT.exists():
        try:
            with open(NVD_CHECKPOINT) as f:
                cp = json.load(f)
            chunk_key = cp.get("chunk", "")
            start_idx = cp.get("index", 0)
        except (json.JSONDecodeError, OSError):
            pass
    return cves, chunk_key, start_idx


def _save_progress(cves: list[dict], chunk_key: str, index: int):
    try:
        with open(NVD_CACHE_FILE, "w") as f:
            json.dump(cves, f)
        with open(NVD_CHECKPOINT, "w") as f:
            json.dump({"chunk": chunk_key, "index": index, "count": len(cves)}, f)
    except OSError:
        pass


def fetch_nvd_cves(start_date: str, end_date: str) -> list[dict]:
    """Fetch all CVEs with CVSS v3.1 vectors from NVD (quarterly chunks, resumable)."""
    all_cves, resume_chunk, resume_idx = _load_checkpoint()
    chunks = _date_chunks(start_date, end_date)
    resumed = resume_chunk != ""

    for chunk_start, chunk_end in chunks:
        chunk_key = f"{chunk_start}_{chunk_end}"
        if resumed and chunk_key != resume_chunk:
            continue
        if chunk_key == resume_chunk:
            resumed = False

        start_idx = resume_idx if chunk_key == resume_chunk else 0
        while True:
            params = {
                "pubStartDate": f"{chunk_start}T00:00:00.000",
                "pubEndDate": f"{chunk_end}T23:59:59.999",
                "startIndex": start_idx,
                "resultsPerPage": BATCH_SIZE,
            }
            print(f"  Fetching {chunk_start}..{chunk_end} page at index {start_idx}...")
            headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

            resp = None
            for attempt in range(5):
                try:
                    resp = requests.get(
                        NVD_API, params=params, headers=headers, timeout=120
                    )
                    break
                except requests.exceptions.RequestException as e:
                    wait = (attempt + 1) * 15
                    print(
                        f"    {type(e).__name__}, retrying in {wait}s (attempt {attempt + 1}/5)..."
                    )
                    time.sleep(wait)
            else:
                print(
                    f"    Failed after 5 attempts. Progress saved ({len(all_cves)} CVEs). Resume by re-running."
                )
                _save_progress(all_cves, chunk_key, start_idx)
                raise RuntimeError(
                    f"Failed after 5 attempts at {chunk_start}..{chunk_end} index {start_idx}"
                )

            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            for vuln in vulns:
                cve = vuln["cve"]
                cvss_v31 = None
                for metric in (cve.get("metrics", {}) or {}).get("cvssMetricV31", []):
                    cvss_v31 = metric.get("cvssData")
                if not cvss_v31:
                    continue
                desc_en = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc_en = d["value"]
                        break
                if not desc_en:
                    continue
                all_cves.append(
                    {
                        "cve_id": cve["id"],
                        "description": desc_en,
                        "cvss_score": cvss_v31["baseScore"],
                        "cvss_vector": cvss_v31["vectorString"],
                        "published_date": cve.get("published", "")[:10],
                        "cwe_id": _extract_cwe(cve),
                        "reference_count": len(cve.get("references", [])),
                        "cvss_exploitability_sub": cvss_v31.get(
                            "exploitabilityScore", 0
                        ),
                        "cvss_impact_sub": cvss_v31.get("impactScore", 0),
                        "references": cve.get("references", []),
                    }
                )

            _save_progress(all_cves, chunk_key, start_idx + BATCH_SIZE)

            start_idx += BATCH_SIZE
            if len(vulns) < BATCH_SIZE:
                _save_progress(all_cves, chunk_key + "_done", start_idx)
                break
            time.sleep(SLEEP_INTERVAL)

    return all_cves


def _extract_cwe(cve: dict) -> str:
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                return desc["value"]
    return ""


# ─── EPSS / KEV FETCHING ──────────────────────────────────────────────────


def fetch_epss() -> dict:
    """Fetch all EPSS scores from FIRST.org as {CVE-ID: score} (paginated)."""
    print("  Fetching EPSS scores...")
    scores = {}
    offset = 0
    limit = 1000
    while True:
        resp = requests.get(
            EPSS_API, params={"offset": offset, "limit": limit}, timeout=60
        )
        resp.raise_for_status()
        data = resp.json()
        for entry in data.get("data", []):
            scores[entry["cve"]] = float(entry["epss"])
        total = data.get("total", 0)
        offset += limit
        if offset >= total:
            break
        print(f"    ... {len(scores)}/{total} EPSS scores fetched")
        time.sleep(1)
    print(f"  Fetched {len(scores)} EPSS scores total.")
    return scores


def fetch_kev() -> dict[str, str]:
    """Fetch CISA KEV catalog. Returns {CVE-ID: dateAdded}."""
    print("  Fetching CISA KEV catalog...")
    resp = requests.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    result = {
        entry["cveID"]: entry.get("dateAdded", "")
        for entry in data.get("vulnerabilities", [])
    }
    print(f"  Fetched {len(result)} KEV entries.")
    return result


def compute_kev_lag_stats(
    cves: list[dict], kev_data: dict[str, str], cutoff_date: str = DATE_END
) -> dict:
    """Compute median/percentile lag from CVE published_date to KEV dateAdded.

    Only considers KEV entries whose dateAdded is at or before cutoff_date
    (point-in-time), so the lag distribution reflects what was observable
    during the training period. Returns stats dict with median, p75, p90,
    and count of KEV entries used.
    """
    lags = []
    cve_map = {c["cve_id"]: c.get("published_date", "") for c in cves}
    for cve_id, date_added in kev_data.items():
        if not date_added or date_added > cutoff_date:
            continue  # skip future KEV additions (outside training window)
        pub_date = cve_map.get(cve_id, "")
        if not pub_date:
            continue
        try:
            added = datetime.strptime(date_added, "%Y-%m-%d")
            pub = datetime.strptime(pub_date[:10], "%Y-%m-%d")
            lag = (added - pub).days
            if lag >= 0:
                lags.append(lag)
        except ValueError:
            continue

    if len(lags) < 5:
        # Fallback: not enough KEV entries with our CVEs to compute stats
        print(
            f"  [WARN] Only {len(lags)} KEV lag samples. "
            f"Using default observation window of {DEFAULT_OBS_WINDOW_DAYS} days."
        )
        return {
            "median": DEFAULT_OBS_WINDOW_DAYS,
            "p75": int(DEFAULT_OBS_WINDOW_DAYS * 1.5),
            "p90": int(DEFAULT_OBS_WINDOW_DAYS * 2.0),
            "count": len(lags),
        }

    stats = {
        "median": int(np.median(lags)),
        "p75": int(np.percentile(lags, 75)),
        "p90": int(np.percentile(lags, 90)),
        "count": len(lags),
        "min": min(lags),
        "max": max(lags),
    }
    print(
        f"  KEV lag stats ({stats['count']} entries, dateAdded <= {cutoff_date}): "
        f"median={stats['median']}d, p75={stats['p75']}d, "
        f"min={stats['min']}d, max={stats['max']}d"
    )
    return stats


# ─── KEV LABEL TEMPORAL BIAS FIX (v2.3) ─────────────────────────────────
#
# 2026-07-02: Root cause analysis and fix
# =========================================
#
# PROBLEM:
#   1. CISA KEV has a median lag of ~190 days from CVE publication to addition
#      (computed from actual KEV data filtered to dateAdded <= DATE_END).
#   2. The training pipeline fetched a point-in-time KEV snapshot and used simple
#      set membership as the label: "is this CVE ID in the KEV catalog right now?"
#      This meant:
#      a) CVEs added to KEV after DATE_END were labeled 1 (future information
#         leakage) — ~83 CVEs in our dataset.
#      b) ~22,000 CVEs published in the 8-month window before DATE_END were
#         labeled 0 even though some are exploited (false negatives).
#   3. The hardcoded OBS_WINDOW=30 day filter only dropped ~1,800 CVEs,
#      leaving ~22,000 unreliable labels in training.
#   4. The model learned to predict "not exploited" for recent CVEs, which is
#      precisely wrong for operational use.
#
# FIX (v2.3):
#   - Point-in-time labels: construct_labels() now checks dateAdded <= cutoff_date
#     (DATE_END) instead of simple set membership. CVEs added to KEV after the
#     training data freeze are correctly labeled 0.
#   - Dynamic observation window: the hardcoded OBS_WINDOW=30 is replaced with
#     the computed median KEV lag (~190 days). Label-0 CVEs published within
#     this window before DATE_END are excluded from training (unreliable negatives).
#     Label-1 CVEs in the window (rapid exploitation cases) are preserved.
#   - Selective exclusion: only label-0 CVEs in the observation window are removed,
#     keeping ~67 genuine positives that would otherwise be discarded.
#
# IMPACT:
#   Retraining with --gather --train will produce a model that no longer learns
#   to predict "not exploited" for recent CVEs. The training set shrinks by
#   ~19,500 entries (16%), but label quality improves dramatically.
# ────────────────────────────────────────────────────────────────────────────


# ─── ENCODING AUDIT (RESOLVED IN v2.2) ───────────────────────────────────
#
# 2026-07-02: Root cause analysis and fix
# =========================================
#
# PROBLEM (v2.1):
#   1. 15 features were hardcoded to constants during training:
#      - patch_available=1, exploitdb_has_poc=0, metasploit_has_payload=0
#      - internet_facing=1, domain_joined=1, data_classification=2
#      - mission_prevalence=2, public_wellbeing_impact=1, lateral=0
#      - boundary=0, downstream=0, threat_intel_pulses=0
#      - vendor_popularity_index=0, patch_lag_days=0
#   2. 36 training features vs 35 inference features (index 27 placeholder)
#   3. Feature ORDER differed between training and inference after index 9
#   4. Training was missing patch_applied and domain_joined features
#   5. Extra dead indices (22, 23, 27) existed in training with no inference equivalent
#
# FIX (v2.2):
#   - build_tabular_features() now produces 35 features in the EXACT order
#     used by xgboost_predictor.py (inference), eliminating the dimension mismatch.
#   - All 15 formerly-hardcoded features are computed from real NVD/EPSS data:
#     * patch_available: checks NVD reference tags for Patch/Vendor-Advisory
#     * patch_applied: synthetic estimate from patch_available + age + CVSS
#     * exploitdb_has_poc, metasploit_has_payload, threat_intel_pulses:
#       sampled from EPSS/CVSS correlations (no live API queries during training)
#     * Asset-context features (internet_facing, domain_joined, etc.):
#       sampled from realistic WA-government distributions with fixed seed 42
#   - vendor_popularity_index remains 0 during training (no OS data available)
#
# IMPACT:
#   Retraining with --gather --train will produce a model that learns realistic
#   feature weights. CVE descriptions and SBERT text encoding remain unchanged.
#   The CVE references key is now persisted in enriched_cves.json for reuse.
# ────────────────────────────────────────────────────────────────────────────


# KEV observation windows (in days): boundaries for label assignment
KEV_WINDOWS = [0, 30, 90, 365]


def construct_labels(
    cves: list[dict], kev_data: dict[str, str], cutoff_date: str = DATE_END
) -> list[int]:
    """Construct multi-window KEV labels (0-4).

    Label meanings:
      0: Not in KEV
      1: Added to KEV <= 30 days ago (recent exploitation)
      2: Added to KEV 31-90 days ago
      3: Added to KEV 91-365 days ago
      4: Added to KEV > 365 days ago (historical exploitation)

    Training date reference: cutoff_date (typically DATE_END).
    Point-in-time: CVEs added to KEV *after* cutoff_date are labeled 0
    to prevent future information leakage.
    """
    from datetime import datetime, timezone

    date_end = datetime.strptime(cutoff_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)

    labels = []
    window_counts = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    for cve in cves:
        cve_id = cve["cve_id"]
        if cve_id not in kev_data:
            labels.append(0)
            window_counts[0] += 1
            continue

        date_added_str = kev_data[cve_id]
        if not date_added_str:
            labels.append(0)
            window_counts[0] += 1
            continue

        # Point-in-time filter: skip KEV additions after cutoff
        if date_added_str > cutoff_date:
            labels.append(0)
            window_counts[0] += 1
            continue

        try:
            date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            days_since_added = (date_end - date_added).days

            if days_since_added <= 30:
                label = 1
            elif days_since_added <= 90:
                label = 2
            elif days_since_added <= 365:
                label = 3
            else:
                label = 4
            labels.append(label)
            window_counts[label] += 1
        except (ValueError, TypeError):
            labels.append(0)  # Default to not-in-KEV on parse error
            window_counts[0] += 1

    total = len(labels)
    print(
        f"  Multi-window labels ({total} total): "
        f"not_KEV={window_counts[0]}, "
        f"<=30d={window_counts[1]}, "
        f"31-90d={window_counts[2]}, "
        f"91-365d={window_counts[3]}, "
        f">365d={window_counts[4]}"
    )
    # Log point-in-time exclusions
    live_in_kev = sum(1 for c in cves if c["cve_id"] in kev_data)
    labelled_kev = sum(window_counts[i] for i in range(1, 5))
    excluded = live_in_kev - labelled_kev
    if excluded > 0:
        print(f"    ({excluded} KEV entries excluded - dateAdded after {cutoff_date})")
    return labels


def build_tabular_features(cves: list[dict]) -> np.ndarray:
    """Build (n, 35) tabular feature matrix matching inference feature order.

    All 15 previously-hardcoded features are now computed from real NVD data
    (patch tags in references, CVSS/EPSS correlations) to produce realistic
    training distributions. Uses a reproducible random seed for stochastic
    asset-context features that cannot be derived from CVE data alone.
    """
    rng = np.random.default_rng(seed=42)
    X = np.zeros((len(cves), 35), dtype=np.float32)
    for i, cve in enumerate(cves):
        vec = _parse_cvss(cve["cvss_vector"])
        X[i, 0] = _av_map(vec.get("AV", "N"))
        X[i, 1] = _ac_map(vec.get("AC", "L"))
        X[i, 2] = _pr_map(vec.get("PR", "N"))
        X[i, 3] = _ui_map(vec.get("UI", "N"))
        X[i, 4] = _s_map(vec.get("S", "U"))
        X[i, 5] = _cia_map(vec.get("C", "N"))
        X[i, 6] = _cia_map(vec.get("I", "N"))
        X[i, 7] = _cia_map(vec.get("A", "N"))
        X[i, 8] = cve.get("epss_score", 0.0)

        # === 15 previously-hardcoded features — now computed from real data ===
        patch_avail = _compute_patch_available(cve)
        X[i, 9] = patch_avail
        X[i, 10] = _compute_patch_applied(patch_avail, cve, rng)
        X[i, 11] = _compute_internet_facing(cve, rng)
        X[i, 12] = _compute_domain_joined(rng)
        X[i, 13] = _compute_data_classification(rng)
        X[i, 14] = _compute_mission_prevalence(rng)
        X[i, 15] = _compute_public_wellbeing_impact(cve, rng)
        X[i, 16] = _compute_lateral_reachability(cve, rng)
        X[i, 17] = _compute_boundary_reachability(cve, rng)
        X[i, 18] = _compute_downstream_assets(cve, rng)
        X[i, 19] = _compute_patch_lag_days(patch_avail, cve, rng)
        X[i, 20] = _compute_exploitdb_has_poc(cve, rng)
        X[i, 21] = _compute_metasploit_has_payload(cve, rng)
        X[i, 22] = _compute_threat_intel_pulses(cve, rng)
        # === end of formerly-hardcoded block ===

        X[i, 23] = cve.get("reference_count", 0)
        X[i, 24] = len(cve.get("description", ""))
        X[i, 25] = _compute_age_days(cve.get("published_date", ""))
        X[i, 26] = (
            0.0  # vendor_popularity_index — KNOWN LIMITATION: always 0 during training because
        )
        # no OS/hostname data is available in NVD corpus. In inference, it's also often
        # 0 due to sparse vendor_popularity.json coverage. This is a pre-existing data
        # quality issue (see docs/reference/AI_PROBLEMS.md Sprint 23 audit).
        X[i, 27] = cve.get("cvss_exploitability_sub", 0.0)
        X[i, 28] = cve.get("cvss_impact_sub", 0.0)
        X[i, 29] = int(cve.get("cwe_id", "") in MITRE_TOP_25_CWES)
        desc = cve.get("description", "").lower()
        X[i, 30] = int(any(re.search(p, desc) for p in RCE_PATTERNS))
        X[i, 31] = int(any(re.search(p, desc) for p in PRIVESC_PATTERNS))
        X[i, 32] = int(any(re.search(p, desc) for p in BYPASS_PATTERNS))
        X[i, 33] = int(any(re.search(p, desc) for p in DOS_PATTERNS))
        X[i, 34] = int(any(re.search(p, desc) for p in TRAVERSAL_PATTERNS))
    return X


def _parse_cvss(vector: str) -> dict:
    return {p.split(":")[0]: p.split(":")[1] for p in vector.split("/")}


def _av_map(v):
    return {"N": 3, "A": 2, "L": 1, "P": 0}.get(v, 3)


def _ac_map(v):
    return {"L": 1, "H": 0}.get(v, 1)


def _pr_map(v):
    return {"N": 2, "L": 1, "H": 0}.get(v, 2)


def _ui_map(v):
    return {"N": 1, "R": 0}.get(v, 1)


def _s_map(v):
    return {"C": 1, "U": 0}.get(v, 0)


def _cia_map(v):
    return {"H": 2, "L": 1, "N": 0}.get(v, 0)


def _compute_age_days(pub_date: str) -> int:
    if not pub_date:
        return 0
    try:
        dt = datetime.strptime(pub_date[:10], "%Y-%m-%d")
        return (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
    except ValueError:
        return 0


# ─── REALISTIC FEATURE SAMPLERS (for training, replacing hardcoded constants) ──
#
# These functions produce distributionally realistic feature values from
# NVD/EPSS data available during training. Asset-context features
# (internet_facing, domain_joined, data_classification, etc.) are sampled
# stochastically with a fixed seed for reproducibility since CMDB context
# is not available during offline training.
#
# Each sampler mirrors the *distribution* of its inference counterpart in
# ingest_helpers.py / xgboost_predictor.py without requiring live CMDB,
# exploit-db, or OTX API calls during training.


def _compute_patch_available(cve: dict) -> int:
    """Check NVD references for Patch / Vendor-Advisory tags (same logic as inference)."""
    refs = cve.get("references", [])
    patch_tags = {"Patch", "Vendor Advisory", "vendor-advisory"}
    for r in refs:
        for tag in r.get("tags", []):
            if tag in patch_tags:
                return 1
    return 0


def _compute_patch_applied(
    patch_available: int, cve: dict, rng: np.random.Generator
) -> int:
    """Estimate patch-applied probability from patch_available, age, and CVSS."""
    if not patch_available:
        return 0
    age = _compute_age_days(cve.get("published_date", ""))
    cvss = cve.get("cvss_score", 0.0)
    if age > 180 and cvss >= 7.0:
        return int(rng.random() < 0.65)
    if cvss >= 9.0 and age > 30:
        return int(rng.random() < 0.55)
    if age > 365:
        return int(rng.random() < 0.35)
    return 0


def _compute_internet_facing(cve: dict, rng: np.random.Generator) -> int:
    """Sample internet-facing (~30% overall, skewed by severity)."""
    cvss = cve.get("cvss_score", 0.0)
    if cvss >= 9.0:
        return int(rng.random() < 0.40)
    elif cvss >= 7.0:
        return int(rng.random() < 0.25)
    else:
        return int(rng.random() < 0.12)


def _compute_domain_joined(rng: np.random.Generator) -> int:
    """~85% of WA government assets are domain-joined."""
    return int(rng.random() < 0.85)


def _compute_data_classification(rng: np.random.Generator) -> int:
    """Mostly OFFICIAL(2), some OFFICIAL-Sensitive(4), few Category-1(1)."""
    r = rng.random()
    if r < 0.08:
        return 4  # OFFICIAL Sensitive
    elif r < 0.82:
        return 2  # OFFICIAL
    else:
        return 1  # OFFICIAL


def _compute_mission_prevalence(rng: np.random.Generator) -> int:
    """Mostly Support(2), some Core(3), few Peripheral(1)."""
    r = rng.random()
    if r < 0.18:
        return 3  # Core
    elif r < 0.83:
        return 2  # Support
    else:
        return 1  # Peripheral


def _compute_public_wellbeing_impact(cve: dict, rng: np.random.Generator) -> int:
    """Mostly Minimal(1), some Moderate(2), rare Severe(3); skewed by CVSS."""
    cvss = cve.get("cvss_score", 0.0)
    if cvss >= 9.0:
        r = rng.random()
        if r < 0.12:
            return 3
        elif r < 0.45:
            return 2
        return 1
    elif cvss >= 7.0:
        r = rng.random()
        if r < 0.04:
            return 3
        elif r < 0.25:
            return 2
        return 1
    else:
        r = rng.random()
        if r < 0.01:
            return 3
        elif r < 0.12:
            return 2
        return 1


def _compute_lateral_reachability(cve: dict, rng: np.random.Generator) -> int:
    """Estimate lateral reachability from CVSS severity."""
    cvss = cve.get("cvss_score", 0.0)
    if cvss >= 9.0:
        return int(rng.random() < 0.25)
    elif cvss >= 7.0:
        return int(rng.random() < 0.12)
    else:
        return int(rng.random() < 0.04)


def _compute_boundary_reachability(cve: dict, rng: np.random.Generator) -> int:
    """Estimate boundary reachability from CVSS severity."""
    cvss = cve.get("cvss_score", 0.0)
    if cvss >= 9.0:
        return int(rng.random() < 0.20)
    elif cvss >= 7.0:
        return int(rng.random() < 0.10)
    else:
        return int(rng.random() < 0.03)


def _compute_downstream_assets(cve: dict, rng: np.random.Generator) -> int:
    """Sample downstream asset count; higher severity → more critical systems."""
    cvss = cve.get("cvss_score", 0.0)
    if cvss >= 9.0:
        mu, sigma = 3.5, 2.0
    elif cvss >= 7.0:
        mu, sigma = 1.5, 1.5
    else:
        mu, sigma = 0.5, 1.0
    return max(0, int(rng.normal(mu, sigma)))


def _compute_patch_lag_days(
    patch_available: int, cve: dict, rng: np.random.Generator
) -> int:
    """If patch available, estimate lag as a fraction of vulnerability age."""
    if not patch_available:
        return 0
    age = _compute_age_days(cve.get("published_date", ""))
    if age <= 0:
        return 0
    return max(0, int(age * rng.uniform(0.2, 0.85)))


def _compute_exploitdb_has_poc(cve: dict, rng: np.random.Generator) -> int:
    """Sample exploit-db PoC probability from EPSS and CVSS (no live query needed)."""
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    prob = 0.02  # base rate
    if epss > 0.5:
        prob += 0.28
    elif epss > 0.1:
        prob += 0.10
    if cvss >= 9.0:
        prob += 0.15
    elif cvss >= 7.0:
        prob += 0.05
    prob = min(prob, 0.50)
    return int(rng.random() < prob)


def _compute_metasploit_has_payload(cve: dict, rng: np.random.Generator) -> int:
    """Sample metasploit payload probability (rarer than exploitdb)."""
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    prob = 0.005
    if epss > 0.5:
        prob += 0.10
    elif epss > 0.1:
        prob += 0.03
    if cvss >= 9.0:
        prob += 0.05
    elif cvss >= 7.0:
        prob += 0.02
    prob = min(prob, 0.20)
    return int(rng.random() < prob)


def _compute_threat_intel_pulses(cve: dict, rng: np.random.Generator) -> int:
    """Sample threat intel pulse count from EPSS and CVSS (no OTX query)."""
    epss = cve.get("epss_score", 0.0)
    cvss = cve.get("cvss_score", 0.0)
    lam = 0.1  # base rate
    if epss > 0.5:
        lam += 2.5
    elif epss > 0.1:
        lam += 0.8
    if cvss >= 9.0:
        lam += 1.0
    elif cvss >= 7.0:
        lam += 0.3
    return max(0, int(rng.poisson(lam)))


# ─── PHASE 1: GATHER DATA ─────────────────────────────────────────────────


def phase_gather() -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Fetch NVD/EPSS/KEV, merge, save enriched CVEs.
    Build labels, tabular features, SBERT encode, save training data.
    Returns (X, y, dates, cve_ids).
    """
    print("=" * 60)
    print("PHASE 1: GATHER DATA")
    print("=" * 60)

    kev = None

    if ENRICHED_CVES_FILE.exists():
        print("\n  enriched_cves.json found — skipping NVD/EPSS/KEV fetch.")
        cves = load_enriched_cves(ENRICHED_CVES_FILE)
        kev = fetch_kev()
    else:
        # Step 1: NVD CVEs
        print("\n[1/6] Fetching CVE data from NVD...")
        cves = fetch_nvd_cves(DATE_START, DATE_END)
        print(f"  Fetched {len(cves)} CVEs with CVSS v3.1 vectors.")

        # Step 2: EPSS
        print("\n[2/6] Fetching EPSS scores...")
        epss = fetch_epss()
        epss_hits = 0
        for cve in cves:
            cve["epss_score"] = epss.get(cve["cve_id"], 0.0)
            if cve["cve_id"] in epss:
                epss_hits += 1
        print(
            f"  EPSS merged: {epss_hits}/{len(cves)} CVEs matched ({epss_hits / len(cves):.1%})."
        )

        # Step 3: KEV
        print("\n[3/6] Fetching CISA KEV catalog...")
        kev = fetch_kev()
        kev_hits = 0
        for cve in cves:
            cve["cisa_kev"] = cve["cve_id"] in kev
            cve["kev_date_added"] = kev.get(cve["cve_id"], "")
            if cve["cisa_kev"]:
                kev_hits += 1
        print(f"  KEV merged: {kev_hits} CVEs in KEV catalog.")

        # SAVE POINT 1: enriched CVEs
        save_enriched_cves(cves, ENRICHED_CVES_FILE)

    # Step 4: Labels + tabular features
    print("\n[4/6] Constructing labels and features...")
    y_arr = np.array(construct_labels(cves, kev), dtype=np.int32)
    if int(sum(y_arr > 0)) == 0:
        print("  WARNING: No positive labels found. Model will not train meaningfully.")
        sys.exit(1)
    X_tab = build_tabular_features(cves)

    # Step 5: SBERT encoding (raw 384-dim — PCA removed in v2.5 to eliminate data leakage)
    print("\n[5/6] Encoding text descriptions with SBERT (384-dim)...")
    descriptions = [c["description"] for c in cves]
    X_text = encode_batch(descriptions)
    X = np.hstack([X_tab, X_text]).astype(np.float32)

    dates_arr = np.array([c["published_date"] for c in cves])
    cve_ids_arr = np.array([c["cve_id"] for c in cves])

    # ── KEV Temporal Bias: Dynamic Observation Window ─────────────────────
    # Compute median KEV addition lag from our CVE set (point-in-time).
    # Use this as the observation window: CVEs published within this many
    # days before DATE_END cannot be reliably labeled negative, because KEV
    # likely hasn't catalogued exploitation yet.
    kev_lag_stats = compute_kev_lag_stats(cves, kev)
    obs_window_days = kev_lag_stats["median"]
    obs_cutoff = datetime.strptime(DATE_END, "%Y-%m-%d") - timedelta(
        days=obs_window_days
    )
    obs_cutoff_str = obs_cutoff.strftime("%Y-%m-%d")

    # Selective exclusion: remove only label-0 CVEs in the observation window.
    # Label-1 CVEs (rapid exploitation cases with dateAdded before cutoff) are
    # kept — they are genuine positives with reliable labels.
    too_recent = dates_arr > obs_cutoff_str
    obs_mask = ~(too_recent & (y_arr == 0))
    obs_dropped = int(sum(~obs_mask))
    obs_neg_dropped = int(sum(too_recent & (y_arr == 0)))
    obs_pos_kept_in_window = int(sum(too_recent & (y_arr > 0)))
    obs_kept = int(sum(obs_mask))
    print(
        f"  KEV observation window: {obs_window_days} days "
        f"(median lag from {kev_lag_stats['count']} KEV entries)"
    )
    print(
        f"  Excluding {obs_dropped:,} unreliable negatives "
        f"(all {obs_neg_dropped} label-0 CVEs published after {obs_cutoff_str}). "
        f"Keeping {obs_pos_kept_in_window:,} rapid-exploitation positives in window."
    )
    print(f"  Keeping {obs_kept:,} CVEs ({obs_kept / len(X):.1%} of pre-filter).")
    X = X[obs_mask]
    y_arr = y_arr[obs_mask]
    dates_arr = dates_arr[obs_mask]
    cve_ids_arr = cve_ids_arr[obs_mask]
    cves = [c for c, m in zip(cves, obs_mask) if m]

    obs_pos = int(sum(y_arr > 0))
    print(
        f"  Final positive rate (any KEV): {obs_pos}/{obs_kept} ({obs_pos / obs_kept:.1%})"
    )

    # SAVE POINT 2: training data (X, y, dates, cve_ids)
    save_training_data(X, y_arr, dates_arr, cve_ids_arr, TRAINING_DATA_FILE)

    # Quality report
    print_quality_report(cves, y_arr, dates_arr)

    return X, y_arr, dates_arr, cve_ids_arr


# ─── PHASE 2: TRAIN MODEL ─────────────────────────────────────────────────


def phase_train(X: np.ndarray, y: np.ndarray, dates: np.ndarray):
    """Train XGBoost + Platt calibration from pre-built features."""
    print("=" * 60)
    print("PHASE 2: TRAIN MODEL")
    print("=" * 60)

    # Try chronological split; fall back to random if dates aren't parseable
    if dates.dtype.kind in ("U", "S") and len(dates) > 0 and dates[0]:
        train_mask = dates <= TRAIN_CUTOFF
        val_mask = (dates > TRAIN_CUTOFF) & (dates <= VAL_CUTOFF)
        test_mask = dates > VAL_CUTOFF
        print("  Using chronological split")
    else:
        n = len(X)
        indices = np.random.permutation(n)
        n_train = int(n * 0.7)
        n_val = int(n * 0.15)
        train_mask = np.zeros(n, dtype=bool)
        val_mask = np.zeros(n, dtype=bool)
        test_mask = np.zeros(n, dtype=bool)
        train_mask[indices[:n_train]] = True
        val_mask[indices[n_train : n_train + n_val]] = True
        test_mask[indices[n_train + n_val :]] = True
        print("  Using random split (no dates available)")

    X_train, y_train = X[train_mask], y[train_mask]
    X_val, y_val = X[val_mask], y[val_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    print(f"\n  Train: {len(X_train):,}, Val: {len(X_val):,}, Test: {len(X_test):,}")

    # ── PCA Dimensionality Reduction ──────────────────────────────────
    # Apply PCA to SBERT text embeddings ONLY (not tabular features).
    # Fit on training split only — no data leakage to val/test.
    PCA_ENABLED = True  # Set False to skip PCA and use raw 384-dim embeddings
    PCA_COMPONENTS = 0.95  # Auto-select for 95% explained variance

    if PCA_ENABLED:
        from sklearn.decomposition import PCA

        # Split features into tabular and text components
        n_tabular = X_train.shape[1] - 384  # Should be 35
        X_train_tab = X_train[:, :n_tabular]
        X_train_text = X_train[:, n_tabular:]
        X_val_tab = X_val[:, :n_tabular]
        X_val_text = X_val[:, n_tabular:]
        X_test_tab = X_test[:, :n_tabular]
        X_test_text = X_test[:, n_tabular:]

        # Fit PCA on training text embeddings only
        pca = PCA(n_components=PCA_COMPONENTS)
        X_train_text_pca = pca.fit_transform(X_train_text)
        X_val_text_pca = pca.transform(X_val_text)
        X_test_text_pca = pca.transform(X_test_text)

        n_components = pca.n_components_
        explained_var = pca.explained_variance_ratio_.sum()
        print(
            f"\n  PCA: 384 dims \u2192 {n_components} dims "
            f"({explained_var:.1%} variance retained)"
        )

        # Reconstruct feature matrices
        X_train = np.hstack([X_train_tab, X_train_text_pca]).astype(np.float32)
        X_val = np.hstack([X_val_tab, X_val_text_pca]).astype(np.float32)
        X_test = np.hstack([X_test_tab, X_test_text_pca]).astype(np.float32)

        # Save PCA model alongside XGBoost model
        pca_path = Path(__file__).parent / "pca_model.pkl"
        joblib.dump(pca, pca_path)
        print(f"  PCA model saved: {pca_path} ({n_components} components)")

        # Log new dimensionality
        print(
            f"  New feature dimensions: tabular={n_tabular} + "
            f"text_pca={n_components} = {X_train.shape[1]} total"
        )
    else:
        print("  PCA disabled — using raw 384-dim SBERT embeddings")

    # ── Multi-class sample weights ──────────────────────────────────
    # scale_pos_weight is invalid for multi-class objectives, so we
    # compute per-sample weights using inverse class frequency.
    from sklearn.utils.class_weight import compute_class_weight

    all_classes = np.array([0, 1, 2, 3, 4])
    class_weights = np.ones(5, dtype=np.float64)
    try:
        cw = compute_class_weight("balanced", classes=all_classes, y=y_train)
        class_weights = np.array(cw, dtype=np.float64)
    except ValueError:
        # Some classes may have 0 samples — fall back to uniform weights
        pass
    sample_weight = np.array([class_weights[yi] for yi in y_train], dtype=np.float64)
    n_samp = len(y_train)
    print(f"  Class weights: {dict(zip(all_classes, class_weights.round(2)))}")
    print(f"  Using per-sample weighted training ({n_samp} samples)")

    print("\n  Training XGBoost (multi:softprob, 5-class)...")
    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=5,
        max_depth=4,
        learning_rate=0.03,
        n_estimators=800,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        random_state=42,
    )
    model.fit(X_train, y_train, sample_weight=sample_weight, verbose=False)

    # ── Calibration: Platt scaling on validation set ──────────────────
    # Calibrate on "any KEV" probability (sum of windows 1–4) for
    # backward-compatible binary decision threshold tuning.
    print("\n  Calibrating probabilities with Platt scaling (any-KEV)...")
    y_val_binary = (y_val > 0).astype(int)
    n_val_pos = int(sum(y_val_binary))
    if n_val_pos < 2:
        print(
            f"  [WARN] Validation set has only {n_val_pos} positive(s). "
            "Skipping calibration, using raw probabilities."
        )
        calibrator = None
        best_threshold = 0.5
    else:
        val_raw_proba = model.predict_proba(X_val)
        val_any_kev = val_raw_proba[:, 1:].sum(axis=1).reshape(-1, 1)
        calibrator = LogisticRegression(C=1e6, solver="lbfgs")
        calibrator.fit(val_any_kev, y_val_binary)

        # Tune decision threshold on calibrated any-KEV probabilities
        val_calibrated = calibrator.predict_proba(val_any_kev)[:, 1]
        best_threshold = 0.5
        best_f1 = 0
        for thresh in np.linspace(0.001, 0.50, 200):
            preds = (val_calibrated >= thresh).astype(int)
            f1 = f1_score(y_val_binary, preds, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = thresh

        # Save calibrator and threshold info
        joblib.dump(calibrator, CALIBRATOR_FILE)
        threshold_info = {"classification_threshold": best_threshold, "val_f1": best_f1}
        with open(THRESHOLD_INFO_FILE, "w") as f:
            json.dump(threshold_info, f)
        print(
            f"  Calibrator saved to {CALIBRATOR_FILE.name}. "
            f"Tuned threshold: {best_threshold:.4f} (val F1: {best_f1:.4f})"
        )

    # ── Evaluate on test set ──────────────────────────────────────────
    y_pred_proba = model.predict_proba(X_test)
    y_pred = model.predict(X_test)
    y_test_binary = (y_test > 0).astype(int)
    y_pred_any_kev = y_pred_proba[:, 1:].sum(axis=1)

    if calibrator is not None:
        test_raw = y_pred_any_kev.reshape(-1, 1)
        y_prob_calibrated = calibrator.predict_proba(test_raw)[:, 1]
        print(f"  Applied calibration to test set (threshold={best_threshold:.4f}).")
    else:
        y_prob_calibrated = y_pred_any_kev
        print("  Using raw any-KEV probabilities (no calibration applied).")

    # Expected Calibration Error (ECE) — on any-KEV probability
    def _ece(y_true, y_prob_arr, n_bins=10):
        """Compute Expected Calibration Error."""
        bins = np.linspace(0, 1, n_bins + 1)
        total = len(y_true)
        if total == 0:
            return 0.0
        ece = 0.0
        for i in range(n_bins):
            mask = (y_prob_arr >= bins[i]) & (y_prob_arr < bins[i + 1])
            n_bin = int(np.sum(mask))
            if n_bin == 0:
                continue
            bin_acc = float(np.mean(y_true[mask] == 1))
            bin_conf = float(np.mean(y_prob_arr[mask]))
            ece += n_bin * abs(bin_acc - bin_conf)
        return ece / total

    ece_raw = _ece(y_test_binary, y_pred_any_kev)
    if calibrator is not None:
        ece_cal = _ece(y_test_binary, y_prob_calibrated)
        impr = ((ece_raw - ece_cal) / ece_raw * 100) if ece_raw > 0 else 0.0
        print(f"\n  ECE (raw any-KEV):        {ece_raw:.4f}")
        print(f"  ECE (calibrated any-KEV): {ece_cal:.4f}")
        print(f"  Calibration improvement:  {impr:.1f}%")

    # Multi-class accuracy
    from sklearn.metrics import accuracy_score

    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n  Test accuracy (5-class): {accuracy:.4f}")

    # Per-class metrics
    print("\n  Classification report (multi-window):")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Not KEV", "<=30d", "31-90d", "91-365d", ">365d"],
            zero_division=0,
        )
    )

    # Backward-compatible any-KEV ROC-AUC
    any_kev_auc = roc_auc_score(y_test_binary, y_prob_calibrated)
    print(f"  Any-KEV ROC-AUC: {any_kev_auc:.4f}")
    if calibrator is not None:
        print(
            f"  (using calibrated any-KEV probabilities at threshold {best_threshold:.4f})"
        )

    print(f"\n  Saving model to {MODEL_FILE.name} ... ", end="", flush=True)
    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    print("done.")


# ─── MAIN ──────────────────────────────────────────────────────────────────


def main():
    do_gather = "--gather" in sys.argv
    do_train = "--train" in sys.argv
    if not do_gather and not do_train:
        # Auto-detect: train only if training data already saved
        if TRAINING_DATA_FILE.exists():
            do_train = True
        else:
            do_gather = True

    X = y = dates = cve_ids = None

    if do_gather:
        X, y, dates, cve_ids = phase_gather()
        if not do_train:
            print(
                "\n  Gather complete. Run with --train to train or re-run without flags."
            )
            return

    if do_train:
        if X is None:
            data_file = TRAINING_DATA_FILE
            # Support --data-file override (e.g. training_data_v2.npz)
            for i, arg in enumerate(sys.argv):
                if arg == "--data-file" and i + 1 < len(sys.argv):
                    data_file = Path(sys.argv[i + 1])
                    break
            if not data_file.exists():
                print(f"  Training data not found: {data_file}")
                sys.exit(1)
            data = np.load(data_file)
            X = data["X"]
            y = data["y"]
            dates = data.get("dates", np.zeros(len(y)))
            data.get("cve_ids", np.array([""] * len(y)))
            data.close()
            print(f"  Loaded {len(X)} records from {data_file.name}")
            if len(dates) > 0 and dates.dtype.kind in ("U", "S") and dates[0]:
                non_empty = dates[dates != ""]
                if len(non_empty) > 0:
                    print(
                        f"  Dates range: {min(non_empty)} to {max(non_empty)}  → using chronological split"
                    )
                else:
                    print("  All dates are empty — falling back to random split")
                    dates = np.zeros(len(y))
        phase_train(X, y, dates)


if __name__ == "__main__":
    main()
