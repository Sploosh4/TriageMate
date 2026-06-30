"""
Offline XGBoost training pipeline — two-phase design.

Phase 1 (Gather): Fetch NVD/EPSS/KEV, build features, encode text, save to disk.
Phase 2 (Train):  Load saved features, train XGBoost + Platt, export model.

Save points:
    enriched_cves.json   — after NVD + EPSS + KEV merge (skip re-fetch)
    training_data.npz    — after label/feature/PCA construction (skip re-encoding)

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
from sklearn.metrics import classification_report, roc_auc_score

from ml.encoder import fit_pca, encode_batch

OUTPUT_DIR = Path(__file__).parent
MODEL_FILE = OUTPUT_DIR / "xgboost_model.pkl"
PCA_FILE = OUTPUT_DIR / "pca_reducer.pkl"
NVD_CHECKPOINT = OUTPUT_DIR / "nvd_checkpoint.json"
NVD_CACHE_FILE = OUTPUT_DIR / "nvd_cves_cached.json"
ENRICHED_CVES_FILE = OUTPUT_DIR / "enriched_cves.json"
TRAINING_DATA_FILE = OUTPUT_DIR / "training_data.npz"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NVD_API_KEY = os.getenv("NVD_API_KEY", "")

DATE_START = "2019-01-01"
DATE_END = "2024-12-31"
KEV_START = "2021-11-01"
TRAIN_CUTOFF = "2023-06-30"
VAL_CUTOFF = "2023-12-31"
OBS_WINDOW = 30
BATCH_SIZE = 200
SLEEP_INTERVAL = 6.2

RCE_PATTERNS = [r"remote code execution", r"arbitrary code", r"execute arbitrary"]
PRIVESC_PATTERNS = [r"privilege escalation", r"elevat\w+ privilege"]
BYPASS_PATTERNS = [r"bypass", r"authentication bypass", r"access control"]
DOS_PATTERNS = [r"denial of service", r"dos", r"resource exhaustion"]
TRAVERSAL_PATTERNS = [r"directory traversal", r"path traversal", r"\.\.[\\/]"]

MITRE_TOP_25_CWES = {
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78",
    "CWE-20", "CWE-125", "CWE-22", "CWE-352", "CWE-434",
    "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-502",
    "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306",
    "CWE-362", "CWE-269", "CWE-94", "CWE-863", "CWE-276",
}

# ─── SAVE / LOAD ───────────────────────────────────────────────────────────

def save_enriched_cves(cves: list[dict], path: Path):
    """Save NVD CVEs with merged EPSS/KEV to JSON."""
    print(f"  Writing {len(cves)} enriched CVEs to {path.name} ... ", end="", flush=True)
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


def save_training_data(X: np.ndarray, y: np.ndarray, dates: np.ndarray,
                       cve_ids: np.ndarray, path: Path):
    """Save (n, 36+32) features, labels, dates, and CVE IDs to compressed .npz."""
    print(f"  Writing training data to {path.name} ... ", end="", flush=True)
    np.savez_compressed(path, X=X, y=y, dates=dates, cve_ids=cve_ids)
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
        print(f"\n  [migrate] Old 69-column data detected. Stripping cisa_kev (column 9)...")
        keep = [i for i in range(69) if i != 9]
        X = X[:, keep]
        save_training_data(X, y_arr, dates_arr, cve_ids_arr, path)
    print(f"  {X.shape[0]} records, {n_cols}→{X.shape[1]} features.")
    return X, y_arr, dates_arr, cve_ids_arr


# ─── QUALITY REPORT ────────────────────────────────────────────────────────

def print_quality_report(cves: list[dict], y: np.ndarray, dates: np.ndarray):
    """Print a data-quality summary before training."""
    cve_ids_arr = np.array([c["cve_id"] for c in cves])
    n_pos = int(sum(y == 1))
    n_total = len(y)

    print("\n" + "=" * 60)
    print("DATA QUALITY REPORT")
    print("=" * 60)

    print(f"\n  Total CVEs:           {n_total:,}")
    print(f"  Exploited (label=1):  {n_pos:,}  ({n_pos/n_total:.3%})")
    print(f"  Not exploited:        {n_total - n_pos:,}  ({(n_total-n_pos)/n_total:.3%})")

    train = dates <= TRAIN_CUTOFF
    val = (dates > TRAIN_CUTOFF) & (dates <= VAL_CUTOFF)
    test = dates > VAL_CUTOFF

    for name, mask in [("Train", train), ("Val", val), ("Test", test)]:
        n = int(sum(mask))
        n_p = int(sum(y[mask] == 1))
        pct = n_p / n * 100 if n > 0 else 0
        print(f"  {name:>5} set:           {n:,} CVEs  (positives: {n_p} = {pct:.2f}%)")

    pos_ids = cve_ids_arr[y == 1]
    print(f"\n  Positive CVE IDs (first 20): {', '.join(pos_ids[:20].tolist())}")

    pos_cwes = Counter(cve["cwe_id"] for cve, lab in zip(cves, y) if lab == 1 and cve["cwe_id"])
    neg_cwes = Counter(cve["cwe_id"] for cve, lab in zip(cves, y) if lab == 0 and cve["cwe_id"])
    common_pos = pos_cwes.most_common(10)
    common_neg = neg_cwes.most_common(10)

    if common_pos:
        print(f"\n  Top CWE among exploited: {', '.join(f'{c} ({n})' for c, n in common_pos)}")
    if common_neg:
        print(f"  Top CWE among non-exploited: {', '.join(f'{c} ({n})' for c, n in common_neg[:5])}")

    pos_cvss = [c["cvss_score"] for c, lab in zip(cves, y) if lab == 1]
    neg_cvss = [c["cvss_score"] for c, lab in zip(cves, y) if lab == 0]
    if pos_cvss:
        print(f"\n  Mean CVSS (exploited):     {np.mean(pos_cvss):.1f}")
    print(f"  Mean CVSS (not exploited): {np.mean(neg_cvss):.1f}")

    pos_epss = [c.get("epss_score", 0) for c, lab in zip(cves, y) if lab == 1]
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
                    resp = requests.get(NVD_API, params=params, headers=headers, timeout=120)
                    break
                except requests.exceptions.RequestException as e:
                    wait = (attempt + 1) * 15
                    print(f"    {type(e).__name__}, retrying in {wait}s (attempt {attempt+1}/5)...")
                    time.sleep(wait)
            else:
                print(f"    Failed after 5 attempts. Progress saved ({len(all_cves)} CVEs). Resume by re-running.")
                _save_progress(all_cves, chunk_key, start_idx)
                raise RuntimeError(f"Failed after 5 attempts at {chunk_start}..{chunk_end} index {start_idx}")

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
                all_cves.append({
                    "cve_id": cve["id"],
                    "description": desc_en,
                    "cvss_score": cvss_v31["baseScore"],
                    "cvss_vector": cvss_v31["vectorString"],
                    "published_date": cve.get("published", "")[:10],
                    "cwe_id": _extract_cwe(cve),
                    "reference_count": len(cve.get("references", [])),
                    "cvss_exploitability_sub": cvss_v31.get("exploitabilityScore", 0),
                    "cvss_impact_sub": cvss_v31.get("impactScore", 0),
                })

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
        resp = requests.get(EPSS_API, params={"offset": offset, "limit": limit}, timeout=60)
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


# ─── FEATURE ENGINEERING ───────────────────────────────────────────────────

def construct_labels(cves: list[dict], kev_data: dict[str, str]) -> list[int]:
    """Label each CVE: 1 = appears in CISA KEV catalog (exploited), 0 = not."""
    kev_set = set(kev_data.keys())
    labels = []
    pos_count = 0
    for cve in cves:
        if cve["cve_id"] in kev_set:
            labels.append(1)
            pos_count += 1
        else:
            labels.append(0)

    print(f"  Labels: {pos_count} positive (in KEV) out of {len(labels)} "
          f"({pos_count/len(labels):.1%})")
    return labels


def build_tabular_features(cves: list[dict]) -> np.ndarray:
    """Build (n, 36) tabular feature matrix (cisa_kev excluded — it is the label)."""
    X = np.zeros((len(cves), 36), dtype=np.float32)
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
        X[i, 9] = 1
        X[i, 10] = 0
        X[i, 11] = 0
        X[i, 12] = 1
        X[i, 13] = 2
        X[i, 14] = 2
        X[i, 15] = 1
        X[i, 16] = 0
        X[i, 17] = 0
        X[i, 18] = 0
        X[i, 19] = cve.get("patch_lag_days", 0)
        X[i, 20] = 0
        X[i, 21] = 0
        X[i, 22] = 0
        X[i, 23] = 0
        X[i, 24] = cve.get("reference_count", 0)
        X[i, 25] = len(cve.get("description", ""))
        X[i, 26] = _compute_age_days(cve.get("published_date", ""))
        X[i, 27] = 0.0
        X[i, 28] = cve.get("cvss_exploitability_sub", 0.0)
        X[i, 29] = cve.get("cvss_impact_sub", 0.0)
        X[i, 30] = int(cve.get("cwe_id", "") in MITRE_TOP_25_CWES)
        desc = cve.get("description", "").lower()
        X[i, 31] = int(any(re.search(p, desc) for p in RCE_PATTERNS))
        X[i, 32] = int(any(re.search(p, desc) for p in PRIVESC_PATTERNS))
        X[i, 33] = int(any(re.search(p, desc) for p in BYPASS_PATTERNS))
        X[i, 34] = int(any(re.search(p, desc) for p in DOS_PATTERNS))
        X[i, 35] = int(any(re.search(p, desc) for p in TRAVERSAL_PATTERNS))
    return X


def _parse_cvss(vector: str) -> dict:
    return {p.split(":")[0]: p.split(":")[1] for p in vector.split("/")}

def _av_map(v): return {"N": 3, "A": 2, "L": 1, "P": 0}.get(v, 3)
def _ac_map(v): return {"L": 1, "H": 0}.get(v, 1)
def _pr_map(v): return {"N": 2, "L": 1, "H": 0}.get(v, 2)
def _ui_map(v): return {"N": 1, "R": 0}.get(v, 1)
def _s_map(v):  return {"C": 1, "U": 0}.get(v, 0)
def _cia_map(v): return {"H": 2, "L": 1, "N": 0}.get(v, 0)

def _compute_age_days(pub_date: str) -> int:
    if not pub_date:
        return 0
    try:
        dt = datetime.strptime(pub_date[:10], "%Y-%m-%d")
        return (datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)).days
    except ValueError:
        return 0


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
        print(f"  EPSS merged: {epss_hits}/{len(cves)} CVEs matched ({epss_hits/len(cves):.1%}).")

        # Step 3: KEV
        print("\n[3/6] Fetching CISA KEV catalog...")
        kev = fetch_kev()
        kev_hits = 0
        for cve in cves:
            cve["cisa_kev"] = cve["cve_id"] in kev
            if cve["cisa_kev"]:
                kev_hits += 1
        print(f"  KEV merged: {kev_hits} CVEs in KEV catalog.")

        # SAVE POINT 1: enriched CVEs
        save_enriched_cves(cves, ENRICHED_CVES_FILE)

    # Step 4: Labels + tabular features
    print("\n[4/6] Constructing labels and features...")
    y_arr = np.array(construct_labels(cves, kev), dtype=np.int32)
    if int(sum(y_arr == 1)) == 0:
        print("  WARNING: No positive labels found. Model will not train meaningfully.")
        sys.exit(1)
    X_tab = build_tabular_features(cves)

    # Step 5: SBERT encoding + PCA (this is the expensive part — 13+ minutes)
    print("\n[5/6] Encoding text descriptions and fitting PCA...")
    descriptions = [c["description"] for c in cves]
    fit_pca(descriptions, save=True)
    X_text = encode_batch(descriptions)
    X = np.hstack([X_tab, X_text]).astype(np.float32)

    dates_arr = np.array([c["published_date"] for c in cves])
    cve_ids_arr = np.array([c["cve_id"] for c in cves])

    # Filter to post-KEV-era CVEs only — CVEs published before the CISA KEV
    # catalog existed (November 2021) structurally cannot be labeled positive.
    post_kev_mask = dates_arr >= KEV_START
    dropped = int(sum(~post_kev_mask))
    remaining = int(sum(post_kev_mask))
    print(f"\n  Filtering to post-{KEV_START} CVEs: "
          f"keeping {remaining:,}, dropping {dropped:,} pre-KEV CVEs.")
    X = X[post_kev_mask]
    y_arr = y_arr[post_kev_mask]
    dates_arr = dates_arr[post_kev_mask]
    cve_ids_arr = cve_ids_arr[post_kev_mask]
    cves = [c for c, m in zip(cves, post_kev_mask) if m]

    pos_total = int(sum(y_arr == 1))
    print(f"  Post-filter positive rate: {pos_total}/{remaining} "
          f"({pos_total/remaining:.1%})")
    if pos_total == 0:
        print("  WARNING: No positive labels after filtering. Cannot train.")
        sys.exit(1)

    # Exclude CVEs published within OBS_WINDOW days of DATE_END.
    # These are too recent for KEV to have catalogued exploitation — labeling them
    # as negative would create systematic false negatives.
    obs_cutoff = datetime.strptime(DATE_END, "%Y-%m-%d") - timedelta(days=OBS_WINDOW)
    obs_cutoff_str = obs_cutoff.strftime("%Y-%m-%d")
    obs_mask = dates_arr <= obs_cutoff_str
    obs_dropped = int(sum(~obs_mask))
    obs_kept = int(sum(obs_mask))
    print(f"  Excluding {obs_dropped:,} CVEs published after {obs_cutoff_str} "
          f"({OBS_WINDOW}-day observation window). Keeping {obs_kept:,}.")
    X = X[obs_mask]
    y_arr = y_arr[obs_mask]
    dates_arr = dates_arr[obs_mask]
    cve_ids_arr = cve_ids_arr[obs_mask]
    cves = [c for c, m in zip(cves, obs_mask) if m]

    obs_pos = int(sum(y_arr == 1))
    print(f"  Final positive rate: {obs_pos}/{obs_kept} ({obs_pos/obs_kept:.1%})")

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

    train_mask = dates <= TRAIN_CUTOFF
    val_mask = (dates > TRAIN_CUTOFF) & (dates <= VAL_CUTOFF)
    test_mask = dates > VAL_CUTOFF

    X_train, y_train = X[train_mask], y[train_mask]
    X_val, y_val = X[val_mask], y[val_mask]
    X_test, y_test = X[test_mask], y[test_mask]

    print(f"\n  Train: {len(X_train):,}, Val: {len(X_val):,}, Test: {len(X_test):,}")

    n_neg = int(sum(y_train == 0))
    n_pos = int(sum(y_train == 1))
    sw = n_neg / n_pos if n_pos > 0 else 15.0
    print(f"  scale_pos_weight = {sw:.1f} ({n_neg} neg / {n_pos} pos)")

    print("\n  Training XGBoost (binary:logistic, no separate calibration)...")
    model = xgb.XGBClassifier(
        max_depth=4, learning_rate=0.03, n_estimators=800,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=sw, tree_method="hist",
        random_state=42,
    )
    model.fit(X_train, y_train, verbose=False)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 60)
    print("TEST SET RESULTS")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["Not Exploited", "Exploited"],
                                 zero_division=0))
    roc = roc_auc_score(y_test, y_prob)
    print(f"  ROC-AUC: {roc:.4f}")

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
            print("\n  Gather complete. Run with --train to train or re-run without flags.")
            return

    if do_train:
        if X is None:
            if not TRAINING_DATA_FILE.exists():
                print("  No training data found. Run with --gather first.")
                sys.exit(1)
            X, y, dates, cve_ids = load_training_data(TRAINING_DATA_FILE)
        phase_train(X, y, dates)


if __name__ == "__main__":
    main()
