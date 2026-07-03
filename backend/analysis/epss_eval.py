"""
EPSS as Standalone Predictor — Baseline Analysis
=================================================
Determine whether EPSS score alone can predict KEV entry,
and whether a threshold-based rule matches or exceeds XGBoost.

All code blocks from the execution prompt are included verbatim.
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score,
)
from sklearn.model_selection import StratifiedKFold
import xgboost as xgb

BASE = Path(__file__).resolve().parent.parent / "data"

# =====================================================================
# 1. Load and Align Data
# =====================================================================
print("Loading data...")
nvd = json.load(open(BASE / "nvd_corpus.json"))
epss_raw = json.load(open(BASE / "epss_cache.json"))
kev_raw = json.load(open(BASE / "kev_cache.json"))
print(f"NVD: {len(nvd)} entries")
print(f"EPSS: {len(epss_raw)} entries")
print(f"KEV: {len(kev_raw)} entries")

# Build aligned DataFrame
records = []
for cve_id, meta in nvd.items():
    epss_entry = epss_raw.get(cve_id, {})
    epss_score = epss_entry.get("epss", 0.0) if isinstance(epss_entry, dict) else 0.0
    epss_pct = (
        epss_entry.get("percentile", 0.0) if isinstance(epss_entry, dict) else 0.0
    )
    has_epss = cve_id in epss_raw
    kev_entry = kev_raw.get(cve_id, {})
    in_kev = (
        kev_entry.get("known_exploited", False)
        if isinstance(kev_entry, dict)
        else False
    )
    date_added = kev_entry.get("date_added", "") if isinstance(kev_entry, dict) else ""

    # Point-in-time label matching train_xgboost.py
    label = 1 if (in_kev and date_added and date_added <= "2024-12-31") else 0

    records.append(
        {
            "cve_id": cve_id,
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "has_epss": has_epss,
            "label": label,
            "cvss_score": meta.get("cvss_v3_score", 0.0),
            "cvss_vector": meta.get("cvss_v3_vector", ""),
            "cwe_class": meta.get("cwe_class", "NONE"),
            "age_days": meta.get("vulnerability_age_days", 0),
            "patch_available": meta.get("patch_available", False),
            "exploitdb_has_poc": meta.get("exploitdb_has_poc", False),
            "metasploit_has_payload": meta.get("metasploit_has_payload", False),
            "nvd_reference_count": meta.get("nvd_reference_count", 0),
            "cvss_exploitability_sub": meta.get("cvss_exploitability_sub", 0.0),
            "cvss_impact_sub": meta.get("cvss_impact_sub", 0.0),
        }
    )

df = pd.DataFrame(records)
total_pos = df["label"].sum()
print(f"\nTotal CVEs: {len(df):,}")
print(f"Positive labels: {total_pos} ({total_pos / len(df) * 100:.4f}%)")
print(
    f"Missing EPSS: {len(df) - df['has_epss'].sum()} ({((len(df) - df['has_epss'].sum()) / len(df) * 100):.1f}%)"
)
print(
    f"EPSS == 0.0: {(df['epss_score'] == 0.0).sum()} ({(df['epss_score'] == 0.0).mean() * 100:.1f}%)"
)

# =====================================================================
# 2. EPSS Distribution Report
# =====================================================================
print("\n=== EPSS DISTRIBUTION ===")
pos = df[df["label"] == 1]
neg = df[df["label"] == 0]
print(
    f"KEV positives: mean EPSS={pos['epss_score'].mean():.6f}, median={pos['epss_score'].median():.6f}"
)
print(
    f"KEV negatives: mean EPSS={neg['epss_score'].mean():.6f}, median={neg['epss_score'].median():.6f}"
)
print(
    f"EPSS zeros among positives: {(pos['epss_score'] == 0.0).sum()} ({(pos['epss_score'] == 0.0).mean() * 100:.1f}%)"
)

# Percentile analysis
print(
    f"\nKEV positives: mean percentile={pos['epss_percentile'].mean():.4f}, median={pos['epss_percentile'].median():.4f}"
)
print(
    f"KEV negatives: mean percentile={neg['epss_percentile'].mean():.4f}, median={neg['epss_percentile'].median():.4f}"
)

# =====================================================================
# 3. Threshold Search with 5-Fold CV
# =====================================================================
THRESHOLDS = (
    list(np.arange(0.0, 0.05, 0.001))
    + list(np.arange(0.05, 0.30, 0.005))
    + list(np.arange(0.30, 1.01, 0.02))
)
THRESHOLDS = sorted(set(round(t, 4) for t in THRESHOLDS))
print(f"\n=== THRESHOLD SEARCH ({len(THRESHOLDS)} thresholds, 5-fold CV) ===")

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = []
for t in THRESHOLDS:
    fold_metrics = []
    for train_idx, val_idx in skf.split(df["epss_score"], df["label"]):
        y_true = df["label"].values[val_idx]
        y_pred = (df["epss_score"].values[val_idx] >= t).astype(int)
        fold_metrics.append(
            {
                "f1": f1_score(y_true, y_pred, zero_division=0),
                "f2": fbeta_score(y_true, y_pred, beta=2, zero_division=0),
                "precision": precision_score(y_true, y_pred, zero_division=0),
                "recall": recall_score(y_true, y_pred, zero_division=0),
            }
        )
    avg = {k: np.mean([f[k] for f in fold_metrics]) for k in fold_metrics[0]}
    avg["threshold"] = t
    cv_results.append(avg)

cv_df = pd.DataFrame(cv_results)

# Best by F1
best_f1 = cv_df.loc[cv_df["f1"].idxmax()]
print("\nBest by F1:")
print(f"  Threshold: {best_f1['threshold']:.4f}")
print(
    f"  F1: {best_f1['f1']:.4f}, Precision: {best_f1['precision']:.4f}, Recall: {best_f1['recall']:.4f}"
)

# Best by F2
best_f2 = cv_df.loc[cv_df["f2"].idxmax()]
print("\nBest by F2:")
print(f"  Threshold: {best_f2['threshold']:.4f}")
print(
    f"  F2: {best_f2['f2']:.4f}, Precision: {best_f2['precision']:.4f}, Recall: {best_f2['recall']:.4f}"
)

# Max precision at recall >= 0.50
p50 = cv_df[cv_df["recall"] >= 0.50].sort_values("precision", ascending=False)
if len(p50):
    best_p50 = p50.iloc[0]
    print("\nMax Precision @ Recall >= 0.50:")
    print(f"  Threshold: {best_p50['threshold']:.4f}")
    print(
        f"  F1: {best_p50['f1']:.4f}, Precision: {best_p50['precision']:.4f}, Recall: {best_p50['recall']:.4f}"
    )

# Max precision at recall >= 0.80
p80 = cv_df[cv_df["recall"] >= 0.80].sort_values("precision", ascending=False)
if len(p80):
    best_p80 = p80.iloc[0]
    print("\nMax Precision @ Recall >= 0.80:")
    print(f"  Threshold: {best_p80['threshold']:.4f}")
    print(
        f"  F1: {best_p80['f1']:.4f}, Precision: {best_p80['precision']:.4f}, Recall: {best_p80['recall']:.4f}"
    )

# =====================================================================
# 4. AUC-ROC and AUC-PR
# =====================================================================
y_true_all = df["label"].values
y_score_all = df["epss_score"].values

roc_auc = roc_auc_score(y_true_all, y_score_all)
pr_auc = average_precision_score(y_true_all, y_score_all)
baseline_pr = y_true_all.mean()
print("\n=== FULL-CURVE METRICS ===")
print(f"ROC-AUC: {roc_auc:.4f}")
print(f"PR-AUC: {pr_auc:.4f}")
print(f"PR-AUC (random baseline): {baseline_pr:.4f}")
print(f"PR-AUC lift vs random: {pr_auc / baseline_pr:.2f}x")


# =====================================================================
# 5. Stratified Analysis
# =====================================================================
def stratify_metrics(df, thresholds, group_col, group_name, max_groups=10):
    print(f"\n=== STRATIFIED BY {group_name.upper()} ===")
    df = df.copy()
    if group_col == "cwe_class":
        top = df["cwe_class"].value_counts().head(max_groups).index
        df["group"] = df["cwe_class"].apply(lambda c: c if c in top else "OTHER")
    else:
        df["group"] = df[group_col]

    for name, grp in df.groupby("group"):
        y_true = grp["label"].values
        y_score = grp["epss_score"].values
        n, n_pos = len(grp), y_true.sum()
        if n_pos < 2:
            print(f"  {str(name):30s} n={n:>6d} pos={n_pos:>5d} — too few positives")
            continue
        roc = roc_auc_score(y_true, y_score)
        pr = average_precision_score(y_true, y_score)
        best_f1 = 0
        best_t = 0
        for t in thresholds:
            y_pred = (y_score >= t).astype(int)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            if f1 > best_f1:
                best_f1 = f1
                best_t = t
        print(
            f"  {str(name):30s} n={n:>6d} pos={n_pos:>5d} ({n_pos / n:.2%})  "
            f"ROC={roc:.4f}  PR={pr:.4f}  BestF1={best_f1:.4f}@t={best_t:.4f}"
        )


# By CWE
stratify_metrics(df, THRESHOLDS, "cwe_class", "CWE")

# By CVSS band
df["cvss_band"] = pd.cut(
    df["cvss_score"],
    bins=[-0.01, 3.9, 6.9, 8.9, 10.0],
    labels=["0-3.9", "4-6.9", "7-8.9", "9-10"],
)
stratify_metrics(df, THRESHOLDS, "cvss_band", "CVSS band")

# By age
df["age_band"] = pd.cut(
    df["age_days"],
    bins=[-1, 30, 90, 365, 730, 99999],
    labels=["0-30d", "31-90d", "91-365d", "1-2yr", "2yr+"],
)
stratify_metrics(df, THRESHOLDS, "age_band", "vulnerability age")

# =====================================================================
# 6. XGBoost Comparison
# =====================================================================
print("\n=== XGBOOST COMPARISON (5-fold CV) ===")


# Build feature matrix
def prepare_features(df):
    n = len(df)
    X = np.zeros((n, 29), dtype=np.float32)  # subset of 35 features
    # CVSS components (0-7)
    for i, vec in enumerate(df["cvss_vector"]):
        parts = {p.split(":")[0]: p.split(":")[1] for p in str(vec).split("/")}
        X[i, 0] = {"N": 3, "A": 2, "L": 1, "P": 0}.get(parts.get("AV", "N"), 3)
        X[i, 1] = {"L": 1, "H": 0}.get(parts.get("AC", "L"), 1)
        X[i, 2] = {"N": 2, "L": 1, "H": 0}.get(parts.get("PR", "N"), 2)
        X[i, 3] = {"N": 1, "R": 0}.get(parts.get("UI", "N"), 1)
        X[i, 4] = {"C": 1, "U": 0}.get(parts.get("S", "U"), 0)
        X[i, 5] = {"H": 2, "L": 1, "N": 0}.get(parts.get("C", "N"), 0)
        X[i, 6] = {"H": 2, "L": 1, "N": 0}.get(parts.get("I", "N"), 0)
        X[i, 7] = {"H": 2, "L": 1, "N": 0}.get(parts.get("A", "N"), 0)
    X[:, 8] = df["epss_score"].values
    X[:, 9] = df["patch_available"].astype(float)
    X[:, 20] = df["exploitdb_has_poc"].astype(float)
    X[:, 21] = df["metasploit_has_payload"].astype(float)
    X[:, 23] = df["nvd_reference_count"].values
    X[:, 25] = df["age_days"].values
    X[:, 27] = df["cvss_exploitability_sub"].values
    X[:, 28] = df["cvss_impact_sub"].values
    return X


X_full = prepare_features(df)
y = df["label"].values

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
xgb_results = {"roc_auc": [], "pr_auc": [], "f1": [], "precision": [], "recall": []}

for train_idx, test_idx in skf.split(X_full, y):
    X_tr, X_te = X_full[train_idx], X_full[test_idx]
    y_tr, y_te = y[train_idx], y[test_idx]
    sw = (y_tr == 0).sum() / max((y_tr == 1).sum(), 1)

    model = xgb.XGBClassifier(
        max_depth=4,
        learning_rate=0.03,
        n_estimators=800,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=sw,
        tree_method="hist",
        random_state=42,
        verbosity=0,
    )
    model.fit(X_tr, y_tr)
    y_prob = model.predict_proba(X_te)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    xgb_results["roc_auc"].append(roc_auc_score(y_te, y_prob))
    xgb_results["pr_auc"].append(average_precision_score(y_te, y_prob))
    xgb_results["f1"].append(f1_score(y_te, y_pred))
    xgb_results["precision"].append(precision_score(y_te, y_pred))
    xgb_results["recall"].append(recall_score(y_te, y_pred))

for k, v in xgb_results.items():
    print(f"  {k}: {np.mean(v):.4f} (+/- {np.std(v):.4f})")

# Compare with best EPSS threshold
print("\n=== BEST EPSS THRESHOLD ===")
print(f"Threshold: {best_f1['threshold']:.4f}")
print(f"F1: {best_f1['f1']:.4f}")
print(f"ROC-AUC: {roc_auc:.4f}")
print("\n=== XGBoost ===")
print(f"ROC-AUC: {np.mean(xgb_results['roc_auc']):.4f}")
print(f"F1: {np.mean(xgb_results['f1']):.4f}")
print(f"F1 gap (XGB - EPSS): {np.mean(xgb_results['f1']) - best_f1['f1']:.4f}")

# =====================================================================
# 7. Cost-Benefit Analysis
# =====================================================================
print("\n=== COST-BENEFIT ANALYSIS ===")
total_kev = df["label"].sum()
for t in [0.001, 0.005, 0.01, 0.05, 0.1, 0.2, 0.3, 0.5]:
    flagged = (df["epss_score"] >= t).sum()
    caught = ((df["epss_score"] >= t) & (df["label"] == 1)).sum()
    fp = flagged - caught
    prec = caught / flagged if flagged > 0 else 0
    rec = caught / total_kev if total_kev > 0 else 0
    print(
        f"  t={t:.4f}: flagged={flagged:>8,d} ({flagged / len(df) * 100:>5.2f}%), "
        f"caught={caught:>5,d} ({rec * 100:>5.1f}%), "
        f"FP={fp:>8,d}, prec={prec:.3f}, "
        f"FP/caught={fp / max(caught, 1):.1f}"
    )

# =====================================================================
# 8. Final Recommendation
# =====================================================================
f1_gap = np.mean(xgb_results["f1"]) - best_f1["f1"]
if f1_gap < 0.05 and best_f1["recall"] > 0.30:
    rec = "EPSS-ONLY SUFFICIENT"
elif f1_gap < 0.10 and best_f1["recall"] > 0.20:
    rec = "EPSS-ONLY MAY BE SUFFICIENT FOR LOW-RESOURCE TRIAGE"
else:
    rec = "XGBOOST ADDS VALUE"

print("\n=== FINAL RECOMMENDATION ===")
print(f"F1 gap (XGB - EPSS): {f1_gap:.4f}")
print(f"Recommendation: {rec}")
