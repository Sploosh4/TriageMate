# Assessment: Google Colab Free Tier for TriageMate ML Training

**Date:** 2026-07-07
**Requested by:** Commander / Strike Team
**Sources consulted:** Google Colab Official FAQ, Wikipedia, GeeksforGeeks, Reddit r/MLQuestions, NVD API docs, project codebase analysis, filesystem audit

---

## 1. Executive Summary

**Verdict: CONDITIONAL NO — not worth the effort for TriageMate's workload profile.**

Colab Free Tier is *technically capable* of running all three models, but the speedup it offers is marginal (only the SBERT encoding phase benefits materially from a GPU), the setup friction is significant, and the runtime limitations (12h cap, idle timeout, unreliable GPU allocation) introduce operational risk that outweighs the benefit.

**Why not:** The current CPU-only training pipeline (16-core AMD, 29 GB RAM) already completes with a ROC-AUC of **0.9677**. XGBoost and RandomForest training are CPU-bound operations that run efficiently on the local machine. The only phase that benefits from a GPU is SBERT encoding of ~200K CVE descriptions, which is a one-time cost that could be further optimised locally with batching.

**What would make it YES:** If (a) TriageMate moves to a much larger dataset (500K+ CVEs), (b) the team adopts deep learning models instead of XGBoost, or (c) the training frequency increases to weekly/daily.

**Better alternatives:** See §8.

---

## 2. TriageMate's ML Training Requirements

### 2.1 Data Sizes (actual filesystem audit)

| File | Size | Purpose |
|---|---|---|
| `backend/data/nvd_corpus.json` | **205 MB** | NVD CVE records (200K+) |
| `backend/ml/training_data.npz` | **156 MB** | Pre-built feature matrix + labels |
| `backend/data/epss_cache.json` | 20 MB | FIRST.org EPSS scores |
| `backend/data/kev_cache.json` | 519 KB | CISA KEV catalog |
| `backend/data/nvd_cache.json` | 118 KB | NVD fetch checkpoint |

**Total training data footprint: ~382 MB** (well within any cloud tier's limits)

### 2.2 Model Configurations

| Model | Type | Dataset | Features | Hyperparams | File Size |
|---|---|---|---|---|---|
| **Tier 1** (XGBoost) | `XGBClassifier` | ~200K CVEs (→ ~150K after obs-window filtering) | 35 tabular + 384 SBERT = **419** | 800 trees, depth=4, lr=0.03, `tree_method="hist"` | 1.3 MB |
| **Pre-Tier** (RandomForest) | `MultiOutputClassifier(RandomForest)` | ~550 hostname records | ~40-60 engineered features | 200 trees, `n_jobs=-1` | 5.5 MB |
| **EPSS Substitutor** (XGBoost) | `XGBRegressor` | 500-1000 synthetic samples | 37 (one-hot) | 200-300 trees, depth=6-8 | 0.5-1.3 MB |

### 2.3 Current Local Hardware

| Component | Spec |
|---|---|
| CPU | AMD Ryzen (Rembrandt), **16 cores** |
| RAM | **29 GB** |
| GPU | AMD Radeon 680M (integrated, **no CUDA**) |
| Disk | NVMe SSD (plenty of space) |

**Key finding:** The local machine has no NVIDIA GPU and no CUDA support. All training currently runs on CPU.

---

## 3. Colab Free Tier Specs (as of July 2025/2026)

### 3.1 Hardware

| Resource | Free Tier | Pro ($10/mo) | Pro+ ($50/mo) |
|---|---|---|---|
| **GPU** | T4 (16 GB VRAM), occasionally K80 (12 GB) or P100 (16 GB) | T4, sometimes V100 (16 GB) — **priority access** | V100, A100 — **premium access** |
| **GPU VRAM** | 12-16 GB (depends on allocation) | 16 GB (T4/V100) | 16-40 GB (V100/A100) |
| **System RAM** | **~12 GB** (standard profile) | **~25 GB** (high-RAM profile) | **~52 GB** (high-RAM profile) |
| **Disk** | **~78 GB** (ephemeral VM) | ~166 GB (ephemeral VM) | ~225 GB (ephemeral VM) |
| **CPU cores** | 2-4 vCPU (typically) | 4-8 vCPU | 8+ vCPU |

### 3.2 Runtime Limits

| Limit | Free Tier |
|---|---|
| **Max session duration** | **12 hours** (hard cap) |
| **Idle timeout** | ~90 minutes (no code execution) |
| **GPU availability** | **Not guaranteed** — dynamically allocated; often "no GPU available" during peak |
| **Background execution** | **Not supported** — browser tab must remain active |
| **Concurrent sessions** | 1 |
| **GPU quota** | Soft quota; usage limits fluctuate dynamically |
| **TPU availability** | Rare on free tier (mostly TPUv2-8) |

### 3.3 Key Colab Limitations (from official FAQ)

- "Colab prioritizes users who are **actively programming in a notebook**"
- "Access to expensive resources like GPUs is **heavily restricted**"
- "Usage limits sometimes fluctuate"
- "GPU types available ... vary over time"
- "12-hour limit depending on availability and your usage patterns"
- Disallowed: remote control, SSH, distributed computing workers, file hosting

### 3.4 Storage

| Storage Type | Free Tier | Notes |
|---|---|---|
| **Google Drive** | 15 GB (free) — **persistent** | Training data + models fit easily (~382 MB) |
| **VM local disk** | ~78 GB — **ephemeral** | Lost on runtime disconnect/reset |
| **Git integration** | Direct clone/push | Works for code |

---

## 4. Feasibility Analysis by Training Phase

### 4.1 Phase: NVD Data Fetching (`phase_gather`)

| Factor | Assessment |
|---|---|
| **CPU demand** | Low — mostly I/O-bound (HTTP requests) |
| **GPU benefit** | None — purely network/disk I/O |
| **Time** | ~20-40 min (if using enriched_cves.json checkpoint) to days (if fresh NVD fetch due to API rate limiting at 6.2s per 200 records) |
| **Colab viability** | Works fine, but 12h limit is tight for a full fresh NVD fetch (which involves ~100+ API pages per chunk over 6 years of data) |
| **Sub-verdict** | ✅ **Feasible but wasteful** — better to pre-fetch locally and upload enriched_cves.json |

### 4.2 Phase: SBERT Encoding (Phase 1 — the GPU bottleneck)

| Factor | Assessment |
|---|---|
| **CPU time** | ~2-4 hours on 16-core AMD for 200K descriptions (all-MiniLM-L6-v2, 384-dim) |
| **GPU time** | ~15-30 minutes on T4 (5-8x speedup) |
| **VRAM needed** | ~1-2 GB (model is ~90 MB, batch encoding needs a few MB per sample) — easily fits in 12-16 GB |
| **System RAM** | ~2-4 GB for loading + processing batches of 200K strings |
| **Colab viability** | ✅ **The only phase where Colab GPU provides meaningful acceleration** |
| **Sub-verdict** | ✅ **Feasible and beneficial** |

### 4.3 Phase: XGBoost Training (Phase 2)

| Factor | Assessment |
|---|---|
| **CPU time** | ~5-15 minutes on 16-core AMD (800 trees, depth=4, 419 features, ~150K rows) |
| **GPU time** | ~2-5 minutes on T4 (2-3x speedup) |
| **VRAM needed** | ~2-4 GB for the DMatrix (150K × 419 × 4 bytes ≈ 251 MB + histogram buffer) |
| **System RAM** | ~4-6 GB during fit |
| **Colab viability** | **Marginal benefit** — training is already fast on CPU; GPU speedup is modest |
| **Note** | Current code uses `tree_method="hist"` (CPU). No changes needed to use GPU, but would need to add `device="cuda"` or `tree_method="gpu_hist"` |
| **Sub-verdict** | ✅ **Technically feasible, but ROI is poor** |

### 4.4 Phase: Pre-Tier / EPSS Model Training

| Factor | Assessment |
|---|---|
| **Dataset size** | ~550 records (Pre-Tier), 500-1000 rows (EPSS) |
| **Train time** | <1 minute on any CPU |
| **GPU benefit** | None — too small to matter |
| **Sub-verdict** | ❌ **Pointless to use Colab** |

### 4.5 Phase: Total Workload Footprint

| Resource | Required | Colab Free Limit | OK? |
|---|---|---|---|
| **Disk (ephemeral)** | ~1 GB (venv + data + models) | ~78 GB | ✅ |
| **Disk (persistent)** | ~400 MB (Drive backup) | 15 GB | ✅ |
| **RAM** | ~6-8 GB (peak during SBERT encoding) | ~12 GB | ✅ |
| **GPU VRAM** | ~2-4 GB | 12-16 GB | ✅ |
| **Runtime** | ~4-8 hours (gather + train with checkpoints) | 12 hours | ✅ (tight margin) |

---

## 5. Data Transfer Considerations

### 5.1 Transfer Methods

| Method | Speed (est.) | Complexity | Reliability |
|---|---|---|---|
| **Google Drive mount** (`drive.mount()`) | 10-50 MB/s | Low | Moderate — known timeout issues with many files |
| **Direct HTTP download** (wget/curl) | 10-100 MB/s | Low | High — simple, but data must be hosted |
| **Git clone** (if repo is public) | 1-10 MB/s | Low | High — but repo doesn't host the 205 MB corpus |
| **Colab upload** (`files.upload()`) | 1-5 MB/s (browser dependent) | Low | Good for small files; 205 MB will be slow & risk browser timeout |
| **Kaggle Datasets API** | 10-50 MB/s | Medium | Not applicable — TriageMate data isn't on Kaggle |

### 5.2 Recommended Transfer Strategy

1. Upload to Google Drive: `nvd_corpus.json` (205 MB) + `training_data.npz` (156 MB) + `epss_cache.json` (20 MB) + source code
2. Mount Drive in Colab: `drive.mount('/content/drive')`
3. Copy to local VM: `!cp /content/drive/MyDrive/triagemate/data/* /content/`

**Time estimate:** ~1-3 minutes for ~400 MB over USB/network (assuming reasonable upload speed)

### 5.3 Persistent Storage on Free Tier

- **Google Drive (15 GB)**: Sufficient for all training data + models
- **Ephemeral VM disk**: All data lost on runtime disconnect
- **Recommendation**: Save models directly to Drive after training as a checkpoint: `!cp /content/model.pkl /content/drive/MyDrive/triagemate/models/`

---

## 6. Setup Complexity

### 6.1 Script Modifications Required

| Script | Change Needed | Difficulty |
|---|---|---|
| `train_xgboost.py` | Add `device="cuda"` to XGBClassifier for GPU; change SBERT `device="cpu"` to `device="cuda"` | **Low** (2 lines) |
| `encoder.py` | Parameterise `device="cpu"` or auto-detect CUDA | Low |
| `train_pre_tier.py` | None needed (CPU-only, tiny dataset) | None |
| `train_epss_v*.py` | None needed | None |

### 6.2 Dependency Management

The existing `backend/requirements.txt` includes all needed packages:
- `xgboost==2.0.3` — supports CUDA out of the box
- `sentence-transformers==3.0.1` — auto-detects CUDA if available
- `torch>=2.2.0` — comes pre-installed on Colab (GPU-enabled)
- `scikit-learn`, `numpy`, `joblib` — all pre-installed

**No dependency changes needed.** Just `pip install -r requirements.txt` in the Colab cell.

### 6.3 Notebook vs. Script Execution

| Approach | Pros | Cons |
|---|---|---|
| **Convert to notebook** (.ipynb) | Interactive; native Colab format | Requires manual conversion of all scripts; harder to maintain parity with repo |
| **Script execution** (`!python -m ml.train_xgboost --train`) | Zero modification to existing pipeline | Need to mount Drive, pip install, handle relative paths |
| **Hybrid** (notebook cells that shell-execute scripts) | Best of both | Simple: `!cd backend && pip install -r requirements.txt && python -m ml.train_xgboost --train` |

**Recommended approach:** Hybrid — upload the entire project to Drive, mount in Colab, and execute the existing scripts via `!python -m` commands. This preserves the pipeline identically.

### 6.4 Estimated Setup Time

| Task | Time |
|---|---|
| Upload data to Google Drive | ~5 min (background) |
| Create Colab notebook | ~5 min |
| Write Drive-mount + pip install cells | ~5 min |
| Execute gather phase (with checkpoints) | 2-4 hours (SBERT encoding) |
| Execute train phase | 5-15 min |
| Download models | ~1 min |
| **Total first-time setup** | **~15 min active + ~3 hours passive** |

---

## 7. Bottleneck Analysis

### 7.1 Critical Bottlenecks on Colab Free Tier

1. **GPU availability (unreliable)** — The #1 risk. During peak hours, free-tier users may not get a GPU at all, or may get a K80 (outdated, slow, no FP16). The training pipeline would fall back to CPU, negating any benefit.

2. **12-hour runtime cap** — A full end-to-end run (fresh NVD fetch + SBERT encoding + training) may approach this limit. Using checkpoints (enriched_cves.json, training_data.npz) mitigates this, but a single run from scratch could fail.

3. **Idle timeout (90 min)** — SBERT encoding takes 2-4 hours. A long batch job that isn't generating visible output may trigger the idle timeout. **Workaround:** Add periodic print statements or a `!sleep 30` loop cell.

4. **12 GB RAM ceiling** — Tight for loading the full 200K SBERT-encoded matrix (~150K × 419 × 4 = ~251 MB for features). The training matrix itself is small, but there may be intermediate memory spikes during SBERT batching. **Risk: LOW** — well within limits.

5. **No background execution** — Browser tab must stay open. If the developer closes their laptop, training dies silently. This makes Colab unsuitable for overnight runs.

### 7.2 Bottlenecks That Colab Does NOT Help With

- **NVD API rate limiting** (6.2s per 200 records) — entirely network/IO bound, not compute
- **NVD API key throttling** — Colab's network is no different from local
- **Feature engineering** — purely CPU, already fast
- **Model evaluation** — trivial computation

---

## 8. Comparison: Colab Free Tier vs. Alternatives

| Platform | GPU | RAM | Disk | Runtime | Cost | Best For |
|---|---|---|---|---|---|---|
| **Colab Free** | T4/K80 (flaky) | ~12 GB | 78 GB | 12h max, idle timeout | **$0** | Quick experiments |
| **Colab Pro** | T4/V100 (priority) | ~25 GB | 166 GB | 24h, less idle | **$10/mo** | Serious ML work |
| **Kaggle Notebooks** | 2× T4 (reliable) | **30 GB** | **20 GB persistent** | 30h/week GPU, 9h session | **$0** | ✅ **Best free option** |
| **Lambda Labs** | T4 guaranteed | 32 GB | 100 GB | No limit | ~$0.50/hr | On-demand GPU |
| **RunPod** | T4 guaranteed | 32 GB | 200 GB | No limit | ~$0.28/hr | Cheapest on-demand |
| **AWS SageMaker** | No free GPU tier | — | — | — | Free tier: CPU-only | Not applicable |
| **Local (current)** | None (CPU) | 29 GB | NVMe SSD | Unlimited | $0 (sunk) | Current setup |

### 8.1 Why Kaggle Notebooks is the Stronger Free Option

| Feature | Colab Free | **Kaggle Free** |
|---|---|---|
| GPU | T4 (unreliable) | **2× T4 (reliable, 30 hrs/week)** |
| RAM | ~12 GB | **30 GB** |
| Persistent storage | 15 GB Drive + 78 GB ephemeral | **20 GB persistent + 50 GB ephemeral** |
| Internet | Yes | Yes |
| Session duration | 12h (hard cap) | **9h (but more reliable)** |
| Background execution | No | No |
| Setup | Notebook-centric | **Notebook-centric** |
| Data upload | Drive mount | **Direct upload + Kaggle Datasets** |

---

## 9. Cost-Benefit Analysis

### 9.1 What You Actually Gain

| Phase | Local CPU Time | Colab T4 Time | Speedup | Real-World Benefit |
|---|---|---|---|---|
| SBERT encoding (200K) | ~3 hours | ~30 min | **6×** | **Meaningful** — saves ~2.5 hrs |
| XGBoost training | ~10 min | ~5 min | 2× | Negligible — already fast |
| Pre-Tier training | <1 min | <1 min | 1× | None |
| EPSS training | <1 min | <1 min | 1× | None |
| NVD fetching | 20-40 min | 20-40 min | 1× | None (I/O bound) |
| **End-to-end total** | **~3.7 hrs** | **~1.3 hrs** | **~2.8×** | **Saves ~2.4 hours** |

### 9.2 What You Pay (in Friction)

| Cost | Impact |
|---|---|
| **Setup time** | ~15 min active work (first time) |
| **Pipeline fragmentation** | Colab diverges from local scripts; version drift risk |
| **GPU unreliability** | ~20-30% chance of no GPU during peak times |
| **Runtime risk** | ~10-20% chance of session termination before completion |
| **Tab dependency** | Cannot close browser during SBERT encoding |
| **Data transfer** | Uploading ~400 MB (once) + model downloads |
| **Ongoing maintenance** | Keeping scripts in sync for both Colab and local execution |

### 9.3 ROI Calculation

```
Time saved per full training run:    ~2.4 hours
Setup + faff overhead (one-time):    ~15 min  (absorbed)
Broken-run risk factor:              ~15%     (need retries)

Expected useful time savings:        ~2.0 hours per run
Colab runs before overhead recouped: 1 run    (trivial)
```

The raw time savings are real, but the **reliability cost** (broken sessions, GPU unavailability) and **operational overhead** (keeping a browser open, monitoring progress) make it borderline.

---

## 10. Recommendations

### 10.1 Primary Recommendation: ❌ DON'T use Colab Free Tier

For the current TriageMate workload, **Colab Free Tier is not worth the effort**. The reasoning:

1. The only phase that materially benefits from a GPU (SBERT encoding) can be optimised locally with improved batching
2. The current training pipeline already achieves excellent results (ROC-AUC 0.9677) on CPU
3. The 12-hour runtime cap, idle timeout, and unreliable GPU allocation introduce operational risk
4. The setup overhead and pipeline fragmentation costs are real

### 10.2 If You Want a Free GPU Anyway: 🏆 Use Kaggle Notebooks Instead

Kaggle offers **30 hours/week of reliable T4 GPU time** with 30 GB RAM and 20 GB persistent storage — strictly better than Colab Free in every dimension. The setup is similar (notebook-based, Drive-like Datasets API for data, Git for code).

### 10.3 If You're Willing to Spend a Little: 💰 Colab Pro ($10/mo)

For $10/month, Colab Pro removes the biggest pain points:
- Priority GPU access (T4 reliably, sometimes V100)
- High-RAM profile (~25 GB)
- Longer runtimes (up to 24h with Pro+)

At $10/mo for a government cybersecurity project, this is pocket change and removes the reliability concerns.

### 10.4 If Training Becomes a Bottleneck: ☁️ Consider Pay-per-Use Cloud GPU

- **RunPod:** ~$0.28/hr for T4 — a full training run costs ~$0.36
- **Lambda Labs:** ~$0.50/hr for T4 — ~$0.65 for a full run
- Both are **pre-configured with PyTorch/XGBoost**, have no runtime limits, and support SSH + persistent storage.

### 10.5 Minimal Setup Path (if proceeding anyway)

If the commander directs a Colab trial despite this assessment:

```
# In a Colab notebook cell:
from google.colab import drive
drive.mount('/content/drive')

!cp -r /content/drive/MyDrive/triagemate_data/* /content/

!pip install -r /content/requirements.txt

# SBERT encoding — change device from "cpu" to "cuda" in encoder.py
# XGBoost — change tree_method to "gpu_hist" and add device="cuda"

# Option A: Run full pipeline
!cd /content && python -m ml.train_xgboost --gather --train

# Option B: Run train-only (if training_data.npz pre-uploaded)
!cd /content && python -m ml.train_xgboost --train
```

---

## 11. Appendix: Detailed Data Sizes

| File | Absolute Size | Colab Free Limit | Headroom |
|---|---|---|---|
| `nvd_corpus.json` | **205 MB** | 78 GB (ephemeral) / 15 GB (Drive) | ✅ |
| `training_data.npz` | **156 MB** | 78 GB / 15 GB | ✅ |
| `epss_cache.json` | **20 MB** | 78 GB / 15 GB | ✅ |
| `kev_cache.json` | **519 KB** | 78 GB / 15 GB | ✅ |
| `nvd_cache.json` | **118 KB** | 78 GB / 15 GB | ✅ |
| `xgboost_model.pkl` | **1.3 MB** | 78 GB / 15 GB | ✅ |
| `pre_tier_model.pkl` | **5.5 MB** | 78 GB / 15 GB | ✅ |
| `epss_model*.pkl` | 0.5-1.3 MB | 78 GB / 15 GB | ✅ |
| Python venv (all deps) | ~2 GB | 78 GB | ✅ |
| **Total (worst case)** | **~2.4 GB** | 78 GB / 15 GB | ✅ 32× headroom on Drive |

---

*Prepared by Intel Analyst. Cross-reference with `backend/ml/train_xgboost.py`, `backend/ml/encoder.py`, and `backend/requirements.txt` for code-level details.*
