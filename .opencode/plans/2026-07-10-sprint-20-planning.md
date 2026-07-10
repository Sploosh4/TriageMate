# Sprint 20 (Planned) — Agentic LLM + Customizable Weights + Safe PCA

**Date:** 2026-07-10
**Status: PLANNING ONLY — DO NOT EXECUTE** (Sprint 19 is active)
**Based on:** Commander conceptual analysis of 3 user-requested features
**Previous sprint:** Sprint 19 (Config + Retraining + Closing the Loop)
**Tests baseline:** 298+ pass, 0 fail (Sprint 19 baseline)

---

## ⚠️ Pre-Execution Gate

Before any implementation begins:

1. **Sprint 19 must be complete and verified** (298+ tests pass, all items closed out)
2. **Commander must re-analyze the codebase** with subagents to assess changes from Sprint 19
3. **The `pipeline/config/` package must exist** (Sprint 19 Item 1 delivery)
4. **Commander must verify** that Item 2 (Customizable Weights) can build on the completed config module — specifically that `pipeline/config/scoring.py` has the `SCORING_WEIGHTS` dict that can be extended with config-file overrides and an admin API

> **This entire document is speculative.** All estimates, file paths, and implementation approaches are based on pre-Sprint-19 analysis and must be re-validated by the commander before any execution begins.

---

## Commander Recommendations — Pending User Review

These design decisions were identified during the conceptual analysis. The commander
recommends the defaults below. User confirmation is required before execution.

| # | Decision | Commander Recommendation | Rationale |
|---|----------|--------------------------|-----------|
| D1 | **Tool access scope** — Should any of the 12 planned tools be excluded? | Include all 12 tools. Restrict the agent to **read-only operations** — all tools query existing integrations and databases without making external API calls or modifying state. | Excluding tools like `search_metasploit` would reduce the agent's investigative capability. The safety property comes from the agent being read-only, not from limiting which data sources it can consult. |
| D2 | **Weight range constraints** — What are the min/max bounds for individual scoring weights? | **Min: 1, Max: 100.** Sum must remain ≥ 100. Individual weights must be integers. | A minimum of 1 ensures every dimension contributes at least something — zeroing a dimension would eliminate a deliberate risk signal. A maximum of 100 prevents any single dimension from dominating. The ≥100 sum constraint preserves the clamping headroom (112 → clamp to 100). |
| D3 | **PCA priority** — Given ROC-AUC 0.9459 with 419 dims, is this worth sprint time? | **Keep as Medium priority, but flag as deferrable.** If Sprint 19's retraining work significantly changes the training pipeline, defer PCA to Sprint 21 to avoid compounding instability. | PCA is an optimization — the model works correctly now. The risk of degraded ROC-AUC (even with the 0.01 guardrail) combined with Sprint 19's retraining changes makes this the most deferrable of the three items. |

> **User action required:** Confirm or override each recommendation before execution begins.

---

## Sprint Goals

1. **Rebuild Tier 2 as a multi-step "agentic" LLM** with actual tools (KEV lookup, NVD search, EPSS query, network context, telemetry, advisory search, exploit/PoC databases, CMDB stub, and a resolution-submission tool)
2. **Restore customizable risk multipliers** — expose the 7-dimension scoring weights via config file override + admin API + frontend dashboard with live demo CVE recalculation
3. **Safely reintroduce PCA dimensionality reduction** with correct train/test split hygiene (fit on training data only, transform with fitted PCA, graceful fallback at inference)

---

## Item 1: Multi-Step Agentic LLM

**Effort:** ~8-10 hrs | **Priority:** High

### Current State

Tier 2 (`backend/pipeline/tier_2.py`, 754 lines) is a single-shot text analyzer: builds one large prompt with pre-assembled context (CVSS, EPSS, KEV, RAG chunks, CWE, tags, scores), sends to LLM, parses JSON response. Zero tool/function definitions exist. `KNOWN_CONFLICTS` dict hardcoded for 3 CVEs as a workaround for the single-shot approach. No function/tool calling anywhere in the codebase.

### What

Transform Tier 2 from a single-shot text analyzer into an automated security analyst that can run a multi-step investigation loop, using the LLM to decide which tools to call, in what order, and when to submit a final resolution.

### Sub-Items

**1A. Define Agent Tools** (~3 hrs)

Create `backend/pipeline/tier_2/tools.py` with 10-12 tool functions wrapping existing integrations. Each tool returns structured JSON with a `success` field and error handling:

| Tool | Source | Returns |
|------|--------|---------|
| `search_kev(cve_id)` | `integrations/kev.py` | KEV status + dateAdded |
| `search_nvd(cve_id)` | `integrations/nvd.py` | CVSS vector breakdown, reference count, CWE |
| `search_epss(cve_id)` | `integrations/epss.py` | EPSS score + percentile |
| `search_cwe(cve_id)` | `integrations/cwe.py` | CWE classification + MITRE ATT&CK mapping |
| `search_mitre(cve_id)` | `integrations/mitre.py` | MITRE techniques from integration |
| `query_network(hostname)` | `network_context.py` | Blast radius, zone, peer counts |
| `query_telemetry(hostname)` | `synthetic_telemetry.py` | Sentinel alerts, EDR evidence |
| `query_advisories(cve_id)` | WASOC advisory integration | WASOC advisory lookup |
| `search_exploitdb(cve_id)` | `integrations/exploitdb.py` | Public PoC availability |
| `search_metasploit(cve_id)` | `integrations/metasploit.py` | Metasploit payload availability |
| `search_cmdb(hostname)` | Stub (not yet integrated) | CMDB asset data |
| `submit_resolution(assessment)` | Agent loop finalizer | LLM calls this to submit its decision |

Each tool is read-only — it queries existing data sources and returns structured JSON.
No tool creates, updates, or deletes data. No tool makes external API calls that the
LLM could manipulate. The LLM chooses *which* tool to invoke; the tool implementation
controls *how* the query is executed.

**1B. Implement Agentic Loop** (~4 hrs)

Create `backend/pipeline/tier_2/agent.py` with:

- **`AgenticEvaluator` class** that manages the conversation loop:
  - Step counter (configurable, default 15, max 20)
  - Cost budget tracker (configurable via `TRIAGEMATE_LLM_COST_BUDGET` env var, default $0.50 per CVE)
  - Message history buffer

- **Provider-specific tool calling:**
  - **OpenAI:** native `function_call` / `tools` API support
  - **Anthropic:** native `tool_use` messages support
  - **Together AI:** JSON-mode with tool guidance in system prompt (manual parsing of tool calls from response)

- **Loop termination conditions:**
  1. LLM calls `submit_resolution` with final assessment
  2. Step limit reached (default 15, max 20)
  3. Cost budget exceeded ($0.50 default per CVE)
  4. LLM explicitly requests termination in its response

- **Structured final output** matching the existing `TriageConflictResult` Pydantic model so downstream pipeline stages are unaffected

**1C. Refactor Tier 2 Integration** (~1 hr)

Modify `backend/routers/ingest.py` call site:

- **Current:** passes pre-assembled context (cvss, epss, kev, rag, cwe, tags, scores) to `evaluate_tier_2()`
- **New:** passes only `cve_id`, `hostname`, `description`, and `cvss_score` — the agent gathers everything else via tool calls
- Keep the existing `evaluate_tier_2()` as a legacy fallback, gated behind an env var (`TRIAGEMATE_AGENT_ENABLED=false` by default)

**1D. Cost & Safety Guardrails** (~1 hr)

| Env Var | Default | Purpose |
|---------|---------|---------|
| `TRIAGEMATE_LLM_COST_BUDGET` | `0.50` | Max USD spend per CVE analysis |
| `TRIAGEMATE_AGENT_MAX_STEPS` | `15` | Max tool-calling steps per analysis |
| `TRIAGEMATE_AGENT_ENABLED` | `false` | Feature flag — opt-in while testing |

Logging: structured logs for every tool call, step, and cost increment. Log format:
```json
{"event":"agent_tool_call", "cve_id":"CVE-2024-1234", "tool":"search_kev", "step":3, "cost":0.002}
{"event":"agent_step", "cve_id":"CVE-2024-1234", "step":3, "total_cost":0.014, "steps_remaining":12}
```

**1E. Tests** (included in estimates)

| Test | What it verifies |
|------|-----------------|
| `test_tool_search_kev()` | Tool returns expected KEV structure |
| `test_tool_search_nvd()` | Tool returns expected NVD structure |
| `test_tool_search_epss()` | Tool returns expected EPSS structure |
| `test_tool_submit_resolution()` | Tool finalizes assessment correctly |
| `test_tool_error_handling()` | Tool returns `{"success":false}` on failure |
| `test_agent_loop_normal_flow()` | Agent runs to `submit_resolution` within budget |
| `test_agent_loop_step_limit()` | Agent terminates when steps exhausted |
| `test_agent_loop_cost_budget()` | Agent terminates when cost budget exceeded |
| `test_agent_feature_flag_disabled()` | Legacy `evaluate_tier_2()` used when flag is false |
| `test_agent_provider_fallback()` | Provider chain fallback works correctly |

### Acceptance Criteria

- [ ] LLM can autonomously look up KEV, NVD, EPSS data via tools and produce a conflict assessment
- [ ] Agent respects step limit (default 15, max 20) and cost budget (default $0.50)
- [ ] Feature flag allows safe rollout (`TRIAGEMATE_AGENT_ENABLED=false` by default)
- [ ] Existing single-shot Tier 2 still works as fallback (flag disabled or agent init failure)
- [ ] All existing tests (298+) still pass
- [ ] `just lint` — ruff clean

---

## Item 2: Customizable Risk Multipliers

**Effort:** ~4-5 hrs | **Priority:** Medium

> **⚠️ HARD DEPENDENCY on Sprint 19 Item 1.** The `pipeline/config/scoring.py` module must exist with the `SCORING_WEIGHTS` dict before this item can extend it with config-file overrides and an admin API.

### Current State

Scoring weights are hardcoded in `pipeline/config/scoring.py` as a Python dict. No override mechanism exists. No API to read/modify weights. No frontend admin page. To change a weight, an operator must edit the Python file and restart the server.

### What

Expose the 7-dimension scoring weights (`cvss`, `epss`, `criticality`, `exposure`, `patch`, `ml_exploitation`, `security_context`) so security teams can tune them to their risk appetite without code changes or server restarts.

### Implementation

**2A. Config File Override** (~1 hr)

- Add `backend/pipeline/config/scoring_weights.json` — optional JSON override file (not committed; gitignored)
- Modify `pipeline/config/scoring.py` module:
  - On import, check if `scoring_weights.json` exists
  - If yes: load JSON, merge with defaults (JSON values override defaults)
Validation rules (per Decision D2):
- All weights must be integers ≥ 1 and ≤ 100
- Sum of all 7 weights must be ≥ 100
- On invalid config: log WARNING, fall back to hardcoded defaults
- On valid config: replace SCORING_WEIGHTS in-memory, recalculate TOTAL_WEIGHT
  - Cache loaded weights in memory for fast access
- Add `reload_scoring_weights()` function to allow hot-reload without server restart

**2B. Admin API Endpoints** (~1 hr)

Create `backend/routers/admin.py` with:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/admin/config/scoring` | GET | Returns current weights + defaults + validation status |
| `/api/admin/config/scoring` | PUT | Accepts new weights dict, validates, saves to JSON, triggers in-memory reload |
| `/api/admin/config/scoring/reset` | POST | Deletes JSON file, restores defaults, triggers in-memory reload |

All endpoints auth-gated (JWT required, admin role). Response format:
```json
{
  "current": {"cvss": 40, "epss": 20, ...},
  "defaults": {"cvss": 40, "epss": 20, ...},
  "valid": true,
  "validation_errors": []
}
```

**2C. Frontend Admin Panel** (~2 hrs)

Add to `frontend/`:

- New "Admin Settings" page/view (SPA route)
- Seven sliders (one per scoring dimension) with current value, max value, and default value displayed
- Each slider labeled with its dimension name and a brief description of what it controls
- Real-time demo CVE score recalculation: as user drags sliders, recalculate all 7 demo CVE scores and show the new band for each
- "Save" button (calls `PUT /api/admin/config/scoring`)
- "Reset to Defaults" button (calls `POST /api/admin/config/scoring/reset`)
- Access gated behind JWT auth in the frontend (admin role only)

**2D. Tests** (included in estimates)

| Test | What it verifies |
|------|-----------------|
| `test_weights_json_load_valid()` | Valid JSON file loads correctly |
| `test_weights_json_load_missing()` | Missing file falls back to defaults silently |
| `test_weights_json_load_corrupt()` | Corrupt JSON falls back with warning log |
| `test_weights_validation_sum()` | Sum < 100 → rejected |
| `test_weights_validation_range()` | Weight > 100 or < 1 → rejected |
| `test_weights_merge_defaults()` | Partial override fills missing keys from defaults |
| `test_admin_get_scoring_auth()` | Unauthenticated GET returns 401 |
| `test_admin_put_scoring_valid()` | Valid PUT updates weights |
| `test_admin_put_scoring_invalid()` | Invalid PUT returns 422 |
| `test_admin_reset_scoring()` | POST reset restores defaults |

### Acceptance Criteria

- [ ] Weights loadable from `scoring_weights.json` with graceful fallback to defaults
- [ ] Admin API endpoints return correct data and validate input
- [ ] Frontend admin page allows weight adjustment with live demo CVE recalculation
- [ ] Demo CVE scores DON'T change unless weights are explicitly modified
- [ ] All existing tests pass
- [ ] `just lint` — ruff clean

---

## Item 3: Safe PCA Dimensionality Reduction

**Effort:** ~3-4 hrs | **Priority:** Medium (Technical Optimization)

### Current State

- `backend/ml/encoder.py` produces raw 384-dim SBERT vectors
- PCA was removed in v2.5 due to data leakage (PCA was fitted on all data before train/test split)
- Current model: 35 tabular + 384 SBERT = 419 total dimensions
- ROC-AUC: 0.9459 on test set
- XGBoost handles high dimensionality with built-in regularization (`max_depth`, `subsample`, `colsample_bytree`)

### Honest Assessment

The model works at 0.9459 with 419 dimensions. This is an optimization, not a bug fix. The PCA reintroduction is about model compactness and inference speed, not fixing broken behavior. If ROC-AUC degrades beyond the acceptable threshold (0.01 drop), the change should be reverted. The primary benefits are:

- **Model file size reduction** — PCA can reduce 384 dims to ~50-80 dims (95% variance retention), shrinking the XGBoost model significantly
- **Inference speed** — fewer features mean faster tree traversal
- **Training speed** — smaller feature space for XGBoost to search

### What

Optimize the SBERT embedding pipeline by adding PCA dimensionality reduction with correct train/test split hygiene, reducing model size and inference latency without significant accuracy loss.

> **Deferrability note (Decision D3):** This item is marked as deferrable. If Sprint 19's
> retraining pipeline significantly changes the training code path, defer this item to
> Sprint 21 to avoid stacking PCA changes on top of retraining changes. The current 419-dim
> model works correctly at ROC-AUC 0.9459 — PCA is an optimization, not a fix.

### Implementation

**3A. PCA in Training Pipeline** (~1.5 hrs)

Modify `backend/ml/train_xgboost.py`:

1. After SBERT encoding step, split data chronologically FIRST (preserve existing split logic)
2. Fit `sklearn.decomposition.PCA(n_components=0.95)` on `X_train_text` only (the SBERT portion of training data)
3. Transform `X_train_text`, `X_val_text`, `X_test_text` with the fitted PCA
4. Log: "PCA: 384 dims → {n} dims ({explained_variance:.1%} variance retained)"
5. Save PCA model to `backend/ml/pca_model.pkl` via `joblib.dump()`
6. Save reduced-dim feature matrix (35 tabular + n PCA components) alongside XGBoost model
7. Update `npz` save to include PCA dimensionality metadata

**3B. PCA at Inference** (~1 hr)

Modify `backend/ml/xgboost_predictor.py`:

1. Load PCA model at startup (alongside XGBoost model and calibrator)
2. After SBERT encoding in `predict()`, apply `pca.transform()` to the SBERT vector (384-dim → n-dim)
3. Concatenate reduced SBERT vector with the 35 tabular features
4. If PCA model file is missing: log warning, skip PCA, use full 384-dim embedding (graceful degradation)
5. Update `model_registry.json` schema to include `pca_file` field alongside `model_file` and `calibrator_file`

**3C. Update encoder.py** (~0.5 hr)

Add `pca_transform(embedding: np.ndarray) -> np.ndarray` utility function to `backend/ml/encoder.py`:

```python
def pca_transform(embedding: np.ndarray, pca_model_path: str = "ml/pca_model.pkl") -> np.ndarray:
    """Apply PCA transform to SBERT embedding. Falls back to raw embedding if PCA unavailable."""
    try:
        pca = joblib.load(pca_model_path)
        reduced = pca.transform(embedding.reshape(1, -1))
        return reduced.flatten()
    except (FileNotFoundError, Exception) as e:
        logger.warning("PCA transform failed (%s), using raw embedding", e)
        return embedding
```

Alternatively: keep PCA logic in predictor only (reduces surface area). Decision deferred to implementation — commander to decide based on whether `pca_transform` would be useful in other contexts.

**3D. Validation** (~1 hr)

After implementation:

1. Retrain model from scratch with PCA enabled
2. Verify ROC-AUC on test set doesn't degrade beyond 0.01 from current 0.9459 (minimum acceptable: 0.9359)
3. Compare model file size (before vs after PCA)
4. Compare inference latency (before vs after PCA) — measure 100 predictions
5. Update `feature_parity_check.py` to account for new dimensionality (if PCA is default)
6. If ROC-AUC degrades beyond 0.01: log findings, revert PCA, document for future investigation

**3E. Tests** (included in estimates)

| Test | What it verifies |
|------|-----------------|
| `test_pca_fit_on_train_only()` | PCA fitted on training data, NOT validation or test data |
| `test_pca_transform_consistency()` | Same input produces same output |
| `test_pca_inference_default()` | Inference uses PCA when model present |
| `test_pca_inference_fallback()` | Inference falls back to 384-dim when PCA missing |
| `test_pca_dimensionality_match()` | Training and inference produce same feature count |
| `test_pca_model_saved_and_loaded()` | PCA model persists and loads correctly |

### Acceptance Criteria

- [ ] PCA fitted on training data only, not on validation or test data (no leakage)
- [ ] PCA model saved to `pca_model.pkl` and loaded correctly at inference
- [ ] ROC-AUC doesn't degrade beyond 0.01 from baseline (0.9459 → 0.9359 minimum)
- [ ] Inference pipeline uses PCA when available, falls back gracefully to 384-dim when PCA model is missing
- [ ] Model file size reduced proportionally to PCA reduction (measure: before vs after)
- [ ] Inference latency improved or neutral (measure: 100 predictions before vs after)
- [ ] All existing tests pass
- [ ] `just lint` — ruff clean
- [ ] If ROC-AUC degrades beyond 0.01: revert PCA, document findings

---

## Verification & Quality Gates

### Per-Item Verification

| Item | Verify |
|------|--------|
| **Item 1** | `just test` — 298+ tests pass. `just lint` — ruff clean. |
| **Item 1** | Start server with `TRIAGEMATE_AGENT_ENABLED=true`, ingest CVE with mock LLM, verify tool calls in logs |
| **Item 1** | `TRIAGEMATE_AGENT_ENABLED=false` → legacy evaluate_tier_2() still used |
| **Item 1** | Set `TRIAGEMATE_AGENT_MAX_STEPS=3`, verify agent terminates with step-limit message |
| **Item 1** | Set `TRIAGEMATE_LLM_COST_BUDGET=0.01`, verify agent terminates with budget-exceeded message |
| **Item 2** | `PUT /api/admin/config/scoring` with valid weights → returns 200, scores recalculated |
| **Item 2** | `PUT /api/admin/config/scoring` with sum < 100 → returns 422 |
| **Item 2** | `POST /api/admin/config/scoring/reset` → returns 200, weights restored to defaults |
| **Item 2** | Without JWT token → all admin endpoints return 401 |
| **Item 3** | `python -c "from sklearn.decomposition import PCA; pca = PCA(n_components=0.95); ..."` — verify explained variance |
| **Item 3** | Delete `pca_model.pkl`, run inference — verify graceful fallback (log warning, full 384-dim used) |
| **Item 3** | `python -c "import joblib; pca = joblib.load('backend/ml/pca_model.pkl'); print(pca.n_components_)"` — verify n_components logged |

### Sprint Quality Gate (when executed)

```bash
just gate          # lint → test → audit-all
just graphify      # regenerate auto-generated docs
```

---

## Team Assignments (when executed)

| Item | Subagent | Notes |
|------|----------|-------|
| 1A (Tools) | strike | Create `tier_2/tools.py` with 12 tool wrappers |
| 1B (Agent Loop) | strike | Implement `AgenticEvaluator` with provider tool-calling |
| 1C (Refactor) | strike | Update `ingest.py` call site + legacy fallback |
| 1D (Guardrails) | strike | Cost budget, step limit, feature flag, logging |
| 2A (Config File) | strike | `scoring_weights.json` override in `scoring.py` |
| 2B (Admin API) | strike | GET/PUT/POST admin endpoints in `admin.py` |
| 2C (Frontend) | strike | Admin settings page with sliders and live recalculation |
| 3A (Training PCA) | strike | PCA in `train_xgboost.py` |
| 3B (Inference PCA) | strike | PCA in `xgboost_predictor.py` |
| 3C (Encoder) | strike | `pca_transform` utility in `encoder.py` |
| 3D (Validation) | strike | Retrain + benchmark + compare metrics |
| Post-audit | auditor | Full audit pass after all items complete |
| Bookkeeping | bookkeeper | Update ROADMAP.md, INDEX.md, sprint plan archive |

> **Note:** All items assigned to strike. Items 1 and 3 are independent of each other. Item 2 has a hard dependency on Sprint 19 Item 1 (config package) but is independent of Items 1 and 3. Execution order: Item 1 and Item 3 can proceed in parallel after Sprint 19 gate clears; Item 2 must verify config module exists first.

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| 🔴 Item 1: LLM tool calling unreliable across providers (Together AI lacks native tool API) | Medium | High | Feature-flag gated (`TRIAGEMATE_AGENT_ENABLED=false` default). Legacy single-shot fallback always available. Together AI uses JSON-mode + manual tool call parsing. |
| 🔴 Item 1: Cost overruns from multi-step LLM calls | Medium | Medium | Configurable cost budget per CVE ($0.50 default). Step limit hard cap (15 default, 20 max). Structured cost logging with per-tool granularity. |
| 🟡 Item 1: LLM hallucinates tool calls or misuses tools | Medium | Medium | Tool schemas are strict. Invalid tool calls return error messages rather than crashing. `submit_resolution` required for final output. All tool calls logged. |
| 🟡 Item 2: Weight config file corruption causes scoring failure | Low | High | JSON validation on load. Invalid config → log warning + fallback to defaults. Never crash. Validation includes sum, range, and key-presence checks. |
| 🟡 Item 2: Admin API unauthorized access | Low | High | JWT auth-gated. Admin role required. All endpoints behind auth middleware. Rate limiting on PUT endpoint. |
| 🟢 Item 3: PCA degrades ROC-AUC beyond 0.01 threshold | Medium | Medium | Acceptance criterion: ≥0.9359 (0.01 below baseline 0.9459). If degraded: revert PCA, document findings, log the degradation. |
| 🟢 Item 3: PCA model file missing at inference | Low | Medium | Graceful degradation: use full 384-dim embedding. Log warning. Test verifies this path. Model is loaded only once at startup. |
| 🔴 Cross-cutting: Sprint 19 changes conflict with this plan | Medium | High | Pre-execution gate requires re-analysis after Sprint 19. Commander must verify config module existence, retraining infrastructure, and score contract before proceeding. |
| 🟡 Cross-cutting: Item 2 config module assumptions invalidated by Sprint 19 | Medium | High | Sprint 19 may change `scoring.py` structure. Commander must re-verify before Item 2 implementation begins. |

---

## Appendix A: Dependency Map

```
Sprint 19 (active) ──── complete ────→ Commander re-analysis
                                            │
                          ┌─────────────────┼─────────────────┐
                          ↓                 ↓                  ↓
                     Item 1 (Agentic)  Item 3 (PCA)     Item 2 (Weights)
                          │           [deferrable per      │
                          │            Decision D3]   depends on Sprint 19
                          │                             Item 1 (config pkg)
                          ↓                 ↓                  ↓
                    Independent        Run last          Run after Item 1
                    (feature-flag      (only if PCA      (config must exist;
                     gated rollout)     not deferred)     admin UI last)
```

Items 1 and 3 are independent and can be implemented in parallel. Item 2 must wait for both the Sprint 19 gate and commander verification of the config module structure.

---

## Appendix B: Files to Create/Modify (when executed)

### New Files

```
backend/pipeline/tier_2/tools.py              # Item 1 — Tool definitions (all 12 tools)
backend/pipeline/tier_2/agent.py              # Item 1 — Agentic loop (AgenticEvaluator class)
backend/pipeline/tier_2/__init__.py           # Item 1 — Package init for tier_2 subpackage
backend/pipeline/config/scoring_weights.json  # Item 2 — Optional weight override file (gitignored)
backend/routers/admin.py                      # Item 2 — Admin API endpoints (GET/PUT/POST)
frontend/js/components/adminSettings.js        # Item 2 — Admin settings page component
backend/ml/pca_model.pkl                       # Item 3 — PCA model (generated at training)
```

### Modified Files

```
backend/pipeline/tier_2.py                    # Item 1 — Refactored or kept as legacy fallback
backend/routers/ingest.py                     # Item 1 — Updated Tier 2 call site
backend/ml/train_xgboost.py                   # Item 3 — PCA in training pipeline
backend/ml/xgboost_predictor.py               # Item 3 — PCA at inference + graceful fallback
backend/ml/encoder.py                         # Item 3 — pca_transform utility function
backend/ml/model_registry.json                # Item 3 — Schema updated for pca_file field
backend/pipeline/config/scoring.py            # Item 2 — Config file loading logic + hot-reload
frontend/index.html                           # Item 2 — Admin page route + container
frontend/js/app.js                            # Item 2 — Admin page registration
justfile                                      # Items 1-3 — Any new recipes as needed
```

### Files NOT Modified

```
backend/scoring.py                            # No change needed — reads weights from config
backend/database.py                           # No schema changes in this sprint
backend/scheduler.py                          # Item 2 retrains from Sprint 19 — no change
backend/models.py                             # No new models needed (TriageConflictResult reused)
backend/integrations/*.py                     # Tools wrap existing integrations, don't modify them
```

---

## Appendix C: Item 2 — Validation Rules for Scoring Weights

The `scoring_weights.json` override file must pass these validation rules:

```python
VALID_KEYS = {"cvss", "epss", "criticality", "exposure", "patch", "ml_exploitation", "security_context"}
MIN_WEIGHT = 1
MAX_WEIGHT = 100
MIN_SUM = 100  # Weights must sum to at least 100
```

| Condition | Action |
|-----------|--------|
| File missing | Silently use defaults |
| File invalid JSON | Log warning, use defaults |
| Missing keys | Fill missing keys from defaults |
| Extra keys | Ignore extra keys |
| Any weight < 1 | Reject all, use defaults |
| Any weight > 100 | Reject all, use defaults |
| Sum < 100 | Reject all, use defaults |
| All valid | Merge with defaults, use merged result |

---

## Appendix D: Item 3 — PCA Decision Flow

```
                     ┌─────────────────────────┐
                     │  SBERT encoding produces │
                     │  384-dim embedding       │
                     └──────────┬──────────────┘
                                │
                     ┌──────────▼──────────────┐
                     │  pca_model.pkl exists?   │
                     └──────────┬──────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │ YES               │ NO                 │
            ▼                   ▼                    ▼
   ┌─────────────────┐  ┌─────────────────┐
   │ Apply PCA       │  │ Log warning:     │
   │ 384 → n dims    │  │ "PCA model not   │
   │                 │  │ found, using raw │
   │ Concatenate     │  │ 384-dim vector"  │
   │ 35 + n = total  │  │                  │
   └────────┬────────┘  │ Concatenate      │
            │           │ 35 + 384 = 419   │
            │           └────────┬─────────┘
            └────────────────────┼────────────────────┐
                                 ▼                    ▼
                        ┌─────────────────┐  ┌─────────────────┐
                        │ XGBoost predict │  │ XGBoost predict │
                        │ (n+35 dims)     │  │ (419 dims)      │
                        └─────────────────┘  └─────────────────┘
```

The graceful degradation path (PCA model missing) ensures that a missing or corrupted `pca_model.pkl` never crashes inference. The system logs the condition and falls back to the full 419-dim feature vector.

---

## Appendix E: Sprint 20 — Key Design Decisions

These decisions are flagged for commander review during the pre-execution re-analysis:

| # | Decision | Options | Recommendation |
|---|----------|---------|----------------|
| D1 | Where should `pca_transform` live? | (A) `encoder.py` as a utility function, (B) inline in `xgboost_predictor.py` | (A) — cleaner separation, reusable if other consumers need PCA'd embeddings |
| D2 | Should Tier 2 subpackage replace or coexist with `tier_2.py`? | (A) Replace with `tier_2/` package, (B) Keep `tier_2.py` as fallback + new `tier_2/` package | (B) — lower risk, keeps legacy path cleanly separated |
| D3 | Scoring weights: API-only or also file-based? | (A) API-only (in-memory), (B) File + API | (B) — file persists across restarts without DB dependency |
| D4 | PCA: hard requirement or optional optimization? | (A) Required if ROC-AUC ≥ 0.9359, (B) Always optional behind a feature flag | (A) — if degradation is within bounds, it's strictly better (smaller, faster). If beyond bounds, revert. |
| D5 | 7 demo CVE scores — do they change with PCA? | PCA only affects SBERT → XGBoost path. Demo CVE scores go through Tier 1/XGBoost. | Scores may shift slightly with reduced encoding. Accept if shift is ≤ ±3 from baseline. |

---

## Appendix F: Scope Boundaries

This sprint does NOT include:

- **Database schema changes** — no new tables, no ground truth columns (deferred from Sprint 19 Item 4 Part B)
- **Ground truth feedback loop** — API stubs exist from Sprint 19, but full implementation with DB changes is not in this sprint
- **New threat intel integrations** — tools wrap existing integrations only; no new data sources
- **Webhook system** — deferred from Sprint 19 Bonus C
- **CI benchmark gates** — deferred from Sprint 19 Bonus D
- **Alembic migrations** — deferred from Sprint 19 Bonus E
- **Model rollback API** — deferred from Sprint 19 Bonus G
- **UI redesign** — only the admin settings page is new frontend surface
- **Performance testing** — PCA validation includes latency measurement, but no dedicated performance sprint
