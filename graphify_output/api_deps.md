# TriageMate — API Dependency Map

> Caller -> callee relationships. Generated from Python AST.
> Grouped by import category (stdlib / project / external).

## backend/audit.py

**Project**

- `database`  (from(get_db))

**Stdlib**

- `random`  (import)

## backend/auth.py

**External**

- `bcrypt`  (import)
- `fastapi`  (from(Depends), from(HTTPException), from(status))
- `fastapi.security`  (from(HTTPAuthorizationCredentials), from(HTTPBearer))
- `jwt`  (import)

**Stdlib**

- `datetime`  (from(datetime), from(timedelta), from(timezone))
- `logging`  (import)
- `os`  (import)

## backend/database.py

**External**

- `alembic`  (from(command))
- `alembic.config`  (from(Config))
- `psycopg2`  (import)
- `psycopg2.extras`  (import)

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))
- `sqlite3`  (import)

## backend/ingest_cwe.py

**Project**

- `integrations.nvd`  (from(get_nvd_data))

**Stdlib**

- `logging`  (import)
- `re`  (import)

## backend/ingest_helpers.py

**Project**

- `integrations.cmdb`  (from(get_asset_context), from(is_internet_facing), from(lookup_data_classification))
- `integrations.exploitdb`  (from(has_poc))
- `integrations.metasploit`  (from(has_payload))
- `integrations.nvd`  (from(get_nvd_data))
- `integrations.otx`  (from(query_otx_pulses))
- `ml.vector_store`  (from(query_rag))
- `pipeline.config.feature_names`  (from(TABULAR_FEATURE_ORDER))

**Stdlib**

- `datetime`  (from(date), from(datetime))
- `json`  (import)
- `pathlib`  (from(Path))
- `re`  (import)

## backend/integrations/advisories.py

**Stdlib**

- `logging`  (import)

## backend/integrations/cache_health.py

**Stdlib**

- `datetime`  (from(datetime), from(timezone))
- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))

## backend/integrations/cmdb.py

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))
- `re`  (import)

## backend/integrations/demo_generator.py

**Project**

- `models`  (from(IngestRequest))

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))
- `random`  (import)
- `re`  (import)

## backend/integrations/exploitdb.py

**Project**

- `integrations.nvd`  (from(get_nvd_data))

**Stdlib**

- `csv`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))

## backend/integrations/greynoise.py

**External**

- `requests`  (import)

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `time`  (import)

## backend/integrations/metasploit.py

**Project**

- `integrations.exploitdb`  (from(_lookup_edb))
- `integrations.nvd`  (from(get_nvd_data))

**Stdlib**

- `logging`  (import)

## backend/integrations/mitre_mapping.py

**Stdlib**

- `logging`  (import)

## backend/integrations/network_context.py

**Project**

- `database`  (from(get_db))

**Stdlib**

- `logging`  (import)

## backend/integrations/nvd.py

**Project**

- `integrations.osv`  (from(query_osv))

**Stdlib**

- `datetime`  (from(datetime), from(timezone))
- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))
- `time`  (import)
- `urllib.error`  (import)
- `urllib.request`  (import)

## backend/integrations/osv.py

**External**

- `requests`  (import)

**Stdlib**

- `logging`  (import)
- `time`  (import)

## backend/integrations/otx.py

**External**

- `requests`  (import)

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `time`  (import)

## backend/integrations/synthetic_telemetry.py

**Stdlib**

- `datetime`  (from(datetime), from(timedelta))
- `hashlib`  (import)
- `logging`  (import)
- `random`  (import)

## backend/integrations/tenable.py

**Project**

- `models`  (from(IngestRequest))

**Stdlib**

- `logging`  (import)
- `typing`  (from(Optional))

## backend/logging_config.py

**Stdlib**

- `datetime`  (from(datetime), from(timezone))
- `json`  (import)
- `logging`  (import)
- `os`  (import)

## backend/main.py

**Project**

- `auth`  (from(AUTH_DISABLED), from(get_current_user))
- `database`  (from(init_db))
- `integrations.cache_health`  (from(get_epss_health), from(get_kev_health))
- `integrations.nvd`  (from(get_nvd_health))
- `logging_config`  (from(setup_logging))
- `middleware.rate_limit`  (from(clear_bucket), from(demo_bucket), from(ingest_bucket))
- `ml.vector_store`  (from(DB_PATH), from(TABLE_NAME), from(_get_embedder), from(init_vector_store), from(seed_demo_documents))
- `routers`  (from(admin), from(auth), from(cases), from(config), from(ingest), from(models), from(queue))
- `scheduler`  (from(RETRAIN_DRIFT_THRESHOLD), from(RETRAIN_INTERVAL_HOURS), from(check_drift_and_retrain), from(recheck_low_severity))

**External**

- `apscheduler.schedulers.asyncio`  (from(AsyncIOScheduler))
- `bcrypt`  (import)
- `dotenv`  (from(load_dotenv))
- `fastapi`  (from(Depends), from(FastAPI))
- `fastapi.middleware.cors`  (from(CORSMiddleware))
- `fastapi.responses`  (from(FileResponse), from(JSONResponse))
- `fastapi.staticfiles`  (from(StaticFiles))
- `lancedb`  (import)

**Stdlib**

- `asyncio`  (import)
- `contextlib`  (from(asynccontextmanager))
- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))

## backend/ml/encoder.py

**External**

- `numpy`  (import)
- `requests`  (import)
- `sentence_transformers`  (from(SentenceTransformer))

**Stdlib**

- `logging`  (import)
- `pathlib`  (from(Path))
- `threading`  (import)

## backend/ml/epss_substitutor.py

**Project**

- `pipeline.config.feature_names`  (from(EPSS_V1_FEATURE_NAMES), from(EPSS_V2_FEATURE_NAMES))

**External**

- `joblib`  (import)
- `numpy`  (import)

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `warnings`  (import)

## backend/ml/fetch_epss_data.py

**Stdlib**

- `csv`  (import)
- `datetime`  (from(date), from(datetime))
- `gzip`  (import)
- `io`  (import)
- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `sys`  (import)
- `urllib.request`  (import)

## backend/ml/generate_supplemental_hostnames.py

**Stdlib**

- `collections`  (from(Counter))
- `json`  (import)
- `pathlib`  (from(Path))
- `random`  (import)

## backend/ml/generate_synthetic_data_v2.py

**Project**

- `database`  (from(get_db))

**Stdlib**

- `collections`  (from(Counter))
- `datetime`  (from(datetime))
- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))
- `random`  (import)

## backend/ml/generate_synthetic_findings.py

**Project**

- `database`  (from(get_db), from(init_db))

**External**

- `numpy`  (import)

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `random`  (import)
- `sys`  (import)

## backend/ml/ingest_docs.py

**Project**

- `ml.vector_store`  (from(add_documents), from(clear_documents), from(init_vector_store))

**Stdlib**

- `argparse`  (import)
- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))
- `sys`  (import)

## backend/ml/train_epss_substitutor.py

**External**

- `joblib`  (import)
- `numpy`  (import)
- `sklearn.metrics`  (from(mean_squared_error), from(r2_score))
- `sklearn.model_selection`  (from(train_test_split))
- `xgboost`  (import)

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `random`  (import)
- `warnings`  (import)

## backend/ml/train_epss_v2.py

**External**

- `joblib`  (import)
- `numpy`  (import)
- `sklearn.metrics`  (from(mean_squared_error), from(r2_score))
- `sklearn.model_selection`  (from(train_test_split))
- `xgboost`  (import)

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `random`  (import)
- `warnings`  (import)

## backend/ml/train_epss_v3.py

**External**

- `joblib`  (import)
- `numpy`  (import)
- `sklearn.metrics`  (from(mean_squared_error), from(r2_score))
- `sklearn.model_selection`  (from(train_test_split))
- `xgboost`  (from(XGBRegressor))

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `sys`  (import)

## backend/ml/train_epss_v4.py

**Project**

- `database`  (from(get_db), from(init_db))

**External**

- `joblib`  (import)
- `numpy`  (import)
- `sklearn.metrics`  (from(mean_squared_error), from(r2_score))
- `sklearn.model_selection`  (from(train_test_split))
- `xgboost`  (from(XGBRegressor))

**Stdlib**

- `logging`  (import)
- `os`  (import)
- `sys`  (import)

## backend/ml/train_pre_tier.py

**Project**

- `database`  (from(get_db))
- `ml.pretier_features`  (from(AGENCIES), from(extract_features), from(feature_vector_to_array), from(get_feature_count), from(get_feature_names))

**External**

- `joblib`  (import)
- `numpy`  (import)
- `sklearn.ensemble`  (from(RandomForestClassifier))
- `sklearn.metrics`  (from(accuracy_score))
- `sklearn.model_selection`  (from(StratifiedKFold))
- `sklearn.multioutput`  (from(MultiOutputClassifier))

**Stdlib**

- `argparse`  (import)
- `collections`  (from(Counter))
- `datetime`  (from(datetime), from(timezone))
- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))
- `sys`  (import)

## backend/ml/train_xgboost.py

**Project**

- `ml.encoder`  (from(encode_batch))
- `pipeline.config.feature_names`  (from(TABULAR_FEATURE_ORDER), from(make_sbert_feature_names))

**External**

- `joblib`  (import)
- `numpy`  (import)
- `requests`  (import)
- `sklearn.decomposition`  (from(PCA))
- `sklearn.linear_model`  (from(LogisticRegression))
- `sklearn.metrics`  (from(accuracy_score), from(classification_report), from(f1_score), from(roc_auc_score))
- `sklearn.utils.class_weight`  (from(compute_class_weight))
- `xgboost`  (import)

**Stdlib**

- `collections`  (from(Counter))
- `datetime`  (from(datetime), from(timedelta), from(timezone))
- `json`  (import)
- `os`  (import)
- `pathlib`  (from(Path))
- `re`  (import)
- `sys`  (import)
- `time`  (import)

## backend/ml/vector_store.py

**External**

- `lancedb`  (import)
- `pyarrow`  (import)
- `sentence_transformers`  (from(SentenceTransformer))

**Stdlib**

- `logging`  (import)
- `pathlib`  (from(Path))
- `threading`  (import)
- `time`  (import)
- `typing`  (from(Optional))

## backend/ml/xgboost_predictor.py

**Project**

- `ml.encoder`  (from(encode_description))
- `pipeline.config.feature_names`  (from(TABULAR_FEATURE_ORDER))
- `pipeline.config.thresholds`  (from(CWE_EPSS_THRESHOLDS), from(DEFAULT_EPSS_THRESHOLD), from(LOW_PROB_THRESHOLD), from(MID_PROB_THRESHOLD), from(UNCERTAINTY_THRESHOLD))

**External**

- `joblib`  (import)
- `numpy`  (import)
- `xgboost`  (import)

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))
- `threading`  (import)

## backend/models.py

**External**

- `pydantic`  (from(BaseModel), from(Field))

**Stdlib**

- `typing`  (from(Optional))

## backend/pipeline/pre_tier.py

**Project**

- `ml.pretier_features`  (from(extract_features), from(feature_vector_to_array))

**External**

- `joblib`  (import)
- `numpy`  (import)

**Stdlib**

- `logging`  (import)
- `pathlib`  (from(Path))
- `threading`  (import)

## backend/pipeline/tier_0.py

**Project**

- `pipeline.config.thresholds`  (from(CWE_EPSS_THRESHOLDS), from(KEV_CVSS_THRESHOLD), from(KEV_EPSS_THRESHOLD), from(LOW_CVSS_THRESHOLD), from(LOW_EPSS_THRESHOLD), from(NVD_REF_THRESHOLD))

**Stdlib**

- `logging`  (import)

## backend/pipeline/tier_1.py

**Project**

- `ml.xgboost_predictor`  (from(predict))

**Stdlib**

- `logging`  (import)

## backend/routers/admin.py

**Project**

- `auth`  (from(get_current_user_if_enabled))
- `pipeline.config.scoring`  (from(_MAX_WEIGHT), from(_MIN_TOTAL), from(_MIN_WEIGHT), from(reload_weights), from(reset_weights_to_defaults), import)

**External**

- `fastapi`  (from(APIRouter), from(Depends), from(HTTPException))
- `pydantic`  (from(BaseModel), from(Field))

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))

## backend/routers/auth.py

**Project**

- `auth`  (from(ADMIN_PASS_HASH), from(ADMIN_USER), from(AUTH_DISABLED), from(create_access_token), from(create_refresh_token), from(verify_password), from(verify_token))
- `models`  (from(LoginRequest), from(RefreshRequest), from(TokenResponse))

**External**

- `fastapi`  (from(APIRouter), from(HTTPException), from(status))

**Stdlib**

- `logging`  (import)

## backend/routers/cases.py

**Project**

- `database`  (from(get_db))
- `ingest_helpers`  (from(compliance_category))
- `integrations.nvd`  (from(get_cve_freshness))
- `models`  (from(AssetRegistryEntry), from(CaseResponse), from(CaseViewData), from(MitreTechnique), from(NetworkContextData), from(QueueRow), from(ReviewQueueItem), from(ReviewQueueResponse), from(ReviewRequest), from(ScoringWeight), from(SubstitutionBlock))

**External**

- `fastapi`  (from(APIRouter), from(HTTPException))
- `pydantic`  (from(BaseModel))

**Stdlib**

- `datetime`  (from(datetime), from(timezone))
- `html`  (import)
- `json`  (import)

## backend/routers/config.py

**Project**

- `pipeline.config`  (from(feature_names), from(scoring), from(thresholds))

**External**

- `fastapi`  (from(APIRouter))

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))

## backend/routers/ingest.py

**Project**

- `audit`  (from(select_for_audit), from(should_audit))
- `database`  (from(get_db))
- `ingest_cwe`  (from(get_cwe))
- `ingest_helpers`  (from(build_feature_vector), from(compliance_category), from(get_asset_context), from(is_internet_facing), from(lookup_data_classification), from(query_rag), from(serialize_tabular_features))
- `integrations.advisories`  (from(get_advisory))
- `integrations.cmdb`  (from(validate_wa_gov_hostname))
- `integrations.demo_generator`  (from(generate_random_wave), from(generate_scenario_findings), from(get_scenarios_list), from(inject_enrichment))
- `integrations.mitre_mapping`  (from(lookup_mitre))
- `integrations.network_context`  (from(get_network_context))
- `integrations.nvd`  (from(get_cve_freshness), from(get_nvd_data))
- `integrations.synthetic_telemetry`  (from(get_telemetry_context))
- `integrations.tenable`  (from(parse_tenable_batch), from(parse_tenable_webhook))
- `ml.epss_substitutor`  (from(calculate_substitution), from(get_last_feature_vector))
- `models`  (from(CaseResponse), from(CaseViewData), from(IngestRequest), from(QueueRow), from(SubstitutionBlock))
- `pipeline`  (from(pre_tier), from(tier_0), from(tier_1), from(tier_2))
- `pipeline.pre_tier`  (from(extract_pre_tier_features))
- `routers.cases`  (from(_band_colour))
- `scoring`  (from(calculate_final_score))

**External**

- `fastapi`  (from(APIRouter), from(HTTPException), from(Request))
- `fastapi.responses`  (from(JSONResponse))

**Stdlib**

- `html`  (import)
- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `time`  (import)

## backend/routers/models.py

**Project**

- `ml.xgboost_predictor`  (from(set_active_version))

**External**

- `fastapi`  (from(APIRouter), from(HTTPException), from(Query))
- `pydantic`  (from(BaseModel))

**Stdlib**

- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))

## backend/routers/queue.py

**Project**

- `analysis.drift`  (from(compute_drift))
- `database`  (from(get_db))
- `ingest_helpers`  (from(compliance_category))
- `models`  (from(AccuracyResponse), from(ConceptDriftResponse), from(DailyTimeSeries), from(DistributionStats), from(DriftMetricsResponse), from(FeedbackResponse), from(FeedbackSubmission), from(MetricsResponse), from(MlDriftFeature), from(MlDriftResponse), from(PredictionDistribution), from(QueueResponse), from(QueueRow), from(RoutingCounts), from(TierRouting), from(TimeSeries), from(Window))
- `scheduler`  (from(LOCK_FILE), from(RETRAIN_DRIFT_THRESHOLD), from(RETRAIN_INTERVAL_HOURS))

**External**

- `fastapi`  (from(APIRouter), from(Query))

**Stdlib**

- `datetime`  (from(datetime), from(timedelta), from(timezone))
- `json`  (import)
- `logging`  (import)
- `pathlib`  (from(Path))
- `sqlite3`  (import)
- `statistics`  (import)

## backend/scheduler.py

**Project**

- `analysis.drift`  (from(compute_drift))
- `database`  (from(get_db))
- `ml.pretier_features`  (from(get_feature_count))
- `ml.train_epss_substitutor`  (from(main))
- `ml.train_pre_tier`  (from(cross_validate), from(evaluate_holdout), from(export_model), from(load_holdout_data), from(load_training_data_from_db), from(save_metrics), from(train_model))
- `ml.train_xgboost`  (from(TRAINING_DATA_FILE), from(load_training_data), from(phase_train))
- `pipeline.config.thresholds`  (from(DRIFT_WARNING_PSI))

**External**

- `numpy`  (import)

**Stdlib**

- `asyncio`  (import)
- `datetime`  (from(datetime), from(timezone))
- `json`  (import)
- `logging`  (import)
- `os`  (import)
- `pathlib`  (from(Path))

## backend/scoring.py

**Project**

- `pipeline.config.scoring`  (from(CLAMP_MAX), from(CLAMP_MIN), from(CONTEXT_MULTIPLIER_VALUES), from(CRITICALITY_MAX), from(PATCH_MAX), from(SCORING_WEIGHTS), from(TELEMETRY_ACTIVE_THRESHOLD))

## backend/seed_data.py

**Project**

- `database`  (from(get_db), from(init_db))

**Stdlib**

- `json`  (import)

## main.py

**Project**

- `routers/admin.py`  (include_router)
- `routers/auth.py`  (include_router)
- `routers/cases.py`  (include_router)
- `routers/config.py`  (include_router)
- `routers/ingest.py`  (include_router)
- `routers/models_router.py`  (include_router)
- `routers/queue.py`  (include_router)

