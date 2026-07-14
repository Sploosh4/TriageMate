import os
from pathlib import Path
from dotenv import load_dotenv

# ─── Resolve project root from this file's location ────────────────────
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_BASE_DIR, ".."))

# ─── Load .env BEFORE any module reads os.getenv() ─────────────────────
_env_path = Path(__file__).resolve().parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))

import logging  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # noqa: E402
from fastapi import FastAPI, Depends  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402
from middleware.rate_limit import limiter  # noqa: E402
from database import init_db  # noqa: E402
from routers import admin, auth, config, queue, cases, ingest, models as models_router  # noqa: E402
from auth import get_current_user, AUTH_DISABLED  # noqa: E402
import asyncio  # noqa: E402

from logging_config import setup_logging  # noqa: E402

logger = logging.getLogger("triagemate")

# Scheduler reference (populated during lifespan start)
_scheduler: AsyncIOScheduler | None = None


async def _background_recheck_loop():
    """Run low-severity re-checks once per day."""
    while True:
        await asyncio.sleep(86400)
        try:
            from scheduler import recheck_low_severity

            await recheck_low_severity()
        except Exception as e:
            logger.warning(f"Background re-check error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    init_db()

    # Pre-load SentenceTransformer embedder for RAG
    try:
        from ml.vector_store import _get_embedder

        _get_embedder()
        logger.info("SentenceTransformer embedder loaded")
    except Exception as e:
        logger.warning(f"Embedder pre-load skipped: {e}")

    # Initialize and seed vector store
    try:
        from ml.vector_store import init_vector_store, seed_demo_documents
        import lancedb
        from ml.vector_store import DB_PATH, TABLE_NAME

        init_vector_store()
        db = lancedb.connect(str(DB_PATH))
        if TABLE_NAME in db.list_tables().tables:
            tbl = db.open_table(TABLE_NAME)
            if tbl.count_rows() == 0:
                seed_demo_documents(db)
        else:
            seed_demo_documents(db)
        logger.info("Vector store initialized and seeded")
    except Exception as e:
        logger.warning(f"Vector store init skipped: {e}")

    if AUTH_DISABLED:
        logger.warning("AUTH IS DISABLED — set TRIAGEMATE_ADMIN_USER in .env to enable")

    # Warn if Tier 2 cloud LLM is not configured
    api_key = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
    if not api_key:
        logger.warning(
            "Tier 2 cloud LLM disabled — no TRIAGEMATE_LLM_API_KEY set. "
            "Using KNOWN_CONFLICTS fallback only. "
            "Set the environment variable or create a .env file to enable cloud LLM analysis."
        )

    task = asyncio.create_task(_background_recheck_loop())

    # ── Start retraining scheduler ───────────────────────────────────────
    global _scheduler
    try:
        from scheduler import (
            check_drift_and_retrain,
            RETRAIN_INTERVAL_HOURS,
            RETRAIN_DRIFT_THRESHOLD,
        )

        _scheduler = AsyncIOScheduler()
        _scheduler.add_job(
            check_drift_and_retrain,
            "interval",
            hours=RETRAIN_INTERVAL_HOURS,
            id="drift_retrain",
            replace_existing=True,
        )
        _scheduler.start()
        logger.info(
            "Retraining scheduler registered (interval=%dh, drift_threshold=%0.3f)",
            RETRAIN_INTERVAL_HOURS,
            RETRAIN_DRIFT_THRESHOLD,
        )
    except Exception as e:
        logger.warning("Retraining scheduler registration skipped: %s", e)

    yield

    # ── Shutdown ─────────────────────────────────────────────────────────
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    if _scheduler:
        _scheduler.shutdown()
        logger.info("Retraining scheduler shut down")


app = FastAPI(title="TriageMate API", version="2.5.0", lifespan=lifespan)

# Wire slowapi rate limiter — per-route limits applied via @limiter.limit()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# TODO(cloud-deploy): restrict allow_origins to known frontend domains
# and set allow_credentials=True when moving off localhost.
# Tracked in ROADMAP.md § Sprint NEXT+ Item 7.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.mount(
    "/css",
    StaticFiles(directory=os.path.join(_PROJECT_ROOT, "frontend", "css")),
    name="css",
)
app.mount(
    "/js",
    StaticFiles(directory=os.path.join(_PROJECT_ROOT, "frontend", "js")),
    name="js",
)

app.include_router(config.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(queue.router, dependencies=[Depends(get_current_user)])
app.include_router(cases.router, dependencies=[Depends(get_current_user)])
app.include_router(ingest.router, dependencies=[Depends(get_current_user)])
app.include_router(models_router.router, dependencies=[Depends(get_current_user)])
app.include_router(
    models_router.rollback_router, dependencies=[Depends(get_current_user)]
)


@app.get("/")
async def root():
    from fastapi.responses import FileResponse

    return FileResponse(os.path.join(_PROJECT_ROOT, "frontend", "index.html"))


@app.get("/api/health")
async def health():
    """Health check endpoint returning dependency status.

    Does NOT probe the LLM API (would incur cost).
    Reports configuration status only.
    """
    api_key = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
    provider = os.getenv("TRIAGEMATE_LLM_PROVIDER", "openai")

    try:
        import lancedb
        from ml.vector_store import DB_PATH, TABLE_NAME

        db = lancedb.connect(str(DB_PATH))
        if TABLE_NAME in db.list_tables().tables:
            tbl = db.open_table(TABLE_NAME)
            doc_count = tbl.count_rows()
        else:
            doc_count = 0
    except Exception:
        doc_count = -1

    from ml.vector_store import DB_PATH as rag_db_path
    from integrations.nvd import get_nvd_health
    from integrations.cache_health import get_kev_health, get_epss_health

    nvd_health = get_nvd_health()
    kev_health = get_kev_health()
    epss_health = get_epss_health()

    return {
        "status": "ok",
        "version": "2.5.0",
        "tier_2_provider": provider if api_key else "none",
        "llm_available": bool(api_key),
        "rag_documents": doc_count,
        "rag_store_path": str(rag_db_path),
        "nvd_last_success": nvd_health["nvd_last_success"],
        "nvd_status": nvd_health["nvd_status"],
        **kev_health,
        **epss_health,
        "demo_mode": os.getenv("DEMO_MODE", "false").lower() == "true",
        "auth_required": not AUTH_DISABLED,
    }
