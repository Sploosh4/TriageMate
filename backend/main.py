import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from routers import auth, queue, cases, ingest
from auth import get_current_user, AUTH_DISABLED
import asyncio

from logging_config import setup_logging

logger = logging.getLogger("triagemate")


# Auth startup logic — hash plain-text password if needed
def _check_admin_password():
    import bcrypt

    admin_pass = os.getenv("TRIAGEMATE_ADMIN_PASS", "")
    admin_pass_hash = os.getenv("TRIAGEMATE_ADMIN_PASS_HASH", "")
    if admin_pass and not admin_pass_hash:
        hashed = bcrypt.hashpw(admin_pass.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        logger.warning(
            "TRIAGEMATE_ADMIN_PASS is set as plain text. "
            "Set TRIAGEMATE_ADMIN_PASS_HASH=%s instead for better security.",
            hashed,
        )


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
    _check_admin_password()
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

    # Warn if Tier 2 cloud LLM is not configured
    api_key = os.getenv("TRIAGEMATE_LLM_API_KEY", "")
    if not api_key:
        logger.warning(
            "Tier 2 cloud LLM disabled — no TRIAGEMATE_LLM_API_KEY set. "
            "Using KNOWN_CONFLICTS fallback only. "
            "Set the environment variable or create a .env file to enable cloud LLM analysis."
        )

    task = asyncio.create_task(_background_recheck_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="TriageMate API", version="0.2.0", lifespan=lifespan)
app.state.cwe_available = False  # Will be updated on startup if CWE model loads

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    from middleware.rate_limit import ingest_bucket, demo_bucket, clear_bucket

    path = request.url.path
    if request.method == "POST":
        if path in ("/api/ingest", "/api/ingest/batch", "/api/ingest/tenable"):
            if not ingest_bucket.allow():
                from fastapi.responses import JSONResponse

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Too many ingest requests."
                    },
                    headers={"Retry-After": str(int(ingest_bucket.retry_after()))},
                )
        elif path == "/api/demo/generate":
            if not demo_bucket.allow():
                from fastapi.responses import JSONResponse

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Slow down demo generation."
                    },
                    headers={"Retry-After": str(int(demo_bucket.retry_after()))},
                )
        elif path == "/api/ingest/clear":
            if not clear_bucket.allow():
                from fastapi.responses import JSONResponse

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Clear is limited to 2/minute."
                    },
                    headers={"Retry-After": str(int(clear_bucket.retry_after()))},
                )
    return await call_next(request)


app.mount("/css", StaticFiles(directory="../frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="../frontend/js"), name="js")

app.include_router(auth.router)
app.include_router(queue.router, dependencies=[Depends(get_current_user)])
app.include_router(cases.router, dependencies=[Depends(get_current_user)])
app.include_router(ingest.router, dependencies=[Depends(get_current_user)])


@app.get("/")
async def root():
    from fastapi.responses import FileResponse

    return FileResponse("../frontend/index.html")


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

    nvd_health = get_nvd_health()

    return {
        "status": "ok",
        "version": "0.2.0",
        "tier_2_provider": provider if api_key else "none",
        "llm_available": bool(api_key),
        "rag_documents": doc_count,
        "rag_store_path": str(rag_db_path),
        "cwe_available": getattr(app.state, "cwe_available", False),
        "nvd_last_success": nvd_health["nvd_last_success"],
        "nvd_status": nvd_health["nvd_status"],
        "demo_mode": os.getenv("DEMO_MODE", "false").lower() == "true",
        "auth_required": not AUTH_DISABLED,
    }
