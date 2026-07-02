import os
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from routers import queue, cases, ingest
import asyncio

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("triagemate")

app = FastAPI(title="TriageMate API", version="0.2.0")
app.state.cwe_available = False  # Will be updated on startup if CWE model loads

_API_KEY = os.getenv("TRIAGEMATE_API_KEY", "")


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    if _API_KEY:
        path = request.url.path
        if path.startswith("/api/") and not path.startswith("/api/health"):
            header_key = request.headers.get("X-API-Key", "")
            if header_key != _API_KEY:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or invalid X-API-Key header"},
                )
    response = await call_next(request)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/css", StaticFiles(directory="../frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="../frontend/js"), name="js")

app.include_router(queue.router)
app.include_router(cases.router)
app.include_router(ingest.router)


async def _background_recheck_loop():
    """Run low-severity re-checks once per day."""
    while True:
        await asyncio.sleep(86400)
        try:
            from scheduler import recheck_low_severity

            await recheck_low_severity()
        except Exception as e:
            logger.warning(f"Background re-check error: {e}")


@app.on_event("startup")
async def startup():
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
        if TABLE_NAME in db.table_names():
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

    asyncio.create_task(_background_recheck_loop())


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
        if TABLE_NAME in db.table_names():
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
    }
