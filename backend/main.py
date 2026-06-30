from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from routers import queue, cases, ingest
import asyncio

app = FastAPI(title="TriageMate API", version="0.1.0")

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
            print(f"Background re-check error: {e}")


@app.on_event("startup")
async def startup():
    init_db()
    try:
        from ml.vector_store import init_vector_store, seed_demo_documents
        db = init_vector_store()
        import lancedb
        db2 = lancedb.connect("/tmp/triagemate_lancedb")
        if "asset_documentation" in db2.table_names():
            tbl = db2.open_table("asset_documentation")
            if tbl.count_rows() == 0:
                seed_demo_documents(db)
        else:
            seed_demo_documents(db)
    except Exception as e:
        print(f"Vector store init skipped: {e}")

    asyncio.create_task(_background_recheck_loop())


@app.get("/")
async def root():
    from fastapi.responses import FileResponse
    return FileResponse("../frontend/index.html")
