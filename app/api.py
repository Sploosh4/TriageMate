"""FastAPI routes and compiled React assets; no Markdown page engine."""

from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
import secrets
import time
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.services.postgres_query import PostgreSQLQueries, QueryError
from app.services.classification_api import ClassificationAPI
from app.services.operations_api import OperationsAPI
from app.services.evidence_revision import EvidenceRevision
from app.notifications import exact_json_values, load_collection_notifications

ROOT = Path(__file__).resolve().parents[1]


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requestId: UUID
    sql: str = Field(default="", max_length=60000)


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requestId: UUID


def create_app(
    query_factory=PostgreSQLQueries, operations_factory=OperationsAPI
) -> FastAPI:
    token = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(application):
        state = Path(
            os.environ.get("TRIAGEMATE_STATE_DIR", "/var/lib/triagemate/state")
        )
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        application.state.queries = query_factory()
        configured = os.environ.get("TRIAGEMATE_OPERATIONS_CONFIG")
        application.state.operations = operations_factory(
            state, Path(configured) if configured else None, "self-hosted"
        )
        application.state.classifications = ClassificationAPI()
        application.state.revision = EvidenceRevision(application.state.queries)
        try:
            yield
        finally:
            from starlette.concurrency import run_in_threadpool

            operations_done = await run_in_threadpool(
                application.state.operations.close
            )
            queries_done = await run_in_threadpool(application.state.queries.close, 5)
            if not operations_done or not queries_done:
                raise RuntimeError(
                    "Application drain incomplete; inspect persisted collection state"
                )

    application = FastAPI(title="TriageMate", version="0.2.0", lifespan=lifespan)
    allowed_hosts = os.environ.get(
        "TRIAGEMATE_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver"
    ).split(",")
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @application.middleware("http")
    async def boundaries(request: Request, call_next):
        request.state.started = time.monotonic()
        if request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            expected_origin = f"{request.url.scheme}://{request.headers.get('host')}"
            if request.headers.get("sec-fetch-site") == "cross-site" or (
                origin and origin != expected_origin
            ):
                return JSONResponse(
                    {"error": "Use the configured TriageMate address."}, status_code=403
                )
            if request.method == "POST":
                if request.headers.get("x-lab-token") != token:
                    return JSONResponse(
                        {"error": "Session expired. Reload the page."}, status_code=403
                    )
                count = 0
                chunks = []
                async for chunk in request.stream():
                    count += len(chunk)
                    if count > 65536:
                        return JSONResponse(
                            {"error": "Request exceeds 64 KiB."}, status_code=413
                        )
                    chunks.append(chunk)
                # Starlette's cached request replays this bounded body to FastAPI.
                request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.exception_handler(QueryError)
    async def query_error(_request, error):
        return JSONResponse(
            {"error": str(error), "code": error.code}, status_code=error.status
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error(_request, _error):
        return JSONResponse({"error": "Invalid request fields."}, status_code=422)

    @application.exception_handler(Exception)
    async def unavailable(_request, error):
        logging.exception("Application request failed", exc_info=error)
        return JSONResponse(
            {"error": "Application unavailable. Check the container log and retry."},
            status_code=503,
        )

    @application.get("/api/health")
    def health(request: Request):
        request.app.state.queries.execute(
            {"sql": "SELECT 1", "requestId": str(uuid4())}
        )
        return {"status": "ok"}

    @application.get("/api/session")
    def session():
        return {"token": token, "engine": "PostgreSQL", "databaseBytes": None}

    @application.post("/api/query")
    def query(body: QueryRequest, request: Request):
        return Response(
            request.app.state.queries.execute(
                {"sql": body.sql, "requestId": str(body.requestId)},
                started=request.state.started,
            ),
            media_type="application/json",
        )

    @application.post("/api/catalogue")
    def catalogue(body: QueryRequest, request: Request):
        return Response(
            request.app.state.queries.catalogue(
                {"sql": body.sql, "requestId": str(body.requestId)},
                started=request.state.started,
            ),
            media_type="application/json",
        )

    @application.post("/api/query/cancel")
    def cancel(body: CancelRequest, request: Request):
        return request.app.state.queries.cancel({"requestId": str(body.requestId)})

    @application.get("/api/evidence/revision")
    def revision(request: Request):
        return request.app.state.revision.read()

    @application.get("/api/classifications")
    def classifications(request: Request):
        return Response(
            request.app.state.classifications.read(request.app.state.queries),
            media_type="application/json",
        )

    @application.post("/api/classifications")
    def classify(body: dict, request: Request):
        return request.app.state.classifications.save(body)

    @application.get("/api/operations")
    def operations(request: Request):
        return request.app.state.operations.read()

    @application.post("/api/operations")
    def mode(body: dict, request: Request):
        return request.app.state.operations.save(body)

    @application.get("/api/notifications")
    def notifications(request: Request):
        notices = load_collection_notifications(request.app.state.queries)
        for record in request.app.state.operations.notifications():
            notices.append(
                {
                    "id": record["id"],
                    "source": record["parameters"]["api"],
                    "input": record["category"],
                    "scope": record["parameters"]["organisation"],
                    "status": record["status"],
                    "urgency": record["urgency"],
                    "message": record["message"],
                    "startedAt": None,
                    "resolvedAt": None,
                    "failureCount": None,
                    "failures": [],
                    "details": record.get("details", {}),
                }
            )
        return {"notifications": exact_json_values(notices)}

    directory = ROOT / "ui-engine/dist"
    if directory.is_dir():
        application.mount(
            "/assets", StaticFiles(directory=directory / "assets"), name="assets"
        )

        @application.get("/")
        def index():
            return FileResponse(directory / "index.html")

        @application.get("/third-party-notices.txt")
        def third_party_notices():
            return FileResponse(
                directory / "third-party-notices.txt", media_type="text/plain"
            )

    return application


app = create_app()
