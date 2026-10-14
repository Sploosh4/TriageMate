# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS frontend
WORKDIR /build/ui-engine
COPY ui-engine/package*.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY ui-engine/ ./
COPY docs/ui/engine/FrontendThirdPartyNotices.txt /build/docs/ui/engine/FrontendThirdPartyNotices.txt
RUN npm run lint && npm run format:check && npm run build && npm run test:notices

FROM python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS python-build
COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /usr/local/bin/uv
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml uv.lock ./
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
RUN uv sync --frozen --no-default-groups --no-install-project
COPY ui-engine/scripts/build_parser.py /build/build_parser.py
RUN /opt/venv/bin/python /build/build_parser.py --allow-downloads --destination /opt/parser

FROM python-build AS checks
RUN uv sync --frozen --no-default-groups --group ci --no-install-project
COPY app/ app/
COPY backend/ backend/
COPY standalone/ standalone/
COPY docs/ docs/
COPY ui-engine/postgres/ ui-engine/postgres/
ENV PYTHONPATH=/build TRIAGEMATE_PG_PARSER_LIBRARY=/opt/parser/libpg_query.so
CMD ["/opt/venv/bin/python", "-m", "pytest", "app/tests/test_api.py", "app/tests/test_notifications.py", "app/tests/services/test_pg_parser.py", "app/tests/services/test_query_cleanup.py", "app/tests/services/test_classification_api.py", "app/tests/services/test_operations_api.py", "backend/tests/test_service_startup.py", "backend/tests/test_container_target.py", "backend/tests/test_database_connections.py", "backend/tests/test_microsoft_source_registry.py", "-q"]

FROM python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258 AS application
LABEL org.opencontainers.image.title="TriageMate" org.opencontainers.image.licenses="GPL-3.0-only" org.opencontainers.image.source="https://github.com/Sploosh4/TriageMate"
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TRIAGEMATE_DEPLOYMENT=container TRIAGEMATE_DATABASE_TARGET=/var/lib/triagemate/database.json \
    TRIAGEMATE_PG_PARSER_LIBRARY=/opt/parser/libpg_query.so TRIAGEMATE_STATE_DIR=/var/lib/triagemate/state
RUN useradd --uid 1000 --create-home triagemate && install -d -m 0700 -o triagemate -g triagemate /var/lib/triagemate
COPY --from=python-build /opt/venv /opt/venv
COPY --from=python-build /opt/parser /opt/parser
WORKDIR /opt/triagemate
COPY app/ app/
COPY backend/ backend/
COPY standalone/ standalone/
COPY docs/ui/engine/ParserThirdPartyNotices.md /opt/parser/THIRD_PARTY_NOTICES.md
COPY --from=frontend /build/ui-engine/dist/ ui-engine/dist/
COPY LICENSE NOTICE ./
COPY LICENSES/ LICENSES/
USER triagemate
EXPOSE 8000
CMD ["sh", "-c", "python -m app.bootstrap && exec uvicorn app.api:app --host 0.0.0.0 --port 8000 --workers 1 --timeout-graceful-shutdown 360"]
