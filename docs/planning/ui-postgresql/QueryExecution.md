# Read-only PostgreSQL query contract

The React SQL explorer submits `{sql, requestId}` to `POST /api/query`; `requestId` is a canonical UUID. `POST /api/query/cancel` uses the same identifier. FastAPI validates requests and session/origin boundaries. `app/services/postgres_query.py` owns execution/cancellation and connects through the configured database target as `tm_mock_reader`, never as owner or fixture writer. There is no SQLite runtime fallback.

The SQL parser permits approved read-only statements and relations/functions. PostgreSQL independently enforces restricted grants and read-only transactions; supported result-generating expressions do not grant writes. Classification corrections use a separate constrained API, retain source observations and record correction provenance. Remote identity authentication remains a future design decision.

The executor applies its configured request, concurrent-query, timeout and result limits. Cancellation must terminate only the owned query and preserve usable state. Failed connection, invalid SQL, unsupported authority, timeouts and oversized results return actionable errors without credentials. Exact PostgreSQL numeric values, large integers, nulls and arrays retain explicit transport semantics rather than silently losing precision.

Retain direct tests for allowed reads, rejected writes, parser edge cases, function/role authority, cancellation races, timeout/cleanup and subsequent successful queries. Schema/authority fingerprints remain intact pending the [database standards discussion](../../architecture/REFACTOR_STANDARDS.md). Run mutation/authority checks only against isolated synthetic targets.
