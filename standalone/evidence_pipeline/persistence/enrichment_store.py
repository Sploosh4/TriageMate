"""Bounded source-specific missing-CVE discovery; caller owns transaction commit.

This uses the explicit enrichment queue schema. It does not install it, perform
network access, register public connections or retry failed requests.
"""

from psycopg2 import sql
from psycopg2.extras import execute_values

from standalone.evidence_pipeline.contracts import identifier, SourceScope
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.store import atomic, ReplayConflict
from standalone.evidence_pipeline.parsing.public_routes import endpoint

SOURCES = {
    "NVD": "vulnerabilities",
    "MSRC": "advisories",
    "CVE": "records",
    "CISA": "vulnrichment",
}


def request_scope(cursor, request_id):
    """Exact fixed-route scope for owner registration before a worker claims work."""
    request_id = identifier(request_id)
    cursor.execute(
        "SELECT source_name,input_kind,cve_id,origin FROM evidence_pipeline.enrichment_requests WHERE id=%s",
        (request_id,),
    )
    request = cursor.fetchone()
    if request is None:
        raise ValueError("Unknown enrichment request")
    source, kind, cve, origin = request
    url = endpoint(source, cve, input_kind=kind)
    provenance = (
        "Explicitly synthetic TriageMate enrichment fixture; no real vulnerability claims"
        if origin == "synthetic"
        else "Public source collection from " + url
    )
    return SourceScope(request_id, source, kind, url, origin, provenance), cve


def start_request(connection, request_id):
    """Claim once; caller commits before network work. Existing claims never retry."""
    if connection.autocommit:
        raise ValueError("Starting enrichment requires an explicit transaction")
    request_id = identifier(request_id)
    execution_id = stable_id("enrichment-execution-v1", request_id)
    with connection.cursor() as cur, atomic(cur):
        # Verify the registered URL and immutable provenance as well as the
        # database-enforced source/origin binding. No worker self-registration.
        from standalone.evidence_pipeline.persistence.store import source_connection
        from standalone.evidence_pipeline.contracts import Snapshot
        from datetime import datetime, timezone

        scope, _ = request_scope(cur, request_id)
        now = datetime.now(timezone.utc)
        cur.execute(
            "SELECT 1 FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
            (request_id,),
        )
        if cur.fetchone() is None:
            raise ValueError("Enrichment requires explicit source registration")
        source_connection(
            cur, Snapshot(scope, execution_id, now, now, "success", True, b"[]")
        )
        cur.execute(
            "INSERT INTO evidence_pipeline.enrichment_runs(request_id,execution_id,connection_id) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING execution_id::text",
            (request_id, execution_id, request_id),
        )
        result = cur.fetchone()
        cur.execute(
            "SELECT execution_id::text,connection_id::text FROM evidence_pipeline.enrichment_runs WHERE request_id=%s",
            (request_id,),
        )
        if cur.fetchone() != (execution_id, request_id):
            raise ReplayConflict("Enrichment execution identity collision")
        return result[0] if result else None


def discover(connection, finding_attempt_id, *, sources, limit=100):
    """Queue missing source records once, across devices and finding collections.

    A source record already present in a latest complete collection satisfies the
    request, including a rejected record. This is record availability, not a claim
    that every desired field is populated. A second pass continues remaining work
    when the bound is reached. Sources must be explicitly selected by the caller.
    """
    return _discover(connection, identifier(finding_attempt_id), sources, limit, None)


def discover_remaining(connection, *, origin, sources, limit=100):
    """Continue missing requests from successful stored evidence, without a new import."""
    if origin not in ("public", "synthetic"):
        raise ValueError("Choose an explicit public or synthetic discovery origin")
    return _discover(connection, None, sources, limit, origin)


def _discover(connection, finding_attempt_id, sources, limit, origin):
    if connection.autocommit or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Discovery requires a transaction and a limit from 1 to 1000")
    if (
        not isinstance(sources, (tuple, list))
        or not sources
        or any(not isinstance(s, str) or s not in SOURCES for s in sources)
        or len(set(sources)) != len(sources)
    ):
        raise ValueError("Select unique supported public enrichment sources")
    with connection.cursor() as cur, atomic(cur):
        if finding_attempt_id is not None:
            cur.execute(
                "SELECT a.complete,a.outcome,c.source_name,c.input_kind "
                "FROM evidence.collection_attempts a JOIN evidence.source_connections c "
                "ON c.id=a.connection_id JOIN evidence_pipeline.authorized_connections auth "
                "ON auth.connection_id=c.id WHERE a.id=%s",
                (finding_attempt_id,),
            )
            attempt = cur.fetchone()
            if (
                attempt is None
                or attempt[2] != "Defender"
                or attempt[3]
                not in ("findings", "vulnerability_baseline", "vulnerability_events")
            ):
                raise ValueError("Discovery requires a registered finding collection")
            if attempt[:2] != (True, "success"):
                return []
        values = sql.SQL(",").join(sql.SQL("(%s,%s)") for _ in sources)
        query = sql.SQL("""
            WITH targets(source_name,input_kind) AS (VALUES {}),
            current_sources AS MATERIALIZED (
              SELECT current.* FROM evidence_pipeline.collection_status current
              JOIN targets t ON t.source_name=current.source_name
               AND t.input_kind=current.input_kind
            ), candidates AS (
              SELECT DISTINCT ON (t.source_name,t.input_kind,c.origin,c.cve_id)
               t.source_name,t.input_kind,c.origin,c.cve_id,c.receipt_id
              FROM evidence_pipeline.enrichment_causes c CROSS JOIN targets t
              WHERE (%s::uuid IS NULL OR c.collection_attempt_id=%s::uuid)
              AND (%s::text IS NULL OR c.origin=%s)
              AND NOT EXISTS(SELECT 1 FROM evidence_pipeline.enrichment_requests q
               WHERE (q.source_name,q.input_kind,q.origin,q.cve_id)=
                (t.source_name,t.input_kind,c.origin,c.cve_id))
              AND NOT EXISTS(
               SELECT 1 FROM current_sources current
               JOIN evidence.observation_receipts r ON r.collection_attempt_id=current.selected_attempt_id
               JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id
               JOIN evidence_pipeline.public_claims claim ON claim.source_revision_id=rev.id
               WHERE current.source_name=t.source_name AND current.input_kind=t.input_kind
                AND rev.connection_id=current.connection_id
                AND rev.origin=c.origin AND rev.source_record_id=c.cve_id)
              ORDER BY t.source_name,t.input_kind,c.origin,c.cve_id,c.receipt_id
            ) SELECT * FROM candidates ORDER BY cve_id,source_name LIMIT %s
        """).format(values)
        params = [item for source in sources for item in (source, SOURCES[source])]
        cur.execute(
            query,
            [*params, finding_attempt_id, finding_attempt_id, origin, origin, limit],
        )
        candidates = cur.fetchall()
        if not candidates:
            return []
        rows = [
            (
                stable_id("enrichment-request-v1", source, kind, origin, cve),
                source,
                kind,
                cve,
                origin,
                receipt,
            )
            for source, kind, origin, cve, receipt in candidates
        ]
        inserted = [
            row[0]
            for row in execute_values(
                cur,
                "INSERT INTO evidence_pipeline.enrichment_requests "
                "(id,source_name,input_kind,cve_id,origin,cause_receipt_id) VALUES %s "
                "ON CONFLICT DO NOTHING RETURNING id::text",
                rows,
                page_size=100,
                fetch=True,
            )
        ]
        # Both the deterministic primary key and logical identity are unique.
        # A concurrent winner can conflict on either index; confirm its identity
        # after waiting rather than silently accepting an unrelated collision.
        cur.execute(
            "SELECT id::text,source_name,input_kind,cve_id,origin FROM evidence_pipeline.enrichment_requests WHERE id=ANY(%s::uuid[])",
            ([row[0] for row in rows],),
        )
        actual = {row[0]: tuple(row[1:]) for row in cur.fetchall()}
        if actual != {row[0]: tuple(row[1:5]) for row in rows}:
            raise ReplayConflict("Enrichment request identity collision")
        return inserted
