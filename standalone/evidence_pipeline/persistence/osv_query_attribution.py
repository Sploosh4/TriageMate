"""Read-only reconstruction of query context, wire pages and advisory links.

The existing OSV receipt verifier separately checks each advisory projection.
This pass checks why those receipts belong to a particular package query.
"""

from datetime import datetime
import hashlib

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.osv_query import URL, query_bytes
from standalone.evidence_pipeline.persistence.osv_query_snapshot import QuerySnapshot
from standalone.evidence_pipeline.parsing.osv_records import normalize_osv
from standalone.evidence_pipeline.parsing.public_inputs import _json
from standalone.evidence_pipeline.contracts import PublicDownload


def verify_osv_queries(cursor):
    from standalone.evidence_pipeline.persistence.attribution import require

    cursor.execute("SELECT to_regclass('evidence_pipeline.osv_query_batches')")
    if cursor.fetchone()[0] is None:
        return
    cursor.execute("""
        SELECT b.connection_id::text,b.query_document,c.source_name,c.input_kind,
         c.scope_reference,c.tenant_id,auth.origin
        FROM evidence_pipeline.osv_query_bindings b
        JOIN evidence.source_connections c ON c.id=b.connection_id
        LEFT JOIN evidence_pipeline.authorized_connections auth ON auth.connection_id=c.id
    """)
    bindings = {}
    for connection, query, *source in cursor.fetchall():
        require(
            source[:4] == ["OSV", "advisories", URL, None]
            and source[4] in {"synthetic", "public"},
            "Invalid OSV query binding",
        )
        bindings[connection] = query_bytes(_json(query))
    cursor.execute(
        """
        SELECT a.id::text FROM evidence.collection_attempts a
        JOIN evidence.source_connections c ON c.id=a.connection_id
        WHERE c.source_name='OSV' AND c.input_kind='advisories' AND c.scope_reference=%s
    """,
        (URL,),
    )
    attempts = {row[0] for row in cursor.fetchall()}
    cursor.execute("""
        SELECT b.attempt_id::text,b.manifest,a.connection_id::text,a.started_at,a.finished_at,
         a.outcome,a.complete,a.error_code,a.input_fingerprint,c.collector_reference,auth.origin
        FROM evidence_pipeline.osv_query_batches b
        JOIN evidence.collection_attempts a ON a.id=b.attempt_id
        JOIN evidence.source_connections c ON c.id=a.connection_id
        LEFT JOIN evidence_pipeline.authorized_connections auth ON auth.connection_id=c.id
    """)
    batches = cursor.fetchall()
    require(
        {row[0] for row in batches} == attempts, "OSV query manifest inventory differs"
    )
    all_pages, all_links = set(), set()
    for (
        execution,
        manifest,
        connection,
        started,
        finished,
        outcome,
        complete,
        error,
        fingerprint,
        marker,
        origin,
    ) in batches:
        from json import loads

        documents = loads(manifest)
        require(
            isinstance(documents, list) and len(documents) == 1,
            "Invalid query manifest",
        )
        metadata = documents[0]
        scope = SourceScope(**metadata["scope"])
        require(
            scope.connection_id == connection
            and scope.origin == origin
            and bindings.get(connection) == query_bytes(metadata["query"]),
            "Query binding differs from retained request",
        )
        require(
            marker
            == "evidence-pipeline-v1:"
            + scope.origin
            + ":"
            + hashlib.sha256(scope.provenance.encode()).hexdigest(),
            "Query source provenance differs",
        )
        cursor.execute(
            "SELECT page_index,wire,record_hashes,CASE WHEN %s THEN evidence_pipeline.osv_query_record_hashes(wire) ELSE ARRAY[]::text[] END FROM evidence_pipeline.osv_query_pages WHERE attempt_id=%s ORDER BY page_index",
            (complete, execution),
        )
        stored_pages = cursor.fetchall()
        require(
            [row[0] for row in stored_pages] == list(range(len(metadata["pages"]))),
            "Query source page inventory differs",
        )
        responses = []
        for index, wire, hashes, expected_hashes in stored_pages:
            require(
                hashes == expected_hashes, "Query record hashes differ from source page"
            )
            page = metadata["pages"][index]
            responses.append(
                PublicDownload(
                    URL,
                    datetime.fromisoformat(page["started_at"]),
                    datetime.fromisoformat(page["finished_at"]),
                    bytes(wire),
                    bytes(wire),
                )
            )
            all_pages.add((execution, index))
        snapshot = QuerySnapshot(
            scope,
            execution,
            started,
            finished,
            outcome,
            complete,
            manifest.encode(),
            error,
            tuple(responses),
        )
        require(
            snapshot.input_fingerprint == fingerprint,
            "Query attempt fingerprint differs",
        )
        expected, ids = {}, {}
        if complete:
            for record in normalize_osv(snapshot.feed()):
                revision = stable_id(
                    "public-revision",
                    connection,
                    record.source_record_id,
                    record.content_hash,
                )
                receipt = stable_id("public-receipt", revision, execution)
                expected[receipt] = (revision, record.source_record_id, record.claim)
                ids[record.source_record_id] = receipt
        cursor.execute(
            """
            SELECT r.id::text,rev.id::text,rev.source_record_id,p.claim
            FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id
            LEFT JOIN evidence_pipeline.public_claims p ON p.source_revision_id=rev.id
            WHERE r.collection_attempt_id=%s
        """,
            (execution,),
        )
        actual = {
            receipt: (revision, native, claim)
            for receipt, revision, native, claim in cursor.fetchall()
        }
        require(actual == expected, "Query advisory receipts differ from source pages")
        links = set()
        if complete:
            for page_index, response in enumerate(responses):
                raw = _json(response.payload.decode("utf-8-sig"))
                for record_index, record in enumerate(raw.get("vulns", [])):
                    links.add((page_index, record_index, ids[record["id"]]))
        cursor.execute(
            "SELECT page_index,record_index,receipt_id::text FROM evidence_pipeline.osv_query_advisory_links WHERE attempt_id=%s",
            (execution,),
        )
        require(
            set(cursor.fetchall()) == links,
            "Query advisory positions differ from source pages",
        )
        all_links.update((execution, *link) for link in links)
    cursor.execute(
        "SELECT attempt_id::text,page_index FROM evidence_pipeline.osv_query_pages"
    )
    require(set(cursor.fetchall()) == all_pages, "Unexplained query pages")
    cursor.execute(
        "SELECT attempt_id::text,page_index,record_index,receipt_id::text FROM evidence_pipeline.osv_query_advisory_links"
    )
    require(set(cursor.fetchall()) == all_links, "Unexplained query advisory links")
