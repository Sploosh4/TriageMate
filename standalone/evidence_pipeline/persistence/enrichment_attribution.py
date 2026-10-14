"""Read-only reconstruction of queue identity and its source/receipt boundaries."""

import hashlib

from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_routes import endpoint


def verify_enrichment(cursor):
    cursor.execute("SELECT to_regclass('evidence_pipeline.enrichment_requests')")
    if cursor.fetchone()[0] is None:
        return
    cursor.execute("""
        SELECT q.id::text,q.source_name,q.input_kind,q.origin,q.cve_id,
         EXISTS(SELECT 1 FROM evidence_pipeline.enrichment_causes c
          WHERE c.receipt_id=q.cause_receipt_id AND c.cve_id=q.cve_id AND c.origin=q.origin)
        FROM evidence_pipeline.enrichment_requests q
    """)
    for request, source, kind, origin, cve, caused in cursor.fetchall():
        if not caused or request != stable_id(
            "enrichment-request-v1", source, kind, origin, cve
        ):
            raise AssertionError("Enrichment request differs from its finding evidence")
    cursor.execute("""
        SELECT q.id::text,q.source_name,q.input_kind,q.origin,q.cve_id,
         run.execution_id::text,run.connection_id::text,c.source_name,c.input_kind,
         c.scope_reference,c.collector_reference,c.tenant_id,allowed.origin
        FROM evidence_pipeline.enrichment_runs run
        JOIN evidence_pipeline.enrichment_requests q ON q.id=run.request_id
        JOIN evidence.source_connections c ON c.id=run.connection_id
        LEFT JOIN evidence_pipeline.authorized_connections allowed ON allowed.connection_id=c.id
    """)
    for row in cursor.fetchall():
        request, source, kind, origin, cve, execution, connection, *registered = row
        url = endpoint(source, cve, input_kind=kind)
        provenance = (
            "Explicitly synthetic TriageMate enrichment fixture; no real vulnerability claims"
            if origin == "synthetic"
            else "Public source collection from " + url
        )
        marker = (
            "evidence-pipeline-v1:"
            + origin
            + ":"
            + hashlib.sha256(provenance.encode()).hexdigest()
        )
        if (
            execution != stable_id("enrichment-execution-v1", request)
            or connection != request
            or registered != [source, kind, url, marker, None, origin]
        ):
            raise AssertionError(
                "Enrichment execution differs from its registered request"
            )
