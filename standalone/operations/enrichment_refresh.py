"""Select previously resolved CVEs for refresh without reclaiming failed requests.

Selection is read-only. The caller must journal a fixed per-run declaration before
collection; this module does not activate schedules or authorise network access.
"""

from standalone.evidence_pipeline.persistence.enrichment_store import SOURCES
from standalone.evidence_pipeline.parsing.public_inputs import _cve


def candidates(cursor, *, source, origin, limit=100, synthetic_cves=None, history=None):
    if (
        not isinstance(source, str)
        or source not in SOURCES
        or origin not in ("synthetic", "public")
        or type(limit) is not int
        or not 1 <= limit <= 100
    ):
        raise ValueError("Invalid enrichment refresh selection")
    if origin == "synthetic":
        if not isinstance(synthetic_cves, (list, tuple)) or len(synthetic_cves) > 100:
            raise ValueError("Synthetic refresh requires explicit bounded CVEs")
        selected = [_cve(value) for value in synthetic_cves]
        if len(set(selected)) != len(selected):
            raise ValueError("Duplicate synthetic refresh CVE")
    else:
        if synthetic_cves is not None:
            raise ValueError("Public refresh cannot select synthetic fixtures")
        selected = []
    if history is None:
        history_key, history_input = None, None
    else:
        from .store import service_key
        from standalone.evidence_pipeline.contracts import identifier

        if not isinstance(history, tuple) or len(history) != 2:
            raise ValueError("Refresh history requires an exact service/input binding")
        history_key, history_input = service_key(history[0]), identifier(history[1])
    query = """
        WITH causes AS (
          SELECT DISTINCT cve_id FROM evidence_pipeline.enrichment_causes
          WHERE origin=%s AND (%s OR cve_id=ANY(%s::text[]))
        ), rotation AS (
          SELECT DISTINCT ON (member.cve_id) member.cve_id,e.recorded_at AS declared_at
          FROM evidence_pipeline.operation_events e
          CROSS JOIN LATERAL jsonb_array_elements_text(e.event->'cve_ids') member(cve_id)
          WHERE e.service_key=%s AND e.event->>'input_id'=%s
            AND e.event->>'kind'='enrichment_refresh_batch'
            AND e.event->>'source'=%s AND e.event->>'origin'=%s
          ORDER BY member.cve_id,e.recorded_at DESC
        ), known AS (
          SELECT DISTINCT ON (rev.source_record_id) rev.source_record_id AS cve_id,a.finished_at AS observed_at
          FROM evidence_pipeline.collection_status current
          JOIN evidence.collection_attempts a ON a.id=current.selected_attempt_id
          JOIN evidence.observation_receipts r ON r.collection_attempt_id=a.id
          JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id
          JOIN evidence_pipeline.public_claims claim ON claim.source_revision_id=rev.id
          JOIN causes ON causes.cve_id=rev.source_record_id
          WHERE current.source_name=%s AND current.input_kind=%s AND rev.origin=%s
          ORDER BY rev.source_record_id,a.finished_at DESC
        )
        SELECT causes.cve_id,q.id::text,
               greatest(known.observed_at,q.finished_at,rotation.declared_at) AS priority_at
        FROM causes
        LEFT JOIN evidence_pipeline.enrichment_request_status q
          ON q.cve_id=causes.cve_id AND q.source_name=%s
          AND q.input_kind=%s AND q.origin=%s
        LEFT JOIN known ON known.cve_id=causes.cve_id
        LEFT JOIN rotation ON rotation.cve_id=causes.cve_id
        WHERE (q.state IN ('succeeded','not_found') OR
               (q.id IS NULL AND known.cve_id IS NOT NULL))
        ORDER BY priority_at NULLS FIRST,causes.cve_id LIMIT %s
    """
    parameters = [origin, origin == "public", selected]
    if history is None:
        start = query.index("        ), rotation AS (")
        end = query.index("        ), known AS (", start)
        query = (
            query[:start]
            + """        ), rotation AS (
          SELECT NULL::text AS cve_id,NULL::timestamptz AS declared_at WHERE false
"""
            + query[end:]
        )
    else:
        parameters += [history_key, history_input, source, origin]
    parameters += [
        source,
        SOURCES[source],
        origin,
        source,
        SOURCES[source],
        origin,
        limit,
    ]
    if source == "MSRC":
        # MSRC's retained source shape makes the correlated causes join select a
        # repeated-scan plan. Compute its current records once; the final causes
        # join still restricts eligibility. Other providers benefit from their
        # earlier cause filter, so retain their measured query shape.
        query = query.replace("), known AS (", "), known AS MATERIALIZED (").replace(
            "          JOIN causes ON causes.cve_id=rev.source_record_id\n", ""
        )
    cursor.execute(query, parameters)
    return [
        dict(cve_id=cve, request_id=request, priority_at=observed)
        for cve, request, observed in cursor.fetchall()
    ]
