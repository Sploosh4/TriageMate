"""Query context belongs to the same transaction as all returned advisories."""

from standalone.evidence_pipeline.persistence.osv_query_snapshot import QuerySnapshot
from standalone.evidence_pipeline.parsing.public_inputs import _json


def stage_context(cursor, snapshot):
    if not isinstance(snapshot, QuerySnapshot):
        return
    snapshot.reconstruct()
    cursor.execute(
        "INSERT INTO evidence_pipeline.osv_query_batches(attempt_id,manifest) VALUES(%s,%s)",
        (snapshot.execution_id, snapshot.payload.decode()),
    )
    for index, response in enumerate(snapshot.responses):
        cursor.execute(
            "INSERT INTO evidence_pipeline.osv_query_pages(attempt_id,page_index,wire,record_hashes) SELECT %s,%s,input.wire,CASE WHEN %s THEN evidence_pipeline.osv_query_record_hashes(input.wire) ELSE ARRAY[]::text[] END FROM (VALUES(%s::bytea)) input(wire)",
            (snapshot.execution_id, index, snapshot.complete, response.wire),
        )


def link_advisories(cursor, snapshot):
    if not isinstance(snapshot, QuerySnapshot) or not snapshot.complete:
        return
    cursor.execute(
        "SELECT o.advisory_id,o.receipt_id::text FROM evidence.osv_advisory_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s",
        (snapshot.execution_id,),
    )
    receipts = dict(cursor.fetchall())
    for page_index, response in enumerate(snapshot.responses):
        raw = _json(response.payload.decode("utf-8-sig"))
        for record_index, record in enumerate(raw.get("vulns", [])):
            cursor.execute(
                "INSERT INTO evidence_pipeline.osv_query_advisory_links(attempt_id,page_index,record_index,receipt_id) VALUES(%s,%s,%s,%s)",
                (
                    snapshot.execution_id,
                    page_index,
                    record_index,
                    receipts[record["id"]],
                ),
            )
