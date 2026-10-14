"""Actual restricted writer and application reader for an owned synthetic notice."""

import json
from uuid import uuid4

from .commands import register, ingest_public
from .test_retained_public_fixture import prepare
from .runtime import local_database
from .test_commands import cleanup
from .test_redhat_advisories import scope, document


def test_redhat_runtime_collection_reader_and_replay(tmp_path):
    chosen = scope()
    raw = document()
    raw["vulnerabilities"] = []
    value = prepare(
        chosen,
        str(uuid4()),
        tmp_path / "bundle",
        vendor_path="2099/rhsa-2099_1234.json",
        synthetic_payload=json.dumps(raw).encode(),
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(chosen)
        assert not register(chosen)
        assert not ingest_public(value)["replayed"]
        replay = prepare(
            chosen,
            value.execution_id,
            tmp_path / "bundle",
            vendor_path="2099/rhsa-2099_1234.json",
            replay_only=True,
        )
        assert ingest_public(replay)["replayed"]
        result = PostgreSQLQueries().execute(
            {
                "requestId": str(uuid4()),
                "sql": "SELECT native_id,cve_ids FROM evidence_pipeline.current_vendor_advisories WHERE connection_id='"
                + chosen.connection_id
                + "'::uuid",
            }
        )
        assert json.loads(result)["rows"] == [
            ["RHSA-2099:1234", {"type": "_text", "value": "{}"}]
        ]
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)",
                (chosen.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                (chosen.connection_id,),
            )
        cleanup(chosen)
