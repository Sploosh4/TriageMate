"""Every validated native MSRC identity remains visible without becoming a CVE."""

from backend.database import schema as database_schema

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection


from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_store import snapshot
from .test_store import db as db


@pytest.mark.parametrize(
    "native_id",
    [
        "ADV160001",
        "CVE-2099-5001-M",
        "CVE-2099-5001 - M",
        "CVE-2099-5001 mariner - do not use this one",
    ],
)
def test_all_native_forms_keep_completeness_and_no_canonical_join(db, native_id):
    item = snapshot()
    raw = json.loads(item.payload)
    raw["Vulnerability"][0]["CVE"] = "CVE-2099-5001"
    native = deepcopy(raw["Vulnerability"][0])
    native["CVE"] = native_id
    raw["Vulnerability"].append(native)
    item = replace(item, payload=json.dumps(raw).encode())
    with db.cursor() as q:
        database_schema.verify(q)
        authorize_connection(q, item)
        q.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, item)
    with db.cursor() as q:
        q.execute("SET CONSTRAINTS ALL IMMEDIATE")
        q.execute("RESET ROLE")
        q.execute("SET LOCAL ROLE tm_mock_reader")
        q.execute(
            "SELECT cve_id FROM evidence_pipeline.current_msrc_update_claims WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        assert q.fetchall() == [("CVE-2099-5001",)]
        q.execute(
            "SELECT native_id FROM evidence_pipeline.current_msrc_advisory_claims WHERE connection_id=%s",
            (item.scope.connection_id,),
        )
        assert q.fetchall() == [(native_id,)]
        q.execute(
            "SELECT domain,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) ORDER BY domain",
            ([item.scope.connection_id],),
        )
        assert q.fetchall() == [
            ("msrc-update", 5),
            ("public-patch", 20),
            ("vendor-advisory", 5),
            ("whole-product", 30),
        ]
        q.execute(
            """SELECT count(*) FROM evidence.patch_vulnerabilities p
            JOIN evidence.observation_receipts r ON r.id=p.receipt_id
            JOIN evidence.source_revisions s ON s.id=r.source_revision_id
            WHERE r.collection_attempt_id=%s AND s.source_record_id=%s""",
            (item.execution_id, native_id),
        )
        assert q.fetchone() == (0,)


def test_repair_is_explicit_idempotent_and_prior_entrypoint_verifies(db):

    with db.cursor() as q:
        database_schema.verify(q)
        q.execute(
            "GRANT SELECT ON evidence_pipeline.current_msrc_advisory_claims TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(q)
