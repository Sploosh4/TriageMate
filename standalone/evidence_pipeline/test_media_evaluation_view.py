"""Persisted synthetic media joins retain source scope and pinned history."""

from backend.database import schema as database_schema

import json
import pytest
from datetime import datetime, timezone
from uuid import uuid4
from .test_store import db as db, snapshot as snapshot
from standalone.windows_inventory.test_store import configured as configured
from standalone.windows_inventory.test_contract import sample
from .test_resource_package_migration import save
from .test_media_inventory_match import facts, source
from .test_cve_program import document, scope
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.authority import authorize_connection


def test_public_scopes_and_native_receipts_remain_separate_across_refresh(
    db, configured
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    f = facts()
    record = sample()["records"][1]
    record.update(
        {
            k: v
            for k, v in f.items()
            if k not in ("source", "product", "platform", "operating_system")
        }
    )
    save(db, configured, [record, record | {"native_id": "synthetic-second-av1"}])
    public_scopes = []
    for _ in range(2):
        d = document()
        d["containers"]["cna"]["providerMetadata"]["shortName"] = "microsoft"
        d["containers"]["cna"]["affected"] = source()["affected"]
        now = datetime.now(timezone.utc)
        s = PublicSnapshot(
            scope(), str(uuid4()), now, now, "success", True, json.dumps(d).encode()
        )
        with db.cursor() as cur:
            authorize_connection(cur, s)
        persist_public(db, s)
        public_scopes.append(s.scope.connection_id)

    def read():
        with db.cursor() as cur:
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT receipt_id::text,device_attempt_id::text,public_connection_id::text,public_receipt_id::text,manifest FROM (SELECT receipt_id,device_attempt_id,public_connection_id,public_receipt_id,facts->'manifest' AS manifest FROM evidence_pipeline.current_native_media_evaluations WHERE connection_id=%s AND public_connection_id=ANY(%s::uuid[])) x",
                (configured[1].connection_id, public_scopes),
            )
            rows = cur.fetchall()
            cur.execute("RESET ROLE")
            return rows

    before = read()
    assert len(before) == 4 and len({r[0] for r in before}) == 2
    assert {r[1] for r in before} == {configured[0].execution_id}
    assert {r[2] for r in before} == set(public_scopes)
    assert len({r[3] for r in before}) == 2
    assert all(r[4] == f["manifest"] for r in before)
    save(db, configured, [record], later=True)
    after = read()
    assert len(after) == 2 and len({r[0] for r in after}) == 1
    assert not {r[0] for r in before} & {r[0] for r in after}
    assert {r[1] for r in after} == {configured[0].execution_id}
    assert {r[3] for r in after} == {r[3] for r in before}


@pytest.mark.parametrize("target", ["view", "function"])
def test_public_grant_drift_is_rejected(db, target):
    with db.cursor() as cur:
        database_schema.verify(cur)
        if target == "view":
            cur.execute(
                "GRANT SELECT ON evidence_pipeline.current_native_media_evaluations TO PUBLIC"
            )
        else:
            cur.execute(
                "GRANT EXECUTE ON FUNCTION evidence_pipeline.media_inventory_status(jsonb,text,jsonb) TO PUBLIC"
            )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
