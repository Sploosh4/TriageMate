"""Retained update fields must match their source revision, not just row counts."""

from copy import deepcopy
from psycopg2 import sql
import pytest

from .test_store import db, snapshot  # noqa: F401
from .test_antivirus_store import antivirus_bound  # noqa: F401
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.antivirus_attribution import (
    verify_antivirus,
)


def test_antivirus_attribution_detects_changed_fields(db, antivirus_bound):  # noqa: F811
    device, child = antivirus_bound
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")

        def fetch(table, condition, value):
            cur.execute(
                sql.SQL("SELECT to_jsonb(t) FROM evidence.{} t WHERE ").format(
                    sql.Identifier(table)
                )
                + sql.SQL(condition),
                (value,),
            )
            return [row[0] for row in cur.fetchall()]

        sources = {
            row["id"]: row
            for row in fetch("source_connections", "id=%s", child.scope.connection_id)
        }
        revisions = {
            row["id"]: row
            for row in fetch(
                "source_revisions", "connection_id=%s", child.scope.connection_id
            )
        }
        receipts = {
            row["id"]: row
            for row in fetch(
                "observation_receipts", "collection_attempt_id=%s", child.execution_id
            )
        }
        attempts = {
            row["id"]: row
            for row in fetch("collection_attempts", "id=%s", child.execution_id)
        }
        providers = {
            row["id"]: row
            for row in fetch(
                "provider_devices", "connection_id=%s", device.scope.connection_id
            )
        }
        received = next(iter(receipts))
        extras = {
            table: fetch(table, "receipt_id=%s", received)
            for table in ("antivirus_observations",)
        }

    def verify(values):
        explained = {table: set() for table in extras}

        def verify_receipt(receipt_id, source_id, content_hash, kind):
            revision = revisions[receipts[receipt_id]["source_revision_id"]]
            assert kind == "exposure"
            assert source_id == revision["source_record_id"]
            assert content_hash == revision["content_hash"]

        verify_antivirus(
            values,
            sources,
            revisions,
            receipts,
            attempts,
            providers,
            explained,
            verify_receipt,
        )
        return explained

    explained = verify(extras)
    assert sum(map(len, explained.values())) == 1
    for field, value in {
        "mode": "tampered",
        "signature_status": "True",
        "signature_current": False,
        "source_rbac_group_id": "042",
        "source_record_id": "different",
        "quick_scan_error": "changed",
    }.items():
        changed = deepcopy(extras)
        changed["antivirus_observations"][0][field] = value
        with pytest.raises(AssertionError):
            verify(changed)
