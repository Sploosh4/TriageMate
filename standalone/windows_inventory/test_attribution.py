"""Retained inventory must explain receipts without relaxing device authority."""

from dataclasses import replace
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.attribution import rows, require
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.windows_inventory_attribution import (
    verify_windows_inventory,
)
from .test_store import db, snapshot, configured, inventory  # noqa: F401
from .store import persist


def check(cur):
    sources = {r["id"]: r for r in rows(cur, "evidence.source_connections")}
    attempts = {r["id"]: r for r in rows(cur, "evidence.collection_attempts")}
    cur.execute(
        "SELECT to_jsonb(r),to_jsonb(v) FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id JOIN evidence.source_connections c ON c.id=v.connection_id WHERE c.input_kind IN ('devices','software_inventory')"
    )
    receipts, revisions = {}, {}
    for received, revision in cur.fetchall():
        receipts[received["id"]] = received
        revisions[revision["id"]] = revision
    # Only registered pipeline sources belong to attribution.
    authorized = {
        r["connection_id"]
        for r in rows(cur, "evidence_pipeline.authorized_connections")
    }
    sources = {k: v for k, v in sources.items() if k in authorized}
    used = set()

    def receipt(key, native, content, kind):
        r = receipts[key]
        v = revisions[r["source_revision_id"]]
        expected = stable_id(kind + "-revision", v["connection_id"], native, content)
        require(
            key not in used
            and v["id"] == expected
            and v["content_hash"] == content
            and v["source_record_id"] == native
            and key
            == stable_id(kind + "-receipt", expected, r["collection_attempt_id"]),
            "Inventory receipt hash changed",
        )
        used.add(key)

    verify_windows_inventory(cur, sources, attempts, receipts, receipt)


@pytest.mark.parametrize("configured", ["synthetic", "lab"], indirect=True)
@pytest.mark.parametrize(
    "tamper", ["none", "facts", "device", "count", "binding", "origin", "tenant"]
)
def test_retained_inventory_attribution(db, configured, tamper):  # noqa: F811
    device, selected, binding = configured
    with inventory(selected, binding) as (attempt, staged):
        persist(db, attempt, staged=staged, device_attempt_id=device.execution_id)
    with db.cursor() as cur:
        check(cur)
        if tamper == "none":
            # Complete-empty and failed attempts require no invented receipts.
            with inventory(selected, binding, empty=True) as (empty, staged):
                persist(db, empty, staged=staged, device_attempt_id=device.execution_id)
            failed = replace(
                attempt,
                execution_id=str(uuid4()),
                complete=False,
                outcome="failure",
                error_code="synthetic_failure",
            )
            persist(db, failed)
            check(cur)
            return
        # Defer existing constraints only inside this rollback-only transaction
        # so the retained-data verifier, rather than the write trigger, sees
        # deliberately corrupted evidence. No altered record can be committed.
        cur.execute("SET CONSTRAINTS ALL DEFERRED")
        if tamper == "facts":
            cur.execute(
                "UPDATE evidence_pipeline.windows_inventory_observations SET facts=jsonb_set(facts,'{version}','\"changed\"') WHERE attempt_id=%s",
                (attempt.execution_id,),
            )
        elif tamper == "device":
            cur.execute(
                "UPDATE evidence_pipeline.windows_inventory_runs SET device_attempt_id=attempt_id WHERE attempt_id=%s",
                (attempt.execution_id,),
            )
        elif tamper == "count":
            cur.execute(
                "UPDATE evidence_pipeline.windows_inventory_runs SET record_count=record_count+1 WHERE attempt_id=%s",
                (attempt.execution_id,),
            )
        elif tamper == "binding":
            cur.execute(
                "UPDATE evidence_pipeline.windows_inventory_bindings SET machine_guid=%s WHERE connection_id=%s",
                (str(uuid4()), selected.connection_id),
            )
        elif tamper == "origin":
            cur.execute(
                "UPDATE evidence_pipeline.authorized_connections SET origin='public' WHERE connection_id=%s",
                (selected.connection_id,),
            )
        else:
            cur.execute(
                "UPDATE evidence.source_connections SET tenant_id=NULL WHERE id=%s",
                (selected.connection_id,),
            )
        with pytest.raises(AssertionError):
            check(cur)
