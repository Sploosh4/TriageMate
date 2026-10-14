from pathlib import Path
import sys
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.test_exposure_store import (
    bound as source_binding,
    inventory,
)
from standalone.evidence_pipeline.test_store import (
    db as database_fixture,
    snapshot as snapshot_fixture,
)

db = database_fixture
snapshot = snapshot_fixture
bound = source_binding
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ui-engine/postgres"))
from epss.baseline import verify  # noqa: E402


def test_baseline_accepts_attributed_devices_and_software(db, bound):
    with db.cursor() as cur:
        before = verify(cur)
    source, related = inventory(bound)
    persist_exposure(db, source, bound[0].execution_id, related)
    with db.cursor() as cur:
        result = verify(cur)
        assert result["device_observations"] == before["device_observations"]
        assert (
            result["software_observations"]
            == before.get("software_observations", 0) + 1
        )
        assert result["software"] == before.get("software", 0) + 2


@pytest.mark.parametrize("target", ["device", "software", "orphan", "original"])
def test_attribution_does_not_excuse_changed_or_unexplained_rows(db, bound, target):
    source, related = inventory(bound)
    persist_exposure(db, source, bound[0].execution_id, related)
    with db.cursor() as cur:
        if target == "device":
            cur.execute(
                "UPDATE evidence.device_observations SET display_name='unexplained change' WHERE provider_device_id IN (SELECT id FROM evidence.provider_devices WHERE connection_id=%s)",
                (bound[0].scope.connection_id,),
            )
        elif target == "software":
            cur.execute(
                "UPDATE evidence.software SET version='unexplained version' WHERE id IN (SELECT software_id FROM evidence_pipeline.software_inventory WHERE collection_attempt_id=%s)",
                (source.execution_id,),
            )
        elif target == "orphan":
            cur.execute(
                "INSERT INTO evidence.software(id,product_name) VALUES(%s,'unattributed')",
                (str(uuid4()),),
            )
        else:
            cur.execute(
                "UPDATE evidence.device_observations SET display_name='changed fixture' WHERE provider_device_id NOT IN (SELECT id FROM evidence.provider_devices WHERE connection_id=%s)",
                (bound[0].scope.connection_id,),
            )
        with pytest.raises(AssertionError):
            verify(cur)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_baseline_accepts_attributed_findings(db, bound):
    from dataclasses import replace
    import json

    device, child = bound
    source = replace(
        child,
        payload=json.dumps(
            [
                {
                    "id": "finding",
                    "machineId": device.records()[0]["id"],
                    "cveId": "CVE-2026-999999",
                    "productName": "Synthetic finding product",
                    "productVersion": "1",
                    "severity": "High",
                    "fixingKbId": "KB-SYNTHETIC",
                }
            ]
        ).encode(),
    )
    with db.cursor() as cur:
        before = verify(cur)
    persist_exposure(db, source, device.execution_id)
    with db.cursor() as cur:
        result = verify(cur)
        assert (
            result["vulnerability_findings"]
            == before.get("vulnerability_findings", 0) + 1
        )


@pytest.mark.parametrize("source", ["FIRST", "MSRC"])
def test_repeated_public_revision_checks_every_receipt_projection(db, source):
    from dataclasses import replace
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from .test_public_snapshot import attempt
    from .test_cvrf_store import prepare

    if source == "MSRC":
        first = prepare(db)
    else:
        first = attempt()
        with db.cursor() as cur:
            authorize_connection(cur, first)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    second = replace(first, execution_id=str(uuid4()))
    persist_public(db, first)
    persist_public(db, second)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)
        cur.execute(
            "SELECT id::text,source_revision_id::text FROM evidence.observation_receipts "
            "WHERE collection_attempt_id=ANY(%s::uuid[]) ORDER BY id",
            ([first.execution_id, second.execution_id],),
        )
        receipts = cur.fetchall()
        assert len(receipts) == 2 and receipts[0][1] == receipts[1][1]
        if source == "MSRC":
            cur.execute(
                "UPDATE evidence.patches SET title='synthetic corruption' WHERE receipt_id=%s",
                (receipts[-1][0],),
            )
        else:
            cur.execute(
                "UPDATE evidence.epss_observations SET probability=0 WHERE receipt_id=%s",
                (receipts[-1][0],),
            )
        with pytest.raises(AssertionError, match="projection changed"):
            verify(cur)


@pytest.mark.full_baseline
def test_full_retained_evidence_and_original_schema(db):
    """One complete retained-data audit; source-specific mutation tests remain."""
    with db.cursor() as cur:
        verify(cur)
