"""Synthetic Tools evidence preserves pinned history and source assertions."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_completeness import put
from .test_cve_program import document, scope
from .test_devices import make
from .test_store import db as database_fixture
from .test_vmware_tools_match import ENTRY


db = database_fixture


@pytest.mark.parametrize(
    "configuration,device_origin,cna_origin",
    [
        (None, "synthetic", "synthetic"),
        ("configurations", "synthetic", "synthetic"),
        ("cpeApplicability", "synthetic", "synthetic"),
        (None, "lab", "synthetic"),
        (None, "lab", "public"),
    ],
)
def test_pinned_history_and_conflicting_source_scopes(
    db, configuration, device_origin, cna_origin
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    raw = dict(id="synthetic-tools-device", osPlatform="Windows11", version="25H2")
    device = make("Defender", [raw])
    device = replace(device, scope=replace(device.scope, origin=device_origin))
    put(db, device)
    finding = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="findings"),
        payload=json.dumps(
            [
                dict(
                    id="synthetic-tools-finding",
                    machineId=raw["id"],
                    cveId="CVE-2099-12345",
                    productName="tools",
                    productVendor="vmware",
                    productVersion="13.0.1.0",
                    fixingKbId="synthetic-source-claim",
                )
            ]
        ).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        authorize_connection(cur, finding)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (finding.scope.connection_id, device.scope.connection_id),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_exposure(db, finding, device.execution_id)

    def read():
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT source_product_version_status,evaluation_reason,"
                "device_attempt_id::text,device_receipt_id::text,public_connection_id::text,"
                "public_receipt_id::text,finding_receipt_id::text,tenant_id::text,"
                "pinned_facts,fixing_patch_reference,interpretation "
                "FROM evidence_pipeline.current_vmware_tools_cna_evaluations "
                "WHERE connection_id=%s ORDER BY public_connection_id",
                (finding.scope.connection_id,),
            )
            return cur.fetchall()

    missing = read()
    assert len(missing) == 1 and missing[0][:2] == (
        "unknown",
        "no_published_cna_evidence",
    )
    value = document()
    value["containers"]["cna"]["providerMetadata"]["shortName"] = "vmware"
    value["containers"]["cna"]["affected"] = [ENTRY]
    if configuration:
        value["containers"]["cna"][configuration] = [
            dict(lang="en", value="Synthetic prerequisite")
        ]
    cna = PublicSnapshot(
        replace(scope(), origin=cna_origin),
        str(uuid4()),
        device.started_at,
        device.finished_at,
        "success",
        True,
        json.dumps(value).encode(),
    )

    def persist(snapshot):
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            authorize_connection(cur, snapshot)
            cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        persist_public(db, snapshot)

    persist(cna)
    before = read()
    assert len(before) == 1
    if device_origin == "lab" and cna_origin == "synthetic":
        assert before == missing
        return
    assert before[0][0] == ("unknown" if configuration else "affected")
    assert before[0][2] == device.execution_id
    with db.cursor() as cur:
        cur.execute(
            "SELECT tenant_id::text FROM evidence.source_connections WHERE id=%s",
            (finding.scope.connection_id,),
        )
        assert before[0][7] == cur.fetchone()[0]
    assert before[0][8]["operating_system"] == "Windows11"
    assert before[0][8]["version"] == "13.0.1.0"
    assert before[0][9] == "synthetic-source-claim"
    assert before[0][10] == "publisher_product_version_statement_not_full_applicability"
    newer = replace(
        device,
        execution_id=str(uuid4()),
        started_at=device.finished_at + timedelta(seconds=1),
        finished_at=device.finished_at + timedelta(seconds=2),
        payload=json.dumps([{**raw, "osPlatform": "Linux"}]).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, newer)
    assert read() == before
    value["containers"]["cna"]["affected"] = [
        {
            **ENTRY,
            "versions": [{**ENTRY["versions"][0], "status": "unaffected"}],
        }
    ]
    other = replace(
        cna,
        execution_id=str(uuid4()),
        scope=replace(cna.scope, connection_id=str(uuid4())),
        payload=json.dumps(value).encode(),
    )
    persist(other)
    rows = read()
    assert len(rows) == 2
    assert {r[0] for r in rows} == (
        {"unknown"} if configuration else {"affected", "unaffected"}
    )
    assert {r[2] for r in rows} == {device.execution_id}
    assert {r[3] for r in rows} == {before[0][3]}
    assert {r[4] for r in rows} == {cna.scope.connection_id, other.scope.connection_id}
    assert len({r[5] for r in rows}) == 2
    assert {r[6] for r in rows} == {before[0][6]}
