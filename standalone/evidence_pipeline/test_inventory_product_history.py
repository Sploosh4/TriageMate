"""Generated inventory/CNA evidence proves joins without a Defender finding."""

from backend.database import schema as database_schema

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4
import json
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_completeness import put
from .test_cve_program import document, scope
from .test_devices import make
from .test_inventory_product_match import STATEMENT
from .test_store import db as db


@pytest.mark.parametrize(
    "inventory_origin,cna_origin",
    [
        ("synthetic", "synthetic"),
        ("lab", "synthetic"),
        ("lab", "public"),
    ],
)
@pytest.mark.parametrize("profile", ["tools", "edge", "onedrive", "teams"])
def test_inventory_pins_history_and_preserves_independent_source_scopes(
    db, inventory_origin, cna_origin, profile
):
    native = str(uuid4())
    raw = dict(id=native, operatingSystem="Windows", azureADDeviceId=str(uuid4()))
    device = make("Intune", [raw])
    device = replace(device, scope=replace(device.scope, origin=inventory_origin))
    put(db, device)
    app = dict(
        id="synthetic-app",
        displayName="VMware Tools",
        publisher="Broadcom Inc.",
        version="13.0.2.0",
        platform="windows",
        deviceCount=1,
    )
    if profile == "edge":
        app.update(
            displayName="Microsoft Edge",
            publisher="Microsoft Corporation",
            version="199.0.1000.5",
        )
    if profile in {"onedrive", "teams"}:
        from standalone.evidence_pipeline.assessment.windows_app_match import (
            PACKAGE_PUBLISHER,
        )

        app.update(
            displayName="MSTeams" if profile == "teams" else "Microsoft OneDrive",
            publisher=PACKAGE_PUBLISHER
            if profile == "teams"
            else "Microsoft Corporation",
            version="2.0.0.0",
        )
    inventory = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(
            device.scope,
            connection_id=str(uuid4()),
            input_kind="software",
            scope_reference="managed-device-apps:" + native,
        ),
        payload=json.dumps([app]).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        authorize_connection(cur, inventory)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (inventory.scope.connection_id, device.scope.connection_id),
        )
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_exposure(
        db, inventory, device.execution_id, json.dumps({app["id"]: [native]}).encode()
    )
    cve = "CVE-2099-" + str(uuid4().int % 9000000 + 1000000)
    value = document()
    value["cveMetadata"]["cveId"] = cve
    value["containers"]["cna"]["providerMetadata"]["shortName"] = "vmware"
    value["containers"]["cna"]["affected"] = deepcopy(STATEMENT["affected"])
    if profile == "edge":
        from .test_edge_inventory_match import STATEMENT as EDGE_STATEMENT

        value["containers"]["cna"]["providerMetadata"]["shortName"] = "microsoft"
        value["containers"]["cna"]["affected"] = deepcopy(EDGE_STATEMENT["affected"])
    if profile in {"onedrive", "teams"}:
        value["containers"]["cna"]["providerMetadata"]["shortName"] = "microsoft"
        value["containers"]["cna"]["affected"] = [
            {
                "vendor": "Microsoft",
                "product": "Microsoft Teams for Desktop"
                if profile == "teams"
                else "OneDrive for Windows",
                "versions": [
                    {
                        "version": "1.0.0.0",
                        "lessThan": "3.0.0.0",
                        "versionType": "custom",
                        "status": "affected",
                    }
                ],
            }
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

    def save(snapshot):
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            authorize_connection(cur, snapshot)
            cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        persist_public(db, snapshot)

    save(cna)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        database_schema.verify(cur)
        if profile == "edge":
            database_schema.verify(cur)
        if profile in {"onedrive", "teams"}:
            database_schema.verify(cur)

    def read():
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT source_product_version_status,device_attempt_id::text,"
                "device_receipt_id::text,inventory_receipt_id::text,tenant_id::text,"
                "public_connection_id::text,public_receipt_id::text,pinned_facts,mapping_profile "
                "FROM evidence_pipeline.current_inventory_product_evaluations "
                "WHERE connection_id=%s AND cve_id=%s ORDER BY public_connection_id",
                (inventory.scope.connection_id, cve),
            )
            return cur.fetchall()

    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        database_schema.verify(cur)

    def read_identity():
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT inventory_origin,tenant_id::text,device_attempt_id::text,"
                "device_receipt_id::text,receipt_id::text,recognition "
                "FROM evidence_pipeline.current_inventory_identities "
                "WHERE connection_id=%s",
                (inventory.scope.connection_id,),
            )
            return cur.fetchall()

    identity_before = read_identity()
    assert len(identity_before) == 1
    assert identity_before[0][0] == inventory_origin
    assert identity_before[0][2] == device.execution_id
    assert identity_before[0][5]["state"] == "recognized"
    assert identity_before[0][5]["applicability"] == "unknown"
    before = read()
    if inventory_origin == "lab" and cna_origin == "synthetic":
        assert before == []
        return
    assert len(before) == 1 and before[0][0] == "affected"
    assert before[0][1] == device.execution_id
    with db.cursor() as cur:
        cur.execute(
            "SELECT tenant_id::text FROM evidence.source_connections WHERE id=%s",
            (inventory.scope.connection_id,),
        )
        assert before[0][4] == cur.fetchone()[0]
    assert before[0][7]["publisher"] == app["publisher"]
    assert before[0][7]["operating_system"] == "Windows"
    assert (
        before[0][8]
        == {
            "tools": "intune-windows-vmware-tools-v1",
            "edge": "intune-windows-microsoft-edge-chromium-v1",
            "onedrive": "intune-windows-onedrive-v1",
            "teams": "intune-windows-msteams-v1",
        }[profile]
    )
    newer = replace(
        device,
        execution_id=str(uuid4()),
        finished_at=device.finished_at + timedelta(seconds=2),
        payload=json.dumps([{**raw, "operatingSystem": "Linux"}]).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, newer)
    assert read() == before
    assert read_identity() == identity_before
    value["containers"]["cna"]["affected"][0]["versions"][0]["status"] = "unaffected"
    other = replace(
        cna,
        execution_id=str(uuid4()),
        scope=replace(cna.scope, connection_id=str(uuid4())),
        payload=json.dumps(value).encode(),
    )
    save(other)
    assert read_identity() == identity_before
    rows = read()
    assert len(rows) == 2 and {row[0] for row in rows} == {"affected", "unaffected"}
    assert {row[1] for row in rows} == {device.execution_id}
    assert {row[2] for row in rows} == {before[0][2]}
    assert {row[3] for row in rows} == {before[0][3]}
    assert len({row[6] for row in rows}) == 2
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.vulnerability_findings WHERE cve_id=%s",
            (cve,),
        )
        assert cur.fetchone() == (0,)
