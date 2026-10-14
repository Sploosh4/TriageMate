"""NVD configuration statements use original finding/device evidence, not patch claims."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4
import pytest
from .test_store import db as database_fixture


from .test_devices import make
from .test_completeness import put
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.store import persist_devices
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_public_inputs import nvd, scope, wire
from .test_windows_cpe_match import criterion, configuration

db = database_fixture


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("match", ["matched"]),
        ("excluded", ["excluded"]),
        ("prerequisite", ["unknown"]),
        ("missing", ["unknown"]),
        ("no_conditions", ["unknown"]),
        ("rejected", ["unknown"]),
        ("conflicting_scopes", ["excluded", "matched"]),
        ("lab_isolation", ["unknown"]),
        ("lab_public", ["matched"]),
    ],
)
def test_reader_preserves_pinned_facts_unknowns_and_separate_source_assertions(
    db, mode, expected
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    cve = "CVE-2099-" + str(uuid4().int)[:15]
    raw = dict(
        id="synthetic-" + str(uuid4()),
        osPlatform="Windows11",
        version="25H2",
        osBuild=26200,
        osArchitecture="64-bit",
        osProcessor="x64",
    )
    device = make("Defender", [raw])
    if mode in {"lab_isolation", "lab_public"}:
        device = replace(device, scope=replace(device.scope, origin="lab"))
    put(db, device)
    finding = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="findings"),
        payload=json.dumps(
            [
                dict(
                    id="synthetic-finding",
                    machineId=raw["id"],
                    cveId=cve,
                    productName="windows_11",
                    productVendor="microsoft",
                    productVersion="10.0.26200.100",
                    fixingKbId="9999991",
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
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_exposure(db, finding, device.execution_id)
    public_scopes = []
    if mode != "missing":
        conditions = [
            configuration(criterion("excluded" if mode == "excluded" else "matched"))
        ]
        if mode == "prerequisite":
            conditions = [
                configuration(criterion(), criterion("unknown", False), operator="AND")
            ]
        if mode == "conflicting_scopes":
            conditions.append(configuration(criterion("excluded")))
        for value in conditions:
            document = nvd()
            row = document["vulnerabilities"][0]["cve"]
            row["id"] = cve
            row["configurations"] = value
            if mode == "no_conditions":
                del row["configurations"]
            if mode == "rejected":
                row["vulnStatus"] = "Rejected"
            chosen = replace(
                scope("NVD"),
                connection_id=str(uuid4()),
                origin="public" if mode == "lab_public" else "synthetic",
            )
            public_scopes.append(chosen.connection_id)
            now = datetime.now(timezone.utc)
            snapshot = PublicSnapshot(
                chosen, str(uuid4()), now, now, "success", True, wire(document)
            )
            with db.cursor() as cur:
                cur.execute("RESET SESSION AUTHORIZATION")
                authorize_connection(cur, snapshot)
                cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
            persist_public(db, snapshot)
    # Later device evidence is deliberately incompatible. The finding keeps its
    # original prerequisite and cannot inherit this newer observation's build.
    newer = replace(
        device,
        execution_id=str(uuid4()),
        started_at=device.finished_at + timedelta(seconds=1),
        finished_at=device.finished_at + timedelta(seconds=2),
        payload=json.dumps(
            [{**raw, "version": "26H1", "osBuild": 27000, "osProcessor": "ARM64"}]
        ).encode(),
    )
    persist_devices(db, newer)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT configuration_state,device_attempt_id::text,pinned_facts,fixing_patch_reference,public_connection_id::text FROM evidence_pipeline.current_windows_nvd_evaluations WHERE connection_id=%s ORDER BY configuration_state",
            (finding.scope.connection_id,),
        )
        rows = cur.fetchall()
        assert [r[0] for r in rows] == expected
        assert all(
            r[1] == device.execution_id
            and r[2]["os_build"] == "26200"
            and r[2]["os_processor"] == "x64"
            for r in rows
        )
        assert all(r[3] == "9999991" for r in rows)
        assert {r[4] for r in rows} == (
            set(public_scopes) if public_scopes and mode != "lab_isolation" else {None}
        )


def test_migration_is_explicit_idempotent_and_detects_reader_grant_drift(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT SELECT ON evidence_pipeline.current_nvd_source_claims TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
