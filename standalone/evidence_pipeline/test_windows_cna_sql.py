"""SQL-reader evaluations match the reference semantics and preserve authority."""

from backend.database import schema as database_schema

from copy import deepcopy
import json
import pytest


from standalone.evidence_pipeline.assessment.windows_cna_match import evaluate_products
from .test_windows_cna_match import entry
from .test_windows_version_match import FACTS
from .test_store import db as database_fixture
from .test_exposure_migration import (
    test_original_schema_verifier_accepts_only_recognized_upgrade as check_original,
)

db = database_fixture


def cases():
    yield [entry()], FACTS
    for version in (
        "10.0.26200.0",
        "10.0.26200.199",
        "10.0.26200.200",
        "10.0.26200.201",
        "10.0.26100.100",
    ):
        yield [entry()], {**FACTS, "version": version}
    for value in ("26200", "026200", None, True):
        yield [entry()], {**FACTS, "os_build": value}
    for change in (
        {"lessThanOrEqual": "10.0.26200.200"},
        {"lessThan": "*"},
        {"lessThan": "invalid"},
        {"lessThan": "10.0.26100.0"},
        {"versionType": "semver"},
        {"status": "fixed"},
        {"changes": {}},
        {"unexpected": True},
        {"changes": [dict(at="10.0.26200.100", status="unaffected")]},
        {
            "changes": [
                dict(at="10.0.26200.150", status="affected"),
                dict(at="10.0.26200.50", status="unaffected"),
            ]
        },
        {
            "changes": [
                dict(at="10.0.26200.100", status="affected"),
                dict(at="10.0.26200.100", status="unaffected"),
            ]
        },
    ):
        value = entry()
        value["versions"][0].update(change)
        yield [value], FACTS
    for change in (
        {"platforms": None},
        {"platforms": []},
        {"platforms": ["unknown"]},
        {"modules": ["feature"]},
        {"defaultStatus": "fixed"},
        {"defaultStatus": None},
        {"defaultStatus": "unaffected"},
        {"versions": [], "defaultStatus": "unaffected"},
    ):
        value = entry()
        value.update(change)
        yield [value], FACTS
    value = entry()
    value["versions"] = [dict(version="10.0.26200.100", status="unaffected")]
    yield [value], FACTS
    first = entry()
    second = entry()
    second["versions"][0]["status"] = "unaffected"
    yield [first, second], FACTS
    yield [second, first], FACTS
    value = entry()
    value["versions"].append({**value["versions"][0], "status": "unaffected"})
    yield [value], FACTS
    yield [entry()], {**FACTS, "os_processor": None}
    yield [entry()], {**FACTS, "os_architecture": "32-bit"}


def test_restricted_sql_parity_with_windows_reference(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for index, (entries, facts) in enumerate(cases()):
            expected = evaluate_products(
                deepcopy(entries), provider="Microsoft", facts=deepcopy(facts)
            )
            cur.execute(
                "SELECT evidence_pipeline.windows_cna_status(%s::jsonb,%s,%s::jsonb)",
                (json.dumps(entries), "Microsoft", json.dumps(facts)),
            )
            actual = cur.fetchone()[0]
            assert actual == expected, (index, actual, expected)


@pytest.mark.parametrize(
    "damage",
    [
        "ALTER FUNCTION evidence_pipeline.windows_cna_status(jsonb,text,jsonb) SECURITY DEFINER",
        "GRANT EXECUTE ON FUNCTION evidence_pipeline.windows_cna_status(jsonb,text,jsonb) TO PUBLIC",
        "REVOKE SELECT ON evidence_pipeline.current_windows_cna_evaluations FROM tm_mock_reader",
        "REVOKE EXECUTE ON FUNCTION pg_catalog.string_to_array(text,text) FROM tm_mock_reader",
    ],
)
def test_evaluator_authority_drift_rejected(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(damage)
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


def test_original_schema_remains_verifiable(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
    check_original(db)


@pytest.mark.parametrize(
    "extra_condition", [None, "cpeApplicability", "configurations"]
)
def test_reader_keeps_pinned_history_and_separate_publisher_scopes(db, extra_condition):
    from dataclasses import replace
    from datetime import timedelta
    from uuid import uuid4
    from .test_devices import make
    from .test_completeness import put
    from .test_cve_program import document, scope
    from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.persistence.store import persist_devices

    with db.cursor() as cur:
        database_schema.verify(cur)
    raw = dict(
        id="synthetic-pinned-cna-device",
        osPlatform="Windows11",
        version="25H2",
        osBuild=26200,
        osArchitecture="64-bit",
        osProcessor="x64",
    )
    device = make("Defender", [raw])
    put(db, device)
    finding = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="findings"),
        payload=json.dumps(
            [
                dict(
                    id="synthetic-cna-finding",
                    machineId=raw["id"],
                    cveId="CVE-2099-12345",
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
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_exposure(db, finding, device.execution_id)

    def read():
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT evaluated_vulnerability_status,evaluation_reason,device_attempt_id::text,public_connection_id::text,pinned_facts,interpretation FROM evidence_pipeline.current_windows_cna_evaluations WHERE connection_id=%s ORDER BY public_connection_id",
                (finding.scope.connection_id,),
            )
            return cur.fetchall()

    assert read()[0][:2] == ("unknown", "no_published_cna_evidence")
    document_value = document()
    document_value["containers"]["cna"]["providerMetadata"]["shortName"] = "Microsoft"
    document_value["containers"]["cna"]["affected"] = [entry()]
    if extra_condition == "cpeApplicability":
        # Synthetic version of the real failure mode: the product statement
        # includes x64 but its additional CPE statement selects ARM64 only.
        document_value["containers"]["cna"][extra_condition] = [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:o:microsoft:windows_11_25h2:*:*:*:*:*:*:arm64:*",
                            }
                        ],
                    }
                ]
            }
        ]
    elif extra_condition == "configurations":
        document_value["containers"]["cna"][extra_condition] = [
            {"lang": "en", "value": "Synthetic optional feature must be enabled"}
        ]
    cna = PublicSnapshot(
        scope(),
        str(uuid4()),
        device.started_at,
        device.finished_at,
        "success",
        True,
        json.dumps(document_value).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        authorize_connection(cur, cna)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, cna)
    rows = read()
    assert (
        len(rows) == 1
        and rows[0][0] == ("unknown" if extra_condition else "affected")
        and rows[0][2] == device.execution_id
    )
    assert rows[0][4]["os_build"] == "26200"
    assert rows[0][5] == "publisher_version_statement_not_patch_installation"
    if extra_condition:
        assert rows[0][1] == (
            "conflicting_product_and_cpe_evidence"
            if extra_condition == "cpeApplicability"
            else "textual_configuration_requires_evidence"
        )
    newer = replace(
        device,
        execution_id=str(uuid4()),
        started_at=device.finished_at + timedelta(seconds=1),
        finished_at=device.finished_at + timedelta(seconds=2),
        payload=json.dumps(
            [{**raw, "version": "26H1", "osBuild": 28000, "osProcessor": "ARM64"}]
        ).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_devices(db, newer)
    assert read() == rows
    document_value["containers"]["cna"]["affected"][0]["versions"][0]["status"] = (
        "unaffected"
    )
    other = replace(
        cna,
        execution_id=str(uuid4()),
        scope=replace(cna.scope, connection_id=str(uuid4())),
        payload=json.dumps(document_value).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        authorize_connection(cur, other)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_public(db, other)
    rows = read()
    expected_states = (
        {"unknown", "unaffected"}
        if extra_condition == "cpeApplicability"
        else {"unknown"}
        if extra_condition
        else {"affected", "unaffected"}
    )
    assert len(rows) == 2 and {row[0] for row in rows} == expected_states
    assert {row[3] for row in rows} == {
        cna.scope.connection_id,
        other.scope.connection_id,
    }
    assert {row[2] for row in rows} == {device.execution_id}
