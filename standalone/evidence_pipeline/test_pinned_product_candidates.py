"""Restricted-reader Windows correlations keep pinned history and unknowns."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure

from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_completeness import put
from .test_cvrf_store import snapshot as advisory_snapshot
from .test_devices import make
from .test_store import db as database_fixture

db = database_fixture
CPE = "cpe:2.3:o:microsoft:windows_11_25H2:10.0.26200.9445:*:*:*:*:*:x64:*"


@pytest.mark.parametrize(
    "field,value,correlated",
    [
        (None, None, True),
        ("architecture", ("64-bit", "x64", "x64", True), True),
        ("architecture", ("64-bit", "ARM64", "arm64", False), True),
        ("architecture", ("32-bit", "x86", "x86", False), True),
        ("architecture", ("32-bit", "x64", None, None), True),
        ("architecture", ("64-bit", None, None, None), True),
        ("architecture", (None, "x64", None, None), True),
        ("architecture", ("unknown", "unknown", None, None), True),
        ("CPE", CPE.replace(":x64:", ":arm64:"), True),
        ("CPE", CPE.replace("25H2", "24H2"), False),
        ("CPE", CPE.replace("windows_11", "windows_10"), False),
        ("CPE", CPE.replace("microsoft", "another_vendor"), False),
        ("CPE", CPE + ":extra", False),
        ("CPE", CPE.replace("windows_11", "windows_*"), False),
        ("CPE", None, False),
        ("multiple_architectures", None, True),
        ("version", "[", False),
        ("productName", "[", False),
        ("version", "24H2", False),
        ("version", "25H2 extra", False),
        ("version", None, False),
        ("osPlatform", "Windows10", False),
        ("productName", "Windows 11", False),
        ("productVendor", "another_vendor", False),
    ],
)
def test_correlation_is_pinned_and_never_independent_applicability(
    db, field, value, correlated
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    device_raw = dict(
        id="synthetic-pinned-device", osPlatform="Windows11", version="25H2"
    )
    if field == "architecture":
        device_raw.update(osArchitecture=value[0], osProcessor=value[1])
    finding_raw = dict(
        id="synthetic-pinned-finding",
        machineId=device_raw["id"],
        cveId="CVE-2026-12345",
        productName="windows_11",
        productVendor="microsoft",
        productVersion="10.0.26200.100",
        fixingKbId="9999991",
    )
    if field in device_raw:
        device_raw[field] = value
    elif field in finding_raw:
        finding_raw[field] = value
    device = make("Defender", [device_raw])
    put(db, device)
    finding = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="findings"),
        payload=json.dumps([finding_raw]).encode(),
    )
    advisory = advisory_snapshot()
    document = json.loads(advisory.payload)
    for product in document["ProductTree"]["FullProductName"]:
        product["CPE"] = value if field == "CPE" else CPE
    if field == "multiple_architectures":
        document["ProductTree"]["FullProductName"][1]["CPE"] = CPE.replace(
            ":x64:", ":arm64:"
        )
        document["Vulnerability"][0]["Remediations"][1]["Description"] = {
            "Value": "9999991"
        }
    advisory = replace(advisory, payload=json.dumps(document).encode())
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        authorize_connection(cur, finding)
        cur.execute(
            "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
            (finding.scope.connection_id, device.scope.connection_id),
        )
        authorize_connection(cur, advisory)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    persist_exposure(db, finding, device.execution_id)
    persist_public(db, advisory)
    # A later OS observation must not change the prerequisite of an old finding.
    newer = replace(
        device,
        execution_id=str(uuid4()),
        started_at=device.finished_at + timedelta(seconds=1),
        finished_at=device.finished_at + timedelta(seconds=2),
        payload=json.dumps(
            [
                {
                    **device_raw,
                    "version": "26H1",
                    "osArchitecture": "32-bit",
                    "osProcessor": "x86",
                }
            ]
        ).encode(),
    )
    persist_devices(db, newer)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT family_release_correlated,independent_applicability,"
            "independent_applicability_reason,pinned_release_label,device_attempt_id,"
            "source_cpe,applicability FROM evidence_pipeline.current_device_product_candidates "
            "WHERE connection_id=%s AND advisory_connection_id=%s",
            (finding.scope.connection_id, advisory.scope.connection_id),
        )
        rows = cur.fetchall()
        assert len(rows) == (2 if field == "multiple_architectures" else 1)
        if field == "multiple_architectures":
            assert {row[5] for row in rows} == {CPE, CPE.replace(":x64:", ":arm64:")}
        for row in rows:
            assert row == (
                correlated,
                "unknown",
                "affected_version_semantics_unresolved"
                if field == "architecture" and value[3] is True
                else "architecture_and_version_applicability_unresolved"
                if correlated
                else "product_identity_unresolved",
                device_raw["version"],
                device.execution_id,
                row[5]
                if field == "multiple_architectures"
                else value
                if field == "CPE"
                else CPE,
                "unknown",
            )
        if field == "architecture":
            cur.execute(
                "SELECT pinned_os_architecture,pinned_os_processor,derived_architecture,"
                "architecture_correlated FROM evidence_pipeline.current_device_product_candidates "
                "WHERE connection_id=%s AND advisory_connection_id=%s",
                (finding.scope.connection_id, advisory.scope.connection_id),
            )
            assert cur.fetchall() == [value]
        cur.execute(
            "SELECT count(*) FROM evidence.device_observations d "
            "JOIN evidence.observation_receipts r ON r.id=d.receipt_id "
            "WHERE r.collection_attempt_id IN (%s,%s)",
            (device.execution_id, newer.execution_id),
        )
        assert cur.fetchone() == (2,)
