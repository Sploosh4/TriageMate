"""Source-exact device patch claims do not turn CVE matches into applicability."""

from backend.database import schema as database_schema

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection

from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_store import snapshot as advisory_snapshot
from .test_devices import make
from .test_completeness import put
from .test_store import db as database_fixture

db = database_fixture


@pytest.mark.parametrize(
    "product,fix,expected,reason",
    [
        (
            "Synthetic product release A",
            "KB9999991",
            "source_reported_applicable",
            "defender_fix_reference_and_exact_msrc_product_label",
        ),
        (
            "Synthetic product release A",
            "9999991",
            "source_reported_applicable",
            "defender_fix_reference_and_exact_msrc_product_label",
        ),
        (
            "Synthetic product release B",
            "KB9999991",
            "unknown",
            "product_identity_unresolved",
        ),
        (
            "Synthetic product release A",
            None,
            "unknown",
            "device_fix_reference_missing_or_different",
        ),
        (
            "Synthetic product release A",
            "9999991 extra",
            "unknown",
            "device_fix_reference_missing_or_different",
        ),
        (
            "Synthetic product release A",
            "kb9999991",
            "unknown",
            "device_fix_reference_missing_or_different",
        ),
        (
            "Synthetic product release A",
            "９９９９９９１",
            "unknown",
            "device_fix_reference_missing_or_different",
        ),
        (
            "Synthetic product release A",
            "KB9999990",
            "unknown",
            "device_fix_reference_missing_or_different",
        ),
    ],
)
@pytest.mark.parametrize(
    "overlapping",
    [
        None,
        "same_device",
        "missing_registration",
        "conflicting_registration",
        "different_device",
        "other_device_conflict_with_repeated_native",
        "other_device_conflict_with_missing_registration",
    ],
)
def test_applicability_and_replacement_require_source_exact_match(
    db, product, fix, expected, reason, overlapping
):
    with db.cursor() as cur:
        database_schema.verify(cur)
    device = make(
        "Defender",
        [
            {
                "id": "synthetic-patch-device",
                "osPlatform": "Windows11",
                "aadDeviceId": None
                if overlapping == "missing_registration"
                else str(uuid4()),
            }
        ],
    )
    put(db, device)
    if overlapping:
        repeated = json.loads(device.payload)
        if overlapping == "conflicting_registration":
            repeated[0]["aadDeviceId"] = str(uuid4())
        elif overlapping in {
            "different_device",
            "other_device_conflict_with_repeated_native",
            "other_device_conflict_with_missing_registration",
        }:
            repeated[0]["id"] = "synthetic-other-patch-device"
        put(
            db,
            replace(
                device,
                scope=replace(device.scope, connection_id=str(uuid4())),
                execution_id=str(uuid4()),
                payload=json.dumps(repeated).encode(),
            ),
        )
    if overlapping in {
        "other_device_conflict_with_repeated_native",
        "other_device_conflict_with_missing_registration",
    }:
        third_payload = json.loads(device.payload)
        if overlapping == "other_device_conflict_with_missing_registration":
            third_payload[0].pop("aadDeviceId")
        put(
            db,
            replace(
                device,
                scope=replace(device.scope, connection_id=str(uuid4())),
                execution_id=str(uuid4()),
                payload=json.dumps(third_payload).encode(),
            ),
        )
    observation_count = (
        3
        if overlapping
        in {
            "other_device_conflict_with_repeated_native",
            "other_device_conflict_with_missing_registration",
        }
        else (2 if overlapping else 1)
    )
    finding = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(device.scope, connection_id=str(uuid4()), input_kind="findings"),
        payload=json.dumps(
            [
                {
                    "id": "synthetic-patch-finding",
                    "machineId": "synthetic-patch-device",
                    "cveId": "CVE-2026-12345",
                    "productName": product,
                    "fixingKbId": fix,
                }
            ]
        ).encode(),
    )
    advisory = advisory_snapshot()
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
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT applicability,applicability_reason FROM evidence_pipeline.current_device_patch_candidates WHERE connection_id=%s AND advisory_connection_id=%s",
            (finding.scope.connection_id, advisory.scope.connection_id),
        )
        assert cur.fetchall() == [(expected, reason)]
        cur.execute(
            "SELECT fixing_patch_reference FROM evidence_pipeline.current_findings WHERE connection_id=%s",
            (finding.scope.connection_id,),
        )
        assert cur.fetchone() == (fix,)
        cur.execute(
            "SELECT count(*),count(DISTINCT computer_key),count(*) FILTER(WHERE derived_os_class='Windows client') FROM evidence_pipeline.current_os_classes WHERE connection_id IN (SELECT connection_id FROM evidence_pipeline.current_computer_links WHERE tenant_id=(SELECT tenant_id FROM evidence_pipeline.current_findings WHERE connection_id=%s LIMIT 1))",
            (finding.scope.connection_id,),
        )
        expected_computers = (
            2
            if overlapping
            in {
                "conflicting_registration",
                "different_device",
                "other_device_conflict_with_repeated_native",
                "other_device_conflict_with_missing_registration",
            }
            else 1
        )
        assert cur.fetchone() == (
            observation_count,
            expected_computers,
            observation_count,
        )
        cur.execute(
            "SELECT c.computer_key=l.computer_key FROM "
            "evidence_pipeline.current_device_patch_candidates c "
            "JOIN evidence_pipeline.current_computer_links l "
            "ON l.connection_id=%s WHERE c.connection_id=%s "
            "AND c.advisory_connection_id=%s",
            (
                device.scope.connection_id,
                finding.scope.connection_id,
                advisory.scope.connection_id,
            ),
        )
        assert cur.fetchall() == [(True,)]
        cur.execute(
            "SELECT count(DISTINCT computer_key),count(DISTINCT connection_id) "
            "FROM evidence_pipeline.current_completeness_cells "
            "WHERE connection_id IN (SELECT connection_id FROM "
            "evidence_pipeline.current_computer_links WHERE tenant_id="
            "(SELECT tenant_id FROM evidence_pipeline.current_findings "
            "WHERE connection_id=%s LIMIT 1))",
            (finding.scope.connection_id,),
        )
        assert cur.fetchone() == (expected_computers, observation_count)
        cur.execute(
            "SELECT replacing_patch,replaced_patch,replacement_meaning FROM evidence_pipeline.current_device_patch_replacements WHERE connection_id=%s AND advisory_connection_id=%s",
            (finding.scope.connection_id, advisory.scope.connection_id),
        )
        assert cur.fetchall() == (
            [("KB9999991", "KB9999990", "source_scoped_replacement_not_installation")]
            if expected == "source_reported_applicable"
            else []
        )
