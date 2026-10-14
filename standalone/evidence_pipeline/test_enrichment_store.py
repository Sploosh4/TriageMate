"""Synthetic queue discovery and writer boundaries in rollback-only transactions."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import timedelta
import json
from uuid import uuid4

import pytest
from psycopg2.errors import UniqueViolation

from standalone.evidence_pipeline.persistence.enrichment_store import (
    discover,
    discover_remaining,
    request_scope,
    start_request,
)

from standalone.evidence_pipeline.persistence.enrichment_attribution import (
    verify_enrichment,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_public_inputs import nvd, scope
from standalone.evidence_pipeline.persistence.store import atomic
from standalone.evidence_pipeline.persistence.store import ReplayConflict
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.persistence.assessment_store import (
    persist_assessments,
    checkpoint,
)
from .test_authority import reject
from .test_exposure_store import (
    bound as bound_fixture,
    db as database_fixture,
    snapshot as snapshot_fixture,
)

bound = bound_fixture
db = database_fixture
snapshot = snapshot_fixture


@pytest.fixture
def queued_input(db, bound):
    device, child = bound
    cves = [("CVE-2099-" + str(uuid4().int))[:28] for _ in range(2)]
    records = [
        {
            "id": f"synthetic-finding-{i}",
            "machineId": device.records()[0]["id"],
            "cveId": cve,
            "productName": "Synthetic queue fixture",
            "productVersion": str(i),
        }
        for i, cve in enumerate([cves[0], cves[0], cves[1]])
    ]
    child = replace(child, payload=json.dumps(records).encode())
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_exposure(db, child, device.execution_id)
    return device, child, cves


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_bounded_discovery_deduplicates_across_rows_passes_and_attempts(
    db, queued_input
):
    device, child, cves = queued_input
    ids = []
    for _ in range(4):
        ids += discover(db, child.execution_id, sources=["NVD", "MSRC"], limit=1)
    assert len(ids) == len(set(ids)) == 4
    assert discover(db, child.execution_id, sources=["NVD", "MSRC"]) == []
    newer = replace(
        child,
        execution_id=str(uuid4()),
        finished_at=child.finished_at + timedelta(seconds=1),
    )
    persist_exposure(db, newer, device.execution_id)
    assert discover(db, newer.execution_id, sources=["NVD", "MSRC"]) == []
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT source_name,cve_id,origin FROM evidence_pipeline.enrichment_requests WHERE id=ANY(%s::uuid[])",
            (ids,),
        )
        assert set(cur.fetchall()) == {
            (s, c, "synthetic") for s in ("NVD", "MSRC") for c in cves
        }


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_failed_findings_do_not_create_requests(db, queued_input):
    device, child, _ = queued_input
    failed = replace(
        child,
        execution_id=str(uuid4()),
        outcome="failure",
        complete=False,
        payload=b"",
        error_code="synthetic_failure",
    )
    persist_exposure(db, failed, device.execution_id)
    assert discover(db, failed.execution_id, sources=["CVE", "CISA"]) == []
    assert len(discover(db, child.execution_id, sources=["CVE", "CISA"])) == 4


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_cause_cannot_be_forged_relabelled_or_removed(db, queued_input):
    _, child, cves = queued_input
    ids = discover(db, child.execution_id, sources=["NVD"])
    with db.cursor() as cur:
        cur.execute(
            "SELECT cause_receipt_id,cve_id FROM evidence_pipeline.enrichment_requests WHERE id=%s",
            (ids[0],),
        )
        receipt, cve = cur.fetchone()
    other = next(c for c in cves if c != cve)
    insert = "INSERT INTO evidence_pipeline.enrichment_requests(id,source_name,input_kind,cve_id,origin,cause_receipt_id) VALUES(%s,'CVE','records',%s,%s,%s)"
    reject(db, insert, (str(uuid4()), other, "synthetic", receipt))
    reject(db, insert, (str(uuid4()), cve, "public", receipt))
    reject(db, insert, (str(uuid4()), cve, "synthetic", str(uuid4())))
    reject(
        db, "DELETE FROM evidence_pipeline.enrichment_requests WHERE id=%s", (ids[0],)
    )
    reject(
        db,
        "UPDATE evidence_pipeline.enrichment_requests SET origin='public' WHERE id=%s",
        (ids[0],),
    )
    with db.cursor() as cur, pytest.raises(UniqueViolation), atomic(cur):
        cur.execute(
            "INSERT INTO evidence_pipeline.enrichment_requests(id,source_name,input_kind,cve_id,origin,cause_receipt_id) VALUES(%s,'NVD','vulnerabilities',%s,'synthetic',%s)",
            (str(uuid4()), cve, receipt),
        )


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("origin,expected", [("synthetic", 1), ("public", 2)])
def test_existing_current_source_record_satisfies_only_same_origin(
    db, queued_input, origin, expected
):
    _, child, cves = queued_input
    raw = nvd()
    raw["vulnerabilities"][0]["cve"]["id"] = cves[0]
    public = PublicSnapshot(
        replace(scope("NVD"), connection_id=str(uuid4()), origin=origin),
        str(uuid4()),
        child.started_at,
        child.finished_at,
        "success",
        True,
        json.dumps(raw).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        authorize_connection(cur, public)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(db, public)
    assert len(discover(db, child.execution_id, sources=["NVD"])) == expected
    # One source's record never satisfies another source's missing evidence.
    assert len(discover(db, child.execution_id, sources=["MSRC"])) == 2


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_discovery_rolls_back_with_callers_transaction_and_rejects_other_inputs(
    db, queued_input
):
    device, child, _ = queued_input
    for execution in (device.execution_id, str(uuid4())):
        with pytest.raises(ValueError, match="registered finding"):
            discover(db, execution, sources=["NVD"])
    with db.cursor() as cur:
        cur.execute("SAVEPOINT before_discovery")
    first = discover(db, child.execution_id, sources=["NVD"])
    with db.cursor() as cur:
        cur.execute("ROLLBACK TO SAVEPOINT before_discovery")
    assert len(first) == 2
    assert discover(db, child.execution_id, sources=["NVD"]) == first


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("event", [None, "New", "Updated", "Fixed"])
def test_assessment_causes_include_baselines_and_open_events(db, queued_input, event):
    device, child, cves = queued_input
    row = {
        "id": "synthetic-assessment",
        "deviceId": device.records()[0]["id"],
        "softwareVendor": "Synthetic",
        "softwareName": "Queue test",
        "softwareVersion": "1",
        "cveId": cves[0],
    }
    baseline = replace(
        child,
        scope=replace(
            child.scope, connection_id=str(uuid4()), input_kind="vulnerability_baseline"
        ),
        execution_id=str(uuid4()),
        payload=json.dumps([row]).encode(),
    )
    delta = replace(
        baseline,
        scope=replace(
            baseline.scope,
            connection_id=str(uuid4()),
            input_kind="vulnerability_events",
        ),
        execution_id=str(uuid4()),
        started_at=baseline.started_at + timedelta(hours=6),
        finished_at=baseline.finished_at + timedelta(hours=6),
        payload=json.dumps(
            [
                {
                    **row,
                    "status": event or "New",
                    "eventTimestamp": "2026-09-12T01:00:00Z",
                }
            ]
        ).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        for value in (baseline, delta):
            authorize_connection(cur, value)
        cur.execute(
            "INSERT INTO evidence_pipeline.assessment_bindings VALUES(%s,%s,NULL),(%s,%s,%s)",
            (
                baseline.scope.connection_id,
                device.scope.connection_id,
                delta.scope.connection_id,
                device.scope.connection_id,
                baseline.scope.connection_id,
            ),
        )
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_assessments(db, baseline, device.execution_id)
    target = baseline
    if event:
        with db.cursor() as cur:
            previous, since, _ = checkpoint(cur, baseline.scope.connection_id)
        persist_assessments(db, delta, device.execution_id, previous, since)
        target = delta
    assert len(discover(db, target.execution_id, sources=["CVE"])) == (
        0 if event == "Fixed" else 1
    )


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize(
    "sources,limit",
    [
        ([], 1),
        (["OSV"], 1),
        (["NVD", "NVD"], 1),
        (["NVD"], 0),
        (["NVD"], 1001),
        (["NVD"], True),
    ],
)
def test_discovery_rejects_unsupported_configuration(db, queued_input, sources, limit):
    with pytest.raises(ValueError):
        discover(db, queued_input[1].execution_id, sources=sources, limit=limit)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize(
    "result,state",
    [
        ("record", "succeeded"),
        ("empty", "not_found"),
        ("wrong_cve", "invalid"),
        ("mixed_cves", "invalid"),
        ("public_not_found", "not_found"),
        ("public_gone", "unavailable"),
        ("public_rate_limited", "unavailable"),
        ("invalid_public_payload", "invalid"),
        ("public_transport_failed", "failed"),
    ],
)
def test_request_claim_and_evidence_determine_state(db, queued_input, result, state):
    _, child, _ = queued_input
    request = discover(db, child.execution_id, sources=["NVD"], limit=1)[0]
    with pytest.raises(ValueError, match="explicit source registration"):
        start_request(db, request)
    with db.cursor() as cur:
        chosen, cve = request_scope(cur, request)
        cur.execute(
            "SELECT state FROM evidence_pipeline.enrichment_request_status WHERE id=%s",
            (request,),
        )
        assert cur.fetchone() == ("queued",)
        cur.execute("RESET SESSION AUTHORIZATION")
        envelope = PublicSnapshot(
            chosen,
            str(uuid4()),
            child.started_at,
            child.finished_at,
            "failure",
            False,
            b"",
            "synthetic_registration",
        )
        authorize_connection(cur, envelope)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    execution = start_request(db, request)
    assert execution and start_request(db, request) is None
    with db.cursor() as cur:
        cur.execute(
            "SELECT state FROM evidence_pipeline.enrichment_request_status WHERE id=%s",
            (request,),
        )
        assert cur.fetchone() == ("started",)
    raw = nvd()
    raw["vulnerabilities"][0]["cve"]["id"] = (
        cve if result != "wrong_cve" else "CVE-2099-99999999"
    )
    if result == "empty":
        raw.update(vulnerabilities=[], totalResults=0, resultsPerPage=0)
    if result == "mixed_cves":
        other = nvd()["vulnerabilities"][0]
        other["cve"]["id"] = "CVE-2099-99999999"
        raw["vulnerabilities"].append(other)
        raw.update(totalResults=2, resultsPerPage=2)
    complete = result in ("record", "empty", "wrong_cve", "mixed_cves")
    attempt = replace(
        envelope,
        execution_id=execution,
        complete=complete,
        outcome="success" if complete else "failure",
        error_code=None if complete else result,
        payload=json.dumps(raw).encode() if complete else b"",
    )
    with db.cursor() as cur:
        cur.execute("SAVEPOINT before_public_import")
    persist_public(db, attempt)
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT state,error_code FROM evidence_pipeline.enrichment_request_status WHERE id=%s",
            (request,),
        )
        assert cur.fetchone() == (state, attempt.error_code)
        cur.execute("ROLLBACK TO SAVEPOINT before_public_import")
        cur.execute(
            "SELECT state FROM evidence_pipeline.enrichment_request_status WHERE id=%s",
            (request,),
        )
        assert cur.fetchone() == ("started",)
    assert start_request(db, request) is None
    persist_public(db, attempt)
    assert persist_public(db, attempt)["replayed"]
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify_enrichment(cur)
        cur.execute(
            "UPDATE evidence_pipeline.enrichment_runs SET execution_id=%s WHERE request_id=%s",
            (str(uuid4()), request),
        )
        with pytest.raises(AssertionError, match="registered request"):
            verify_enrichment(cur)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("damage", ["identity", "cause"])
def test_independent_attribution_rejects_owner_modified_requests(
    db, queued_input, damage
):
    _, child, _ = queued_input
    ids = discover(db, child.execution_id, sources=["NVD"])
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify_enrichment(cur)
        if damage == "identity":
            cur.execute(
                "UPDATE evidence_pipeline.enrichment_requests SET id=%s WHERE id=%s",
                (str(uuid4()), ids[0]),
            )
        else:
            cur.execute(
                "UPDATE evidence_pipeline.enrichment_requests SET cause_receipt_id=(SELECT cause_receipt_id FROM evidence_pipeline.enrichment_requests WHERE id=%s) WHERE id=%s",
                (ids[1], ids[0]),
            )
        with pytest.raises(AssertionError, match="finding evidence"):
            verify_enrichment(cur)


@pytest.mark.full_baseline
@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_queue_and_its_findings_pass_full_retained_attribution(db, queued_input):
    from .test_attribution import verify

    assert len(discover(db, queued_input[1].execution_id, sources=["NVD", "CVE"])) == 4
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_discovery_does_not_hide_unrelated_primary_key_collision(db, queued_input):
    _, child, cves = queued_input
    forged_id = stable_id(
        "enrichment-request-v1", "NVD", "vulnerabilities", "synthetic", cves[1]
    )
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO evidence_pipeline.enrichment_requests(id,source_name,input_kind,cve_id,origin,cause_receipt_id) SELECT %s,'NVD','vulnerabilities',cve_id,origin,receipt_id FROM evidence_pipeline.enrichment_causes WHERE collection_attempt_id=%s AND cve_id=%s LIMIT 1",
            (forged_id, child.execution_id, cves[0]),
        )
    with pytest.raises(ReplayConflict, match="identity collision"):
        discover(db, child.execution_id, sources=["NVD"])


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_remaining_discovery_continues_without_a_new_finding_import(db, queued_input):
    _, child, cves = queued_input
    first = discover_remaining(db, origin="synthetic", sources=["NVD"], limit=1)
    assert len(first) == 1
    rest = discover_remaining(db, origin="synthetic", sources=["NVD"], limit=1000)
    assert not set(first) & set(rest)
    assert discover(db, child.execution_id, sources=["NVD"]) == []
    with db.cursor() as cur:
        cur.execute(
            "SELECT cve_id,origin FROM evidence_pipeline.enrichment_requests WHERE id=ANY(%s::uuid[])",
            (first + rest,),
        )
        rows = cur.fetchall()
        assert {(cve, "synthetic") for cve in cves}.issubset(set(rows))
        assert all(origin == "synthetic" for _, origin in rows)
    with pytest.raises(ValueError, match="explicit public or synthetic"):
        discover_remaining(db, origin=None, sources=["NVD"])


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_large_assessment_sized_discovery_preserves_batch_boundary(db, queued_input):
    device, child, _ = queued_input
    cves = [("CVE-2099-" + str(uuid4().int))[:28] for _ in range(101)]
    row = json.loads(child.payload)[0]
    larger = replace(
        child,
        execution_id=str(uuid4()),
        finished_at=child.finished_at + timedelta(seconds=1),
        payload=json.dumps(
            [
                {**row, "id": f"synthetic-batch-{i}", "cveId": cve}
                for i, cve in enumerate(cves)
            ]
        ).encode(),
    )
    persist_exposure(db, larger, device.execution_id)
    first = discover(db, larger.execution_id, sources=["NVD"], limit=100)
    second = discover(db, larger.execution_id, sources=["NVD"], limit=100)
    assert len(first) == 100 and len(second) == 1
    assert not set(first) & set(second)
    assert discover(db, larger.execution_id, sources=["NVD"], limit=100) == []
    with db.cursor() as cur:
        cur.execute(
            "SELECT cve_id,origin FROM evidence_pipeline.enrichment_requests WHERE id=ANY(%s::uuid[])",
            (first + second,),
        )
        assert set(cur.fetchall()) == {(cve, "synthetic") for cve in cves}
