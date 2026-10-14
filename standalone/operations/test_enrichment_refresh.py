"""Refresh eligibility preserves initial request and synthetic/public boundaries."""

from dataclasses import replace
import json
from uuid import uuid4
import pytest

from .enrichment_refresh import candidates
from standalone.evidence_pipeline.persistence.enrichment_store import (
    discover,
    request_scope,
    start_request,
)
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.test_public_inputs import nvd
from standalone.evidence_pipeline.test_enrichment_store import (
    db as db,
    bound,  # noqa: F401
    snapshot,  # noqa: F401
    queued_input as queued_input,
)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("with_history", [False, True])
@pytest.mark.parametrize("record_origin", ["synthetic", "public"])
@pytest.mark.parametrize("provider", ["NVD", "MSRC"])
def test_bulk_current_records_refresh_only_matching_finding_causes(
    db, queued_input, with_history, record_origin, provider
):
    """Unrequested current records qualify; unrelated records never expand scope."""
    from copy import deepcopy
    from standalone.evidence_pipeline.test_public_inputs import scope

    _, child, cves = queued_input
    if provider == "MSRC":
        from standalone.evidence_pipeline.test_csaf import fixture, scope

        raw = fixture()
        prototype = raw["vulnerabilities"][0]
        source_scope = scope()
    else:
        raw = nvd()
        prototype = raw["vulnerabilities"][0]
        source_scope = scope("NVD")
    records = []
    for cve in [cves[0], *[f"CVE-2098-{10000 + n}" for n in range(256)]]:
        record = deepcopy(prototype)
        if provider == "MSRC":
            record["cve"] = cve
            record["remediations"] = []
        else:
            record["cve"]["id"] = cve
        records.append(record)
    raw["vulnerabilities"] = records
    if provider == "NVD":
        raw.update(totalResults=len(records), resultsPerPage=len(records))
    public_snapshot = PublicSnapshot(
        replace(source_scope, connection_id=str(uuid4()), origin=record_origin),
        str(uuid4()),
        child.started_at,
        child.finished_at,
        "success",
        True,
        json.dumps(raw).encode(),
    )
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        authorize_connection(cur, public_snapshot)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(db, public_snapshot)
    with db.cursor() as cur:
        # Rotation uses the internal operation journal, which remains hidden
        # from the UI reader. Plain eligibility can use the restricted reader.
        cur.execute(
            "SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer"
            if with_history
            else "SET LOCAL SESSION AUTHORIZATION tm_mock_reader"
        )
        history = (
            ("synthetic-bulk-refresh-" + uuid4().hex, str(uuid4()))
            if with_history
            else None
        )
        result = candidates(
            cur,
            source=provider,
            origin="synthetic",
            synthetic_cves=cves,
            history=history,
        )
        assert [r["cve_id"] for r in result] == (
            [cves[0]] if record_origin == "synthetic" else []
        )
        assert all(r["request_id"] is None for r in result)
        assert (
            candidates(
                cur,
                source="NVD" if provider == "MSRC" else "MSRC",
                origin="synthetic",
                synthetic_cves=cves,
                history=history,
            )
            == []
        )


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize(
    "outcome,eligible",
    [
        ("queued", False),
        ("started", False),
        ("record", True),
        ("empty", True),
        ("public_not_found", True),
        ("public_transport_failed", False),
        ("public_rate_limited", False),
        ("invalid_public_payload", False),
    ],
)
def test_only_resolved_requests_become_refresh_candidates(
    db, queued_input, outcome, eligible
):
    _, child, _ = queued_input
    request = discover(db, child.execution_id, sources=["NVD"], limit=1)[0]
    with db.cursor() as cur:
        scope, cve = request_scope(cur, request)
        cur.execute("RESET SESSION AUTHORIZATION")
        envelope = PublicSnapshot(
            scope,
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
    if outcome != "queued":
        execution = start_request(db, request)
        if outcome != "started":
            raw = nvd()
            raw["vulnerabilities"][0]["cve"]["id"] = cve
            if outcome == "empty":
                raw.update(vulnerabilities=[], totalResults=0, resultsPerPage=0)
            complete = outcome in ("record", "empty")
            persist_public(
                db,
                replace(
                    envelope,
                    execution_id=execution,
                    outcome="success" if complete else "failure",
                    complete=complete,
                    error_code=None if complete else outcome,
                    payload=json.dumps(raw).encode() if complete else b"",
                ),
            )
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        result = candidates(cur, source="NVD", origin="synthetic", synthetic_cves=[cve])
        assert [row["cve_id"] for row in result] == ([cve] if eligible else [])
        assert (
            candidates(cur, source="MSRC", origin="synthetic", synthetic_cves=[cve])
            == []
        )
        cur.execute(
            "SELECT execution_id FROM evidence_pipeline.enrichment_runs WHERE request_id=%s",
            (request,),
        )
        before = cur.fetchall()
        candidates(cur, source="NVD", origin="synthetic", synthetic_cves=[cve])
        cur.execute(
            "SELECT execution_id FROM evidence_pipeline.enrichment_runs WHERE request_id=%s",
            (request,),
        )
        assert cur.fetchall() == before


@pytest.mark.parametrize(
    "options",
    [
        {"source": "unknown", "origin": "public"},
        {"source": "NVD", "origin": "lab"},
        {"source": "NVD", "origin": "synthetic"},
        {"source": "NVD", "origin": "public", "synthetic_cves": []},
        {"source": "NVD", "origin": "public", "limit": True},
        {
            "source": "NVD",
            "origin": "synthetic",
            "synthetic_cves": ["CVE-2099-1234"] * 2,
        },
    ],
)
def test_invalid_authority_rejects_before_query(options):
    with pytest.raises(ValueError):
        candidates(None, **options)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
@pytest.mark.parametrize("empty", [False, True])
def test_rotation_reaches_other_resolved_cves_including_not_found(
    db, queued_input, empty
):
    from datetime import timedelta

    _, child, cves = queued_input
    requests = discover(db, child.execution_id, sources=["NVD"])
    for request in requests:
        with db.cursor() as cur:
            scope, cve = request_scope(cur, request)
            cur.execute("RESET SESSION AUTHORIZATION")
            envelope = PublicSnapshot(
                scope,
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
        raw = nvd()
        raw["vulnerabilities"][0]["cve"]["id"] = cve
        if empty:
            raw.update(vulnerabilities=[], totalResults=0, resultsPerPage=0)
        persist_public(
            db,
            replace(
                envelope,
                execution_id=execution,
                outcome="success",
                complete=True,
                error_code=None,
                payload=json.dumps(raw).encode(),
            ),
        )
    key, input_id = "synthetic-refresh-" + uuid4().hex, str(uuid4())
    now = child.finished_at + timedelta(days=1)
    with db.cursor() as cur:
        first = candidates(
            cur,
            source="NVD",
            origin="synthetic",
            limit=1,
            synthetic_cves=cves,
            history=(key, input_id),
        )[0]["cve_id"]
        cur.execute(
            "INSERT INTO evidence_pipeline.operation_checkpoints VALUES(%s,1,%s,%s::jsonb)",
            (key, now, "{}"),
        )
        event = dict(
            kind="enrichment_refresh_batch",
            input_id=input_id,
            source="NVD",
            origin="synthetic",
            cve_ids=[first],
        )
        cur.execute(
            "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) VALUES(%s,1,%s,%s::jsonb)",
            (key, now, json.dumps(event)),
        )
        next_cve = candidates(
            cur,
            source="NVD",
            origin="synthetic",
            limit=1,
            synthetic_cves=cves,
            history=(key, input_id),
        )[0]["cve_id"]
        assert next_cve != first and {first, next_cve} == set(cves)
        assert (
            candidates(
                cur,
                source="NVD",
                origin="synthetic",
                limit=1,
                synthetic_cves=cves,
                history=(key, str(uuid4())),
            )[0]["cve_id"]
            == first
        )
