"""Exact refresh proof and explicit source/origin authority boundaries."""

from dataclasses import replace
from datetime import timezone, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest

from . import enrichment_refresh_worker as module
from .enrichment_refresh_selection import RefreshSelection
from .test_enrichment_batch import binding
from standalone.evidence_pipeline.parsing.devices import stable_id


def held(
    tmp_path, monkeypatch, *, complete=True, error=None, record_cve="CVE-2099-1234"
):
    batch, job = binding()
    selection = RefreshSelection(batch)
    monkeypatch.setattr(type(batch), "active", lambda *args: (1, None))
    monkeypatch.setattr(RefreshSelection, "saved", lambda *args: ["CVE-2099-1234"])
    scope = module.source_scope(batch, "CVE-2099-1234")
    execution = module.attempt_id(job, scope)
    now = datetime(2099, 1, 1, tzinfo=timezone.utc)
    snap = SimpleNamespace(
        complete=complete,
        error_code=error,
        input_fingerprint="a" * 64,
        started_at=now,
        finished_at=now,
        outcome="success" if complete else "failure",
        feed=lambda: None,
    )
    prepare = Mock(return_value=snap)
    monkeypatch.setattr(module, "prepare", prepare)
    record = SimpleNamespace(
        source_record_id=record_cve, content_hash="b" * 64, claim="synthetic claim"
    )
    monkeypatch.setattr(module, "normalize_public", lambda feed: (x for x in [record]))
    cursor = Mock()
    revision = stable_id(
        "public-revision", scope.connection_id, "CVE-2099-1234", record.content_hash
    )
    rows = (
        [
            (
                stable_id("public-receipt", revision, execution),
                revision,
                record.content_hash,
                record.claim,
            )
        ]
        if complete
        else []
    )
    attempt = [
        (
            scope.connection_id,
            snap.input_fingerprint,
            scope.scope_reference,
            scope.origin,
            now,
            now,
            snap.outcome,
            complete,
            error,
        )
    ]
    cursor.fetchall.side_effect = [attempt, rows]
    cursor.fetchone.return_value = (len(rows),)
    return selection, job, cursor, prepare, attempt, rows


@pytest.mark.parametrize(
    "damage",
    [
        None,
        "foreign_cve",
        "wrong_fingerprint",
        "extra_receipt",
        "missing_claim",
        "changed_claim",
        "wrong_origin",
    ],
)
def test_completion_requires_exact_saved_attempt_and_receipts(
    tmp_path, monkeypatch, damage
):
    selection, job, cursor, prepare, attempt, rows = held(
        tmp_path,
        monkeypatch,
        record_cve="CVE-2099-9999" if damage == "foreign_cve" else "CVE-2099-1234",
    )
    if damage == "wrong_fingerprint":
        attempt[0] = (attempt[0][0], "c" * 64, *attempt[0][2:])
    elif damage == "wrong_origin":
        attempt[0] = (*attempt[0][:3], "public", *attempt[0][4:])
    elif damage == "extra_receipt":
        cursor.fetchone.return_value = (2,)
    elif damage == "missing_claim":
        rows.clear()
    elif damage == "changed_claim":
        rows[0] = (*rows[0][:3], "changed")
    assert module.committed(cursor, selection, job, "synthetic", tmp_path) is (
        damage is None
    )
    assert prepare.call_args.kwargs["replay_only"] is True


@pytest.mark.parametrize(
    "error,expected",
    [
        ("public_not_found", True),
        ("public_rate_limited", False),
        ("public_transport_failed", False),
    ],
)
def test_confirmed_absence_is_distinct_from_failed_collection(
    tmp_path, monkeypatch, error, expected
):
    selection, job, cursor, _, _, _ = held(
        tmp_path, monkeypatch, complete=False, error=error
    )
    assert module.committed(cursor, selection, job, "synthetic", tmp_path) is expected


def test_attempts_repeat_only_within_same_run():
    batch, job = binding()
    scope = module.source_scope(batch, "CVE-2099-1234")
    assert module.attempt_id(job, scope) == module.attempt_id(job, scope)
    _, later = binding()
    assert module.attempt_id(job, scope) != module.attempt_id(later, scope)
    assert scope != module.source_scope(
        replace(batch, origin="public"), "CVE-2099-1234"
    )
    assert (
        scope.scope_reference
        == module.source_scope(
            replace(batch, origin="public"), "CVE-2099-1234"
        ).scope_reference
    )


@pytest.mark.parametrize(
    "public,network,fixtures",
    [(False, True, {}), (False, False, None), (True, False, None), (True, True, {})],
)
def test_collection_rejects_unauthorised_network_before_any_effect(
    tmp_path, public, network, fixtures
):
    batch, job = binding()
    selection = RefreshSelection(
        replace(batch, origin="public" if public else "synthetic")
    )
    with pytest.raises(ValueError, match="authority or synthetic"):
        module.collect(
            selection,
            job,
            "synthetic",
            Path(tmp_path),
            allow_network=network,
            fixtures=fixtures,
        )


from standalone.evidence_pipeline.test_store import db as db  # noqa: E402


def test_two_actual_database_attempts_preserve_pinned_history_and_replay(
    db, tmp_path, monkeypatch
):
    import json
    from uuid import uuid4
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from backend.database.schema import verify
    from standalone.evidence_pipeline.test_public_inputs import nvd

    batch, job = binding()
    selection = RefreshSelection(batch)
    cve = "CVE-2099-" + str(uuid4().int)[:10]
    monkeypatch.setattr(type(batch), "active", lambda *args: (1, None))
    monkeypatch.setattr(RefreshSelection, "saved", lambda *args: [cve])
    scope = module.source_scope(batch, cve)
    later = replace(job, run_id=str(uuid4()))
    snapshots = []
    with db.cursor() as cur:
        verify(cur)
    for index, current_job in enumerate((job, later)):
        raw = nvd()
        raw["vulnerabilities"][0]["cve"]["id"] = cve
        raw["vulnerabilities"][0]["cve"]["descriptions"] = [
            {"lang": "en", "value": f"Synthetic refresh revision {index}"}
        ]
        if index:
            raw["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
                "cvssData"
            ].update(
                baseScore=8.8,
                baseSeverity="HIGH",
                vectorString="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            )
        root = tmp_path / current_job.run_id
        root.mkdir(mode=0o700)
        execution = module.attempt_id(current_job, scope)
        snap = module.prepare(
            scope,
            execution,
            root / execution,
            cve=cve,
            synthetic_payload=json.dumps(raw).encode(),
        )
        with db.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")
            if index == 0:
                authorize_connection(cur, snap)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        assert not persist_public(db, snap)["replayed"]
        snapshots.append(snap)
        with db.cursor() as cur:
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
            cur.execute(
                "SELECT score,receipt_id FROM evidence_pipeline.current_public_cvss_observations "
                "WHERE connection_id=%s AND cve_id=%s AND version='3.1'",
                (scope.connection_id, cve),
            )
            current = cur.fetchall()
            assert len(current) == 1
            assert str(current[0][0]) == ("9.8" if index == 0 else "8.8")
            cur.execute(
                "SELECT collection_attempt_id FROM evidence.observation_receipts WHERE id=%s",
                (current[0][1],),
            )
            assert str(cur.fetchone()[0]) == snap.execution_id
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert snapshots[0].input_fingerprint != snapshots[1].input_fingerprint
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        for current_job in (job, later):
            assert module.committed(cur, selection, current_job, "synthetic", tmp_path)
    original = module.prepare(
        scope,
        snapshots[0].execution_id,
        tmp_path / job.run_id / snapshots[0].execution_id,
        cve=cve,
        replay_only=True,
    )
    assert original.input_fingerprint == snapshots[0].input_fingerprint
    assert persist_public(db, original)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT score FROM evidence_pipeline.current_public_cvss_observations "
            "WHERE connection_id=%s AND cve_id=%s AND version='3.1'",
            (scope.connection_id, cve),
        )
        assert [str(row[0]) for row in cur.fetchall()] == ["8.8"]
        cur.execute(
            "SELECT a.id,v.score,rev.content_hash,rev.source_url,rev.licence_or_provenance "
            "FROM evidence.collection_attempts a "
            "JOIN evidence.observation_receipts r ON r.collection_attempt_id=a.id "
            "JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id "
            "JOIN evidence.cvss_observations v ON v.receipt_id=r.id "
            "WHERE a.connection_id=%s AND v.version='3.1' ORDER BY a.finished_at",
            (scope.connection_id,),
        )
        history = cur.fetchall()
        assert [str(row[0]) for row in history] == [s.execution_id for s in snapshots]
        assert [str(row[1]) for row in history] == ["9.8", "8.8"]
        assert len({row[2] for row in history}) == 2
        assert all(row[3] and row[4] for row in history)
