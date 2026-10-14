"""Pinned target manifests drive existing Catalog collection and exact proofs."""

import json
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.collection.catalog_targets import CatalogTargets
from standalone.evidence_pipeline.test_catalog_discovery import empty_payload
from . import catalog_target_worker as worker


@pytest.fixture
def selection(tmp_path, monkeypatch):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    bindings = {str(uuid4()): str(uuid4())}
    targets = CatalogTargets(tuple(bindings.items()), ("KB9999991", "KB9999992"), 0)

    def select(cursor, snapshots, *, origin, maximum):
        assert snapshots == bindings and origin == "synthetic" and maximum == 100
        return targets

    monkeypatch.setattr(worker, "select_targets", select)
    return dict(
        root=root,
        run_id=str(uuid4()),
        snapshots=bindings,
        origin="synthetic",
        fixtures={kb: (empty_payload(kb), {}) for kb in targets.kbs},
    )


def test_selected_searches_collect_and_replay_with_exact_proofs(selection):
    from unittest.mock import patch

    with patch(
        "http.client.HTTPSConnection", side_effect=AssertionError("Synthetic network")
    ):
        first = worker.collect_targets(**selection)
        assert first["complete"] and len(first["outcomes"]) == 2
        assert all(row["verified"] for row in first["outcomes"])
        assert worker.collect_targets(**selection) == first
    path = selection["root"] / selection["run_id"] / "targets.json"
    assert path.stat().st_mode & 0o077 == 0
    raw = json.loads(path.read_text())
    raw["selection"]["kbs"] = []
    path.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="changed"):
        worker.collect_targets(**selection)


@pytest.mark.parametrize(
    "damage", ["network", "missing_fixture", "extra_fixture", "budget", "relative"]
)
def test_invalid_authority_or_membership_makes_no_requests(
    selection, damage, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid request reached collection")

    monkeypatch.setattr(worker, "collect_batch", forbidden)
    if damage == "network":
        selection["allow_network"] = True
    elif damage == "missing_fixture":
        selection["fixtures"].pop("KB9999992")
    elif damage == "extra_fixture":
        selection["fixtures"]["KB9999993"] = (empty_payload("KB9999993"), {})
    elif damage == "budget":
        selection["record_limit"] = 0
    else:
        selection["root"] = "relative"
    with pytest.raises(ValueError):
        worker.collect_targets(**selection)


def test_failed_child_cannot_acknowledge_remaining_targets(selection, monkeypatch):
    from .redhat_worker import BatchResult

    calls = []

    def fail(*args, **kwargs):
        calls.append(kwargs["kb"])
        return BatchResult("collection_failed", 1, 0, None)

    monkeypatch.setattr(worker, "collect_batch", fail)
    result = worker.collect_targets(**selection)
    assert not result["complete"] and calls == ["KB9999991"]
    assert result["selection"]["kbs"] == ["KB9999991", "KB9999992"]
    assert result["outcomes"][0]["verified"] is False


@pytest.mark.parametrize("fail_first", [False, True])
def test_persisted_missing_patch_drives_nonempty_catalog_collection(
    tmp_path, fail_first
):
    from dataclasses import replace
    from unittest.mock import patch
    from standalone.evidence_pipeline.commands import register, ingest, ingest_exposure
    from standalone.evidence_pipeline.test_devices import make
    from standalone.evidence_pipeline.test_commands import cleanup
    from standalone.evidence_pipeline.test_exposure_commands import remove_exposure
    from standalone.evidence_pipeline.test_catalog_discovery import payload, row, ID
    from standalone.evidence_pipeline.test_update_catalog import payload as detail
    from standalone.evidence_pipeline.collection.catalog_collection import catalog_scope
    from standalone.evidence_pipeline.parsing.update_catalog import endpoint
    from standalone.evidence_pipeline.runtime import local_database

    native, update = str(uuid4()), str(uuid4())
    device = make("Defender", [{"id": native}])
    missing = replace(
        device,
        execution_id=str(uuid4()),
        scope=replace(
            device.scope, connection_id=str(uuid4()), input_kind="missing_patches"
        ),
        payload=json.dumps([{"machineId": native, "id": "KB9999991"}]).encode(),
    )
    scope = catalog_scope("synthetic", endpoint(update))
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    options = dict(
        root=root,
        run_id=str(uuid4()),
        snapshots={missing.scope.connection_id: missing.execution_id},
        origin="synthetic",
        fixtures={
            "KB9999991": (
                payload(row(update)),
                {update: detail().replace(ID.encode(), update.encode())},
            )
        },
    )
    try:
        register(device.scope)
        ingest(device)
        register(missing.scope, device_connection_id=device.scope.connection_id)
        ingest_exposure(missing, device.execution_id)
        with patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("Synthetic network"),
        ):
            if fail_first:
                broken = dict(
                    options,
                    run_id=str(uuid4()),
                    fixtures={
                        "KB9999991": (
                            payload(row(update)),
                            {update: b"invalid synthetic detail"},
                        )
                    },
                )
                failed = worker.collect_targets(**broken)
                assert not failed["complete"]
                assert failed["outcomes"][0]["verified"] is False
            result = worker.collect_targets(**options)
            assert result["complete"] and result["outcomes"][0]["verified"]
            assert worker.collect_targets(**options) == result
        from .catalog_target_proof import ScheduledCatalogTargets
        from .dispatch import Job

        proof = ScheduledCatalogTargets(
            str(uuid4()), "a" * 64, "synthetic", root, (missing.scope.connection_id,)
        )
        job = Job(
            options["run_id"],
            proof.input_id,
            missing.finished_at,
            missing.finished_at,
            tuple(options["snapshots"].items()),
        )
        with local_database().connect() as conn, conn.cursor() as cur:
            declaration = proof.evidence(cur, job)
            assert declaration["run_id"] == options["run_id"]
            assert len(declaration["indexes"]) == 1
            assert declaration["indexes"][0]["kb"] == "KB9999991"
            assert proof.evidence(cur, job) == declaration
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute("SET LOCAL ROLE tm_mock_reader")
            cur.execute(
                "SELECT count(*) FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
                (scope.connection_id,),
            )
            assert cur.fetchone() == (1,)
            cur.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=%s",
                (scope.connection_id,),
            )
            assert cur.fetchone() == (2 if fail_first else 1,)
    finally:
        # Only the generated source UUIDs and synthetic update identity belong to this test.
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions s ON s.id=r.source_revision_id WHERE s.connection_id=%s)",
                (scope.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                (scope.connection_id,),
            )
        cleanup(scope)
        remove_exposure(missing.scope)
        cleanup(device.scope)
