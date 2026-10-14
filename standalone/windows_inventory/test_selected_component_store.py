"""Synthetic selected capture history and exact inventory association guards."""

from dataclasses import replace
import io
import json
from uuid import uuid4

import psycopg2
import pytest

from backend.database.schema import verify
from standalone.evidence_pipeline.persistence.store import atomic
from standalone.evidence_pipeline.test_store import db as db, snapshot as snapshot

from .selected_component_store import persist
from .snapshot import InventoryAttempt
from .staging import stage
from .store import persist as persist_inventory
from .test_component_check import case
from .test_component_snapshot import sample_selected
from .test_store import configured as configured


@pytest.fixture
def evidence(db, configured):
    device, selected, binding = configured
    with db.cursor() as cur:
        verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    full, _, _ = case()
    data = json.loads(full)
    capture, _ = sample_selected()
    for document in (data, capture):
        document.update(
            machine_guid=binding.machine_guid,
            tenant_id=binding.tenant_id,
            device_id=binding.device_id,
        )
    with stage(io.BytesIO(json.dumps(data).encode()), binding) as staged:
        attempt = InventoryAttempt.from_staged(selected, str(uuid4()), staged)
        persist_inventory(
            db, attempt, staged=staged, device_attempt_id=device.execution_id
        )
    return attempt, binding, capture


def test_selected_capture_replay_retains_bytes_and_separate_observation_time(
    db, evidence
):
    attempt, binding, capture = evidence
    raw = json.dumps(capture).encode()
    first = persist(db, attempt.execution_id, raw, binding=binding, origin="synthetic")
    assert first["associated"] == 1 and first["records"] == 1 and not first["replayed"]
    assert persist(
        db, attempt.execution_id, raw, binding=binding, origin="synthetic"
    ) == dict(first, replayed=True)
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(
            "SELECT capture,report FROM evidence_pipeline.selected_component_checks WHERE id=%s",
            (first["check_id"],),
        )
        stored, report = cur.fetchone()
        assert bytes(stored) == raw
        assert report["rows"][0]["state"] == "unknown"
        assert (
            report["rows"][0]["inventory_association"]
            == "exact_identity_and_version_only"
        )
        assert report["defender_coverage"] == "unverified"
        cur.execute(
            "SELECT component_observed_at,inventory_collected_at FROM evidence_pipeline.selected_component_history WHERE check_id=%s",
            (first["check_id"],),
        )
        observed, inventory_time = cur.fetchone()
        assert observed != inventory_time.isoformat()


def test_conflicting_version_stays_unassociated_and_preserves_capture(db, evidence):
    attempt, binding, capture = evidence
    capture["rows"][0]["version"] = "9.9.9.9"
    raw = json.dumps(capture).encode()
    result = persist(db, attempt.execution_id, raw, binding=binding, origin="synthetic")
    assert result["associated"] == 0
    with db.cursor() as cur:
        cur.execute(
            "SELECT result FROM evidence_pipeline.selected_component_history WHERE check_id=%s",
            (result["check_id"],),
        )
        row = cur.fetchone()[0]
        assert row["inventory_receipt_id"] is None
        assert row["state"] == "unknown"
        assert row["manifest_evidence"]["state"] != "read"


def test_wrong_device_or_origin_rejected(db, evidence):
    attempt, binding, capture = evidence
    raw = json.dumps(capture).encode()
    for actual, origin in (
        (replace(binding, device_id=str(uuid4())), "synthetic"),
        (binding, "lab"),
    ):
        with pytest.raises(ValueError):
            persist(db, attempt.execution_id, raw, binding=actual, origin=origin)


def test_empty_selected_observation_preserves_missing_names(db, evidence):
    attempt, binding, capture = evidence
    capture["rows"] = []
    # The contract requires explicit accounting rather than dropping rows.
    with pytest.raises(ValueError):
        persist(
            db,
            attempt.execution_id,
            json.dumps(capture).encode(),
            binding=binding,
            origin="synthetic",
        )


def test_writer_cannot_modify_selected_evidence(db, evidence):
    attempt, binding, capture = evidence
    result = persist(
        db,
        attempt.execution_id,
        json.dumps(capture).encode(),
        binding=binding,
        origin="synthetic",
    )
    with db.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            with atomic(cur):
                cur.execute(
                    "UPDATE evidence_pipeline.selected_component_checks SET capture=%s WHERE id=%s",
                    (b"bad", result["check_id"]),
                )


def test_explicit_not_observed_capture_remains_visible(db, evidence):
    attempt, binding, capture = evidence
    name = capture["requested_names"][0]
    capture["rows"] = [
        dict(name=name, state="not_observed", observed_at=capture["finished_at"])
    ]
    result = persist(
        db,
        attempt.execution_id,
        json.dumps(capture).encode(),
        binding=binding,
        origin="synthetic",
    )
    assert result["records"] == 0
    with db.cursor() as cur:
        cur.execute(
            "SELECT not_observed,result,defender_coverage FROM evidence_pipeline.selected_component_history WHERE check_id=%s",
            (result["check_id"],),
        )
        assert cur.fetchall() == [([name], None, "unverified")]


@pytest.mark.parametrize("missing", [False, True])
def test_shipped_selected_query_keeps_unknown_and_missing_evidence(
    db, evidence, missing
):
    from standalone.evidence_pipeline.test_inventory_status_page import page_queries

    attempt, binding, capture = evidence
    if missing:
        capture["rows"] = [
            dict(
                name=capture["requested_names"][0],
                state="not_observed",
                observed_at=capture["finished_at"],
            )
        ]
    saved = persist(
        db,
        attempt.execution_id,
        json.dumps(capture).encode(),
        binding=binding,
        origin="synthetic",
    )
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        cur.execute(page_queries()[4])
        rows = [
            dict(zip([c.name for c in cur.description], row)) for row in cur.fetchall()
        ]
    selected = [row for row in rows if str(row["check_id"]) == saved["check_id"]]
    assert len(selected) == 1
    row = selected[0]
    assert row["defender_coverage"] == "unverified"
    if missing:
        assert row["components_not_observed"] == capture["requested_names"]
        assert row["inventory_association"] == "Requested components not observed"
        assert row["overall_applicability"] is None
    else:
        assert row["overall_applicability"] == "unknown"
        assert row["inventory_receipt"] is not None
        assert row["component_observed_at"] != row["inventory_collected_at"].isoformat()


@pytest.mark.parametrize("commit_fails", [False, True])
def test_cli_acknowledges_only_committed_results(monkeypatch, capsys, commit_fails):
    from . import selected_component_commands as cli

    events = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, kind, value, traceback):
            events.append("commit")
            if commit_fails:
                raise psycopg2.OperationalError("private connection details")

        def close(self):
            events.append("close")

    def save(*args, **kwargs):
        assert capsys.readouterr().out == ""
        events.append("persist")
        return {"replayed": False, "records": 1}

    monkeypatch.setattr(cli, "connect", Connection)
    monkeypatch.setattr(cli, "selected_file_inputs", lambda **kwargs: {})
    monkeypatch.setattr(cli, "persist", save)
    args = ["--inventory-snapshot", "synthetic"]
    for flag in ("selected", "binding", "evidence", "sources"):
        args += ["--" + flag, "synthetic"]
    if commit_fails:
        with pytest.raises(SystemExit) as error:
            cli.main(args)
        assert error.value.code == 2
        output = capsys.readouterr()
        assert output.out == ""
        assert "private connection details" not in output.err
        assert "import failed" in output.err
    else:
        cli.main(args)
        assert json.loads(capsys.readouterr().out) == {"replayed": False, "records": 1}
    assert events == ["persist", "commit", "close"]


@pytest.mark.parametrize(
    "version", ["pipeline-windows-os-native-facts-v113", "unknown", None]
)
def test_selected_writer_refuses_unsupported_version(db, evidence, version):
    from .test_store import unsupported_version

    attempt, binding, capture = evidence
    with unsupported_version(db, version):
        persist(
            db,
            attempt.execution_id,
            json.dumps(capture).encode(),
            binding=binding,
            origin="synthetic",
        )


def test_predecessor_selected_engine_replays_without_new_history(
    db, evidence, monkeypatch
):
    from . import selected_component_store
    from .test_engine_identity import SELECTED

    attempt, binding, capture = evidence
    raw = json.dumps(capture).encode()
    with monkeypatch.context() as patch:
        patch.setattr(selected_component_store, "engine_fingerprint", lambda: SELECTED)
        before = persist(
            db, attempt.execution_id, raw, binding=binding, origin="synthetic"
        )
    after = persist(db, attempt.execution_id, raw, binding=binding, origin="synthetic")
    assert after == dict(before, replayed=True)
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence_pipeline.selected_component_checks")
        assert cur.fetchone() == (1,)
    with monkeypatch.context() as patch:
        patch.setattr(selected_component_store, "engine_fingerprint", lambda: "f" * 64)
        changed = persist(
            db, attempt.execution_id, raw, binding=binding, origin="synthetic"
        )
    assert changed["check_id"] != before["check_id"]
    assert not changed["replayed"]
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence_pipeline.selected_component_checks")
        assert cur.fetchone() == (2,)
