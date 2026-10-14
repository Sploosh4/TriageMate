"""Generated discovery-to-CVRF bundles; network and database writes are mocked."""

import json
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.collection import (
    msrc_discovered_collection as collector,
)
from standalone.evidence_pipeline.collection import (
    public_collection,
    msrc_index_collection,
)
from .test_msrc_publications import entry, CONTEXT
from .test_cvrf_updates import document


def options():
    return dict(
        origin="synthetic",
        execution_id=str(uuid4()),
        starting_month="2099-Mar",
        retained_ids=frozenset(),
        synthetic_index=json.dumps(
            {
                "@odata.context": CONTEXT,
                "value": [entry("2099-Jan"), entry("2099-Mar"), entry("2099-Apr")],
            }
        ).encode(),
    )


@pytest.fixture(autouse=True)
def no_external_effects(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unexpected network/database mutation")

    monkeypatch.setattr(public_collection, "download", forbidden)
    monkeypatch.setattr(msrc_index_collection, "_download_url", forbidden)
    monkeypatch.setattr(collector, "register", forbidden)
    monkeypatch.setattr(collector, "ingest_public", forbidden)


def test_monthly_bundles_transform_and_replay_with_exact_continuation(tmp_path):
    root = tmp_path / "run"
    args = options()
    args["synthetic_payloads"] = {
        month: json.dumps(document()).encode() for month in ("2099-Mar", "2099-Apr")
    }
    first = collector.collect(root, **args, limit=1)
    assert first["remaining"] == 1 and first["next_after"] == "2099-Mar"
    assert first["outcomes"][0]["outcome"] == "success"
    assert first["outcomes"][0]["database_imported"] is False
    second = collector.collect(root, **args, after=first["next_after"])
    assert second["remaining"] == 0 and second["next_after"] is None
    assert second["outcomes"][0]["native_id"] == "2099-Apr"
    args.pop("synthetic_index")
    args.pop("synthetic_payloads")
    replay = collector.collect(root, **args, replay_only=True)
    assert [row["outcome"] for row in replay["outcomes"]] == ["success", "success"]
    assert replay["outcomes"] == first["outcomes"] + second["outcomes"]


def test_failed_or_missing_children_do_not_become_success_on_replay(tmp_path):
    root, args = tmp_path / "run", options()
    first = collector.collect(root, **args, synthetic_payloads={"2099-Mar": b"{}"})
    assert first["outcomes"][0]["outcome"] != "success"
    assert first["outcomes"][1]["outcome"] == "pending"
    replay = collector.collect(root, **args, replay_only=True)
    assert replay == first


def test_changed_policy_and_unknown_cursor_rejected_before_children(tmp_path):
    root, args = tmp_path / "run", options()
    collector.collect(root, **args)
    with pytest.raises(ValueError, match="differs"):
        collector.collect(root, **{**args, "starting_month": None})
    with pytest.raises(ValueError, match="membership"):
        collector.collect(root, **args, after="2099-Jan")
    with pytest.raises(ValueError, match="membership"):
        collector.collect(root, **args, synthetic_payloads={"2099-Jan": b"{}"})


@pytest.mark.parametrize(
    "change",
    [
        {"origin": "public"},
        {"allow_network": True},
        {"limit": True},
        {"starting_month": "all"},
        {"retained_ids": []},
    ],
)
def test_invalid_authority_or_range_has_no_filesystem_effect(tmp_path, change):
    root = tmp_path / "run"
    with pytest.raises(ValueError):
        collector.collect(root, **{**options(), **change})
    assert not root.exists()


def test_committed_flag_uses_import_outcome_not_merely_call_completion(
    tmp_path, monkeypatch
):
    args = options()
    observed = []
    monkeypatch.setattr(collector, "register", lambda scope: observed.append(scope))
    monkeypatch.setattr(
        collector,
        "ingest_public",
        lambda snapshot: dict(outcome="failure", replayed=False),
    )
    result = collector.collect(
        tmp_path / "run",
        **args,
        synthetic_payloads={"2099-Mar": b"{}"},
        import_records=True,
    )
    assert len(observed) == 1
    assert observed[0].scope_reference.endswith("/2099-Mar")
    assert result["outcomes"][0]["database_imported"] is False


def test_precancelled_discovery_leaves_no_bundle(tmp_path):
    root = tmp_path / "run"
    with pytest.raises(ValueError, match="cancelled"):
        collector.collect(root, **options(), cancelled=lambda: True)
    assert not root.exists()


def test_new_run_reconsiders_unchanged_index_with_stable_scopes(tmp_path, monkeypatch):
    scopes, attempts = [], []
    monkeypatch.setattr(collector, "register", lambda scope: scopes.append(scope))

    def imported(snapshot):
        attempts.append(snapshot.execution_id)
        # Exhaust the actual transformed CVRF evidence before claiming success.
        from standalone.evidence_pipeline.parsing.public_records import normalize_public

        assert len(list(normalize_public(snapshot.feed()))) == 1
        return dict(outcome="success", replayed=False)

    monkeypatch.setattr(collector, "ingest_public", imported)
    args = options()
    args["synthetic_payloads"] = {"2099-Mar": json.dumps(document()).encode()}
    first = collector.collect(tmp_path / "first", **args, import_records=True, limit=1)
    args["execution_id"] = str(uuid4())
    second = collector.collect(
        tmp_path / "second", **args, import_records=True, limit=1
    )
    assert scopes[0] == scopes[1]
    assert attempts[0] != attempts[1]
    assert first["outcomes"][0]["database_imported"] is True
    assert second["outcomes"][0]["database_imported"] is True


def test_invalid_index_never_starts_child_imports(tmp_path):
    args = {**options(), "synthetic_index": b'{"value":[],"unexpected":true}'}
    result = collector.collect(tmp_path / "run", **args, import_records=True)
    assert result["index_complete"] is False
    assert result["outcomes"] == ()
    assert result["index_error"] == "invalid_msrc_index"


def test_empty_publication_discovery_import_and_offline_replay(tmp_path, monkeypatch):
    from .test_cvrf_stream import empty_publication
    from standalone.evidence_pipeline.parsing.public_records import normalize_public

    value = empty_publication()
    value["DocumentTracking"]["Identification"]["ID"]["Value"] = "2099-Mar"
    imported = []
    monkeypatch.setattr(collector, "register", lambda scope: None)

    def ingest(snapshot):
        assert snapshot.complete
        assert list(normalize_public(snapshot.feed())) == []
        imported.append(snapshot.input_fingerprint)
        return dict(outcome="success", replayed=len(imported) > 1)

    monkeypatch.setattr(collector, "ingest_public", ingest)
    args = options()
    result = collector.collect(
        tmp_path / "run",
        **args,
        limit=1,
        import_records=True,
        synthetic_payloads={"2099-Mar": json.dumps(value).encode()},
    )
    assert result["outcomes"][0]["database_imported"]
    args.pop("synthetic_index")
    replay = collector.collect(
        tmp_path / "run", **args, limit=1, import_records=True, replay_only=True
    )
    assert replay["outcomes"][0]["database_imported"]
    assert replay["outcomes"][0]["replayed"]
    assert len(imported) == 2 and imported[0] == imported[1]
