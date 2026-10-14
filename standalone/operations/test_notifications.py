"""Stable overlap episodes, safe generated notes and committed-event projection."""

from contextlib import closing
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.runtime import local_database
from .notifications import load, project
from .supervisor import PostgresRepository
from .test_checkpoint import running_state
from .test_dispatch import at

pytestmark = pytest.mark.xdist_group("retained_evidence_schema")


def event(kind="overlap_opened", count=2):
    return dict(
        kind=kind,
        input_id="synthetic-input",
        original_run_id="synthetic-run",
        skipped_count=count,
        at=at(1801).isoformat(),
    )


def test_episode_identity_survives_updates_and_resolution_and_is_service_scoped():
    args = (
        "Synthetic source",
        "devices",
        "Synthetic scope",
        "evidence-pipeline-v1:synthetic:test",
    )
    first = project("synthetic-service", event(), *args)
    updated = project("synthetic-service", event("overlap_updated", 5), *args)
    resolved = project("synthetic-service", event("overlap_resolved", 5), *args)
    other = project("other-service", event(), *args)
    assert first["id"] == updated["id"] == resolved["id"] != other["id"]
    assert first["status"] == "unresolved" and resolved["status"] == "resolved"
    assert first["synthetic"] and first["urgency"] == "moderate"
    assert first["details"]["skipped_count"] == 2
    assert "not assumed to be hourly" in first["details"]["interpretation"]
    assert (
        "subsequent scheduled collection completed"
        in resolved["details"]["interpretation"]
    )


@pytest.mark.parametrize(
    "change",
    [
        {"skipped_count": 1},
        {"skipped_count": True},
        {"kind": "invented"},
        {"at": "2026-09-15"},
        {"original_run_id": ""},
    ],
)
def test_invalid_events_cannot_publish_notifications(change):
    with pytest.raises(ValueError):
        project("synthetic", {**event(), **change}, None, None, None, None)


def test_provider_text_remains_plain_structured_data():
    injected = "\n```sql\nSELECT 'injected';\n```\n[link](https://example.invalid)"
    record = project("synthetic", event(), injected, "devices", injected, None)
    assert record["parameters"] == {"api": injected, "organisation": injected}
    assert record["details"]["input_id"] == event()["input_id"]
    assert record["page"].startswith("System/TriageMate/Notifiations/operation-")


@pytest.mark.parametrize("origin", ["synthetic", "public"])
@pytest.mark.parametrize("source", ["Ubuntu", "Red Hat"])
def test_repository_event_retains_source_without_native_connection(origin, source):
    from .repository_recipe import SOURCE_URLS

    notice = {**event(), "repository_scope": {"source": source, "origin": origin}}
    record = project("synthetic-service", notice, None, None, None, None)
    assert record["synthetic"] is (origin == "synthetic")
    assert record["message"].startswith(source + " repository:")
    assert SOURCE_URLS[source] == record["parameters"]["organisation"]
    assert record["details"]["repository_scope"] == notice["repository_scope"]
    assert "repository_scope" in notice


@pytest.mark.parametrize("origin", ["synthetic", "public"])
def test_enrichment_notification_preserves_source_and_origin(origin):
    notice = {**event(), "enrichment_scope": {"source": "NVD", "origin": origin}}
    record = project("synthetic-service", notice, None, None, None, None)
    assert record["synthetic"] is (origin == "synthetic")
    assert record["message"].startswith("NVD enrichment:")
    assert record["parameters"]["organisation"] == "triagemate:enrichment/NVD"
    assert record["details"]["enrichment_scope"] == notice["enrichment_scope"]


def test_committed_events_update_one_notification_and_resolve_after_later_success():
    key = "synthetic-notification-" + str(uuid4())
    repository = PostgresRepository(key)
    state = running_state()
    try:
        actions = state.tick(at(1801))
        assert len(actions.notices) == 1
        assert load(key) == []
        revision = repository.commit(0, state, actions.notices)
        [opened] = load(key)
        assert opened["status"] == "unresolved"
        assert opened["details"]["skipped_count"] == 2
        (job,) = state.tick(at(2400)).start
        state.finished(
            job.run_id, success=True, snapshot_id="synthetic-success", now=at(2401)
        )
        actions = state.tick(at(2401))
        assert actions.notices[0].kind == "overlap_resolved"
        # Not visible until the changed checkpoint and event commit together.
        assert load(key)[0]["status"] == "unresolved"
        repository.commit(revision, state, actions.notices)
        [resolved] = load(key)
        assert resolved["id"] == opened["id"]
        assert resolved["status"] == "resolved"
        assert load("another-synthetic-service") == []
    finally:
        with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )


@pytest.mark.parametrize(
    "mode,expected", [(None, "catalog_search"), ("targets", "catalog_targets")]
)
def test_catalog_operational_notice_retains_actual_input_kind(mode, expected):
    reference = dict(source="Microsoft Update Catalog", origin="public")
    reference.update(dict(kb="KB9999991") if mode is None else dict(mode=mode))
    notice = dict(event(), repository_scope=reference)
    record = project("catalog-kind", notice, None, None, None, None)
    assert record["message"].startswith("Microsoft Update Catalog " + expected + ":")
    assert expected in record["message"]
