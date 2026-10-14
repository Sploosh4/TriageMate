"""Exact selection and unknown-preserving publication-age aggregation."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.test_msrc_publication_selection import publication
from . import msrc_age
from .repository_recipe import RepositoryRecipe
from .provider_monitor import ProviderPolicy


@pytest.mark.parametrize(
    "damage",
    [None, "unknown", "empty", "proof", "event", "contract", "missing", "digest"],
)
def test_discovery_clock_requires_exact_proof_and_every_clock(
    tmp_path, monkeypatch, damage
):
    scope = SourceScope(
        str(uuid4()),
        "MSRC",
        "repository",
        "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "synthetic",
        "TriageMate generated synthetic clock fixture",
    )
    recipe = RepositoryRecipe(
        scope, tmp_path, starting_month=None, retained_ids=frozenset()
    )
    assert ProviderPolicy(recipe, 86400).recipe == recipe
    run = str(uuid4())
    items = (
        [] if damage == "empty" else [publication("2099-Jan"), publication("2099-Feb")]
    )
    opened = []
    calls = []

    def saved(self, *args):
        if damage == "missing":
            raise OSError("synthetic absent bundle")

        def values():
            try:
                yield from items
            finally:
                opened.append("closed")

        calls.append(True)
        return (
            tmp_path,
            "changed" if damage == "digest" and len(calls) > 1 else "a" * 64,
            values(),
        )

    monkeypatch.setattr(msrc_age.MsrcProof, "saved_index", saved)
    checked = []

    def imports(self, cursor, bundle, origin, chosen_run, entries):
        checked.extend(entries)
        return damage != "proof"

    monkeypatch.setattr(msrc_age.MsrcProof, "imports_committed", imports)
    proof = msrc_age.MsrcProof(None, frozenset())
    event = proof.event(
        SimpleNamespace(input_id=scope.connection_id, run_id=run),
        scope.origin,
        "b" * 64,
        "a" * 64,
    )
    if damage == "event":
        event["input_id"] = str(uuid4())
    contract = "changed" if damage == "contract" else "b" * 64
    state = SimpleNamespace(
        definitions={scope.connection_id: SimpleNamespace(worker_contract=contract)}
    )
    monkeypatch.setattr(msrc_age.store, "load", lambda *args: (1, state))
    sealed = datetime(2099, 3, 1, tzinfo=timezone.utc)
    cursor = Mock()
    cursor.fetchone.return_value = (event, sealed)
    monkeypatch.setattr(
        msrc_age,
        "prepare",
        lambda *args, **kwargs: SimpleNamespace(
            complete=True, feed=lambda: kwargs["month"]
        ),
    )

    def clock(month):
        if damage == "unknown" and month == "2099-Feb":
            return None, None, None
        return (
            datetime(2099, 1 if month == "2099-Feb" else 2, 1, tzinfo=timezone.utc),
            "document_release",
            "timestamp",
        )

    monkeypatch.setattr(msrc_age, "provider_clock", clock)
    cache = {}
    result = msrc_age.read_clock(cursor, "synthetic-msrc-age", recipe, cache=cache)
    assert result["attempt_id"] == run
    assert result["collected_at"] == sealed.isoformat()
    assert result["health_basis"] == "sealed_collection_journal"
    assert result["health_time"] == (
        sealed.isoformat() if damage in (None, "unknown", "empty") else None
    )
    assert result["provider_time"] == (
        "2099-01-01T00:00:00+00:00" if damage is None else None
    )
    if damage is None:
        assert result["basis"] == "oldest_document_release"
        assert checked == items and len(opened) == 2
        assert (
            msrc_age.read_clock(cursor, "synthetic-msrc-age", recipe, cache=cache)
            == result
        )
        assert (
            len(calls) == 2
        )  # immutable successful run reused; age classified each tick
    if damage in {"proof", "event", "contract", "missing", "digest"}:
        assert not cache

    if damage is None:
        nested = tmp_path / run / "nested"
        nested.mkdir(parents=True)
        (nested / "proof.json").write_text("synthetic changed proof")
        monkeypatch.setattr(
            msrc_age.MsrcProof, "imports_committed", lambda *args: False
        )
        invalid = msrc_age.read_clock(cursor, "synthetic-msrc-age", recipe, cache=cache)
        assert invalid["health_time"] is None and invalid["provider_time"] is None
        assert not cache


def test_discovery_unknown_episode_resolves_without_duplicate_notice(tmp_path):
    from standalone.evidence_pipeline.runtime import local_database
    from .provider_monitor import record
    from .dispatch import Dispatcher
    from .store import save
    from .provider_notice import project

    scope = SourceScope(
        str(uuid4()),
        "MSRC",
        "repository",
        "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "synthetic",
        "TriageMate generated synthetic notification recovery",
    )
    policy = ProviderPolicy(RepositoryRecipe(scope, tmp_path), 86400)
    key = "synthetic-msrc-recovery-" + str(uuid4())
    now = datetime(2099, 3, 1, tzinfo=timezone.utc)
    observed = dict(
        attempt_id=str(uuid4()),
        collected_at=now.isoformat(),
        provider_time=None,
        basis=None,
        precision=None,
    )
    connection = local_database().connect()
    try:
        with connection.cursor() as cur:
            save(cur, key, 0, Dispatcher([], now=now))
            assert record(cur, key, policy, observed, now, 1)
            assert not record(cur, key, policy, observed, now, 1)
            cur.execute(
                "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s ORDER BY id",
                (key,),
            )
            first = cur.fetchone()[0]
            observed.update(
                attempt_id=str(uuid4()),
                provider_time=now.isoformat(),
                basis="oldest_document_release",
                precision="timestamp",
            )
            assert record(cur, key, policy, observed, now, 1)
            assert not record(cur, key, policy, observed, now, 1)
            cur.execute(
                "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s ORDER BY id",
                (key,),
            )
            events = [r[0] for r in cur.fetchall()]
            assert len(events) == 2
            before = project(key, first)
            after = project(key, events[1])
            assert before["status"] == "unresolved" and after["status"] == "resolved"
            assert before["id"] == after["id"] and after["synthetic"]
            assert (
                "Historical publications can be old after a fresh collection"
                in after["details"]["interpretation"]
            )
    finally:
        connection.rollback()
        connection.close()


def test_archive_refresh_and_collection_recovery_do_not_rewrite_publication_age(
    tmp_path,
):
    """Fresh retrieval of old releases resolves timeliness, not publisher age."""
    from datetime import timedelta
    from standalone.evidence_pipeline.runtime import local_database
    from .dispatch import Definition, Dispatcher
    from .lifecycle import Mode
    from .provider_monitor import record
    from .provider_notice import project
    from .scheduling import Interval
    from .store import save

    now = datetime(2099, 3, 1, tzinfo=timezone.utc)

    def at(seconds):
        return now + timedelta(seconds=seconds)

    scope = SourceScope(
        str(uuid4()),
        "MSRC",
        "repository",
        "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "synthetic",
        "TriageMate generated synthetic archive freshness fixture",
    )
    policy = ProviderPolicy(RepositoryRecipe(scope, tmp_path), 86400)
    key = "synthetic-msrc-archive-" + str(uuid4())
    state = Dispatcher(
        [Definition(scope.connection_id, Interval(10, now), overdue_after_seconds=25)],
        now=now,
    )
    state.request_mode(Mode.RUNNING, now)
    connection = local_database().connect()
    try:
        with connection.cursor() as cur:
            save(cur, key, 0, state)
            for tick in (10, 20):
                (job,) = state.tick(at(tick)).start
                state.finished(
                    job.run_id, success=True, snapshot_id=str(uuid4()), now=at(tick + 1)
                )
                assert not state.tick(at(tick + 1)).notices
                observation = dict(
                    attempt_id=job.run_id,
                    collected_at=at(tick + 1).isoformat(),
                    provider_time="2010-01-01T00:00:00+00:00",
                    basis="oldest_document_release",
                    precision="timestamp",
                )
                assert record(cur, key, policy, observation, at(tick + 1), 1)
            late = state.tick(at(46))
            opened = [n for n in late.notices if n.kind == "overdue_opened"]
            assert len(opened) == 1
            (job,) = late.start
            state.finished(job.run_id, success=False, now=at(47))
            assert not state.tick(at(47)).notices
            (job,) = state.tick(at(50)).start
            state.finished(
                job.run_id, success=True, snapshot_id=str(uuid4()), now=at(51)
            )
            resolved = [
                n for n in state.tick(at(51)).notices if n.kind == "overdue_resolved"
            ]
            assert len(resolved) == 1 and resolved[0].episode_id == opened[0].episode_id
            observation.update(attempt_id=job.run_id, collected_at=at(51).isoformat())
            assert record(cur, key, policy, observation, at(51), 1)
            cur.execute(
                "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s ORDER BY id",
                (key,),
            )
            events = [r[0] for r in cur.fetchall()]
            assert [e["kind"] for e in events] == [
                "provider_age_opened",
                "provider_age_updated",
                "provider_age_updated",
            ]
            assert len({e["episode_id"] for e in events}) == 1
            assert {e["provider_time"] for e in events} == {"2010-01-01T00:00:00+00:00"}
            note = project(key, events[-1])
            assert note["status"] == "unresolved" and note["synthetic"]
            assert (
                "Historical publications can be old after a fresh collection"
                in note["details"]["interpretation"]
            )
    finally:
        connection.rollback()
        connection.close()


@pytest.mark.parametrize("publication", ["2010-01-01T00:00:00+00:00", None])
@pytest.mark.parametrize("input_kind", ["repository", "security_updates", "advisories"])
def test_collection_health_resolves_old_episode_without_rewriting_publication(
    tmp_path, publication, input_kind
):
    import json
    from datetime import timedelta
    from .provider_monitor import record
    from .provider_notice import project
    from .process_worker import PublicRecipe

    now = datetime(2099, 3, 1, tzinfo=timezone.utc)
    scope = SourceScope(
        str(uuid4()),
        "MSRC",
        input_kind,
        "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
        "synthetic",
        "TriageMate generated synthetic collection health",
    )
    policy = ProviderPolicy(
        (RepositoryRecipe if input_kind == "repository" else PublicRecipe)(
            scope, tmp_path
        ),
        86400,
    )
    observed = dict(
        attempt_id=str(uuid4()),
        collected_at=now.isoformat(),
        provider_time=publication,
        basis=(
            "oldest_document_release"
            if input_kind == "repository"
            else "record_last_modified"
            if input_kind == "advisories"
            else "document_release"
        )
        if publication
        else None,
        precision="timestamp" if publication else None,
        health_time=now.isoformat(),
        health_basis="sealed_collection_journal"
        if input_kind == "repository"
        else "successful_collection",
    )
    cursor = Mock()
    cursor.fetchone.return_value = None
    assert not record(cursor, "synthetic-collection-health", policy, observed, now, 1)
    # Becoming overdue opens an episode even though the publication is unchanged.
    late = now + timedelta(days=2)
    assert record(cursor, "synthetic-collection-health", policy, observed, late, 1)
    opened = json.loads(cursor.execute.call_args.args[1][-1])
    assert opened["condition"] == "stale"
    before = project("synthetic-collection-health", opened)
    assert "verified collection exceeds" in before["message"]
    cursor.fetchone.return_value = (opened,)
    # A fresh complete collection resolves the same episode, even for an old or
    # unknown publisher clock. It never rewrites that publication evidence.
    observed.update(
        attempt_id=str(uuid4()),
        collected_at=late.isoformat(),
        health_time=late.isoformat(),
    )
    assert record(cursor, "synthetic-collection-health", policy, observed, late, 1)
    resolved = json.loads(cursor.execute.call_args.args[1][-1])
    after = project("synthetic-collection-health", resolved)
    assert before["id"] == after["id"] and after["status"] == "resolved"
    assert resolved["provider_time"] == publication
    assert "Publication age is shown separately" in after["details"]["interpretation"]
    # A retained legacy publication-age episode is also resolved under the new
    # collection-health policy, without deleting the old event.
    legacy = dict(opened)
    legacy.pop("health_time")
    legacy.pop("health_basis")
    cursor.fetchone.return_value = (legacy,)
    assert record(cursor, "synthetic-collection-health", policy, observed, late, 1)
    assert (
        json.loads(cursor.execute.call_args.args[1][-1])["episode_id"]
        == opened["episode_id"]
    )


@pytest.mark.parametrize(
    "damage", ["source", "basis", "seal", "missing-field", "false-condition"]
)
def test_collection_health_notification_rejects_unsupported_claims(damage):
    from .provider_notice import project

    event = dict(
        kind="provider_age_resolved",
        input_id=str(uuid4()),
        episode_id=str(uuid4()),
        at="2099-03-01T00:00:00+00:00",
        source="MSRC",
        input_kind="repository",
        scope_reference="https://example.invalid/synthetic",
        origin="synthetic",
        max_age_seconds=86400,
        condition="healthy",
        attempt_id=str(uuid4()),
        collected_at="2099-03-01T00:00:00+00:00",
        provider_time=None,
        basis=None,
        precision=None,
        health_time="2099-03-01T00:00:00+00:00",
        health_basis="sealed_collection_journal",
    )
    if damage == "source":
        event["source"] = "Cisco"
    elif damage == "basis":
        event["health_basis"] = "publisher_date"
    elif damage == "seal":
        event["health_time"] = "2099-02-28T23:59:59+00:00"
    elif damage == "missing-field":
        event.pop("health_basis")
    else:
        event["condition"] = "stale"
    with pytest.raises(ValueError):
        project("synthetic-collection-health", event)
