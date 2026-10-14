"""Generated repository health fixtures; no actual lab identifiers or payloads."""

from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.contracts import SourceScope
from . import repository_age
from .provider_monitor import ProviderPolicy, record
from .provider_notice import project
from .repository_recipe import RepositoryRecipe, SOURCE_URLS

NOW = datetime(2099, 3, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("source", sorted(repository_age.SOURCES))
@pytest.mark.parametrize(
    "damage",
    [
        None,
        "checkpoint",
        "input",
        "definition",
        "failed",
        "run",
        "time",
        "publication",
        "missing",
        "corrupt",
        "unknown-date",
        "empty",
    ],
)
def test_repository_health_requires_checkpoint_and_complete_publication(
    tmp_path, monkeypatch, source, damage
):
    scope = SourceScope(
        str(uuid4()),
        source,
        "repository",
        SOURCE_URLS[source],
        "synthetic",
        "TriageMate generated synthetic repository health fixture",
    )
    recipe = RepositoryRecipe(scope, tmp_path)
    assert ProviderPolicy(recipe, 86400).recipe == recipe
    run = str(uuid4())
    observed = SimpleNamespace(
        latest_success=damage != "failed",
        latest_snapshot=None if damage == "run" else run,
        last_success_at=None if damage == "time" else NOW,
    )
    state = SimpleNamespace(
        definitions={}
        if damage == "definition"
        else {scope.connection_id: SimpleNamespace(worker_contract="a" * 64)},
        inputs={} if damage == "input" else {scope.connection_id: observed},
    )
    monkeypatch.setattr(
        repository_age.store,
        "load",
        lambda *args: None if damage == "checkpoint" else (1, state),
    )
    proof = Mock(return_value=damage != "publication")
    if damage in {"missing", "corrupt"}:
        proof.side_effect = (
            OSError("synthetic missing bundle")
            if damage == "missing"
            else ValueError("synthetic corrupt publication")
        )
    monkeypatch.setattr(repository_age, "published_run", proof)
    reads = []

    @contextmanager
    def dates(cursor, query, parameters):
        reads.append(parameters)
        assert parameters == (source, "synthetic", run)
        yield iter(
            []
            if damage == "empty"
            else [
                ("2010-01-01T00:00:00Z",),
                (None if damage == "unknown-date" else "2011-01-01T00:00:00",),
            ]
        )

    monkeypatch.setattr(repository_age, "streamed_rows", dates)
    cache = {}
    cursor = Mock()
    result = repository_age.read_clock(cursor, "synthetic-health", recipe, cache=cache)
    valid = damage in {None, "unknown-date", "empty"}
    assert result["health_time"] == (NOW.isoformat() if valid else None)
    assert result["health_basis"] == repository_age.HEALTH_BASIS
    assert result["provider_time"] == (
        "2010-01-01T00:00:00+00:00"
        if valid and damage is None and source != "WA SOC"
        else None
    )
    assert bool(cache) is valid
    if valid:
        assert proof.call_args.kwargs == dict(origin="synthetic", execution_id=run)
        assert proof.call_args.args == (cursor, source, tmp_path)
        assert bool(reads) is (source != "WA SOC")
        assert (
            repository_age.read_clock(cursor, "synthetic-health", recipe, cache=cache)
            == result
        )
        assert proof.call_count == 1
        # A changed configured contract must revalidate; prior proof cannot bless it.
        state.definitions[scope.connection_id].worker_contract = "b" * 64
        repository_age.read_clock(cursor, "synthetic-health", recipe, cache=cache)
        assert proof.call_count == 2
        # Failure after success cannot reuse cached health or an older snapshot.
        observed.latest_success = False
        assert (
            repository_age.read_clock(cursor, "synthetic-health", recipe, cache=cache)[
                "health_time"
            ]
            is None
        )

    if damage is None:
        observed.latest_success = True
        nested = tmp_path / run / "nested"
        nested.mkdir(parents=True)
        (nested / "proof.json").write_text("synthetic changed proof")
        proof.return_value = False
        invalid = repository_age.read_clock(
            cursor, "synthetic-health", recipe, cache=cache
        )
        assert invalid["health_time"] is None and invalid["provider_time"] is None
        assert all(key[-1] != "b" * 64 for key in cache)


@pytest.mark.parametrize("source", sorted(repository_age.SOURCES))
def test_repository_age_episode_recovers_without_rewriting_publication(
    tmp_path, source
):
    import json

    scope = SourceScope(
        str(uuid4()),
        source,
        "repository",
        SOURCE_URLS[source],
        "synthetic",
        "TriageMate generated synthetic repository recovery fixture",
    )
    policy = ProviderPolicy(RepositoryRecipe(scope, tmp_path), 86400)
    clock = NOW - timedelta(days=2)
    observation = dict(
        attempt_id=str(uuid4()),
        collected_at=clock.isoformat(),
        health_time=clock.isoformat(),
        health_basis=repository_age.HEALTH_BASIS,
        provider_time=None if source == "WA SOC" else "2010-01-01T00:00:00+00:00",
        basis=None if source == "WA SOC" else "record_last_modified",
        precision=None if source == "WA SOC" else "timestamp",
    )
    cursor = Mock()
    cursor.fetchone.return_value = None
    assert record(cursor, "synthetic-health", policy, observation, NOW, 1)
    opened = json.loads(cursor.execute.call_args.args[1][-1])
    before = project("synthetic-health", opened)
    assert before["status"] == "unresolved"
    cursor.fetchone.return_value = (opened,)
    observation.update(
        attempt_id=str(uuid4()),
        collected_at=NOW.isoformat(),
        health_time=NOW.isoformat(),
    )
    assert record(cursor, "synthetic-health", policy, observation, NOW, 1)
    resolved = json.loads(cursor.execute.call_args.args[1][-1])
    after = project("synthetic-health", resolved)
    assert after["id"] == before["id"] and after["status"] == "resolved"
    assert resolved["provider_time"] == opened["provider_time"]
    assert "Publication age is shown separately" in after["details"]["interpretation"]
    resolved["health_basis"] = "unverified-success"
    with pytest.raises(ValueError, match="clock meaning"):
        project("synthetic-health", resolved)


@pytest.mark.parametrize("source", ["GitHub", "Ubuntu", "Cisco", "Red Hat"])
def test_new_repository_health_does_not_activate_deferred_sources(tmp_path, source):
    scope = SourceScope(
        str(uuid4()),
        source,
        "repository",
        SOURCE_URLS[source],
        "synthetic",
        "TriageMate generated synthetic deferred boundary fixture",
    )
    with pytest.raises(ValueError, match="Unsupported repository"):
        repository_age.read_clock(
            Mock(), "synthetic-health", RepositoryRecipe(scope, tmp_path)
        )
