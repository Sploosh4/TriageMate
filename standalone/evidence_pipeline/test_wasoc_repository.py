"""Complete pinned WA SOC discovery, document collection and offline reconstruction."""

from backend.database import schema as database_schema

import json
from uuid import uuid4
import pytest
from .test_store import db as database_fixture
from standalone.evidence_pipeline.collection.cve_repository import collect
from .test_wasoc_discovery import COMMIT, TREE, PATH, BODY, payloads

db = database_fixture


def fixtures():
    commit, tree = payloads()
    return {
        ("ref", "heads/main"): json.dumps(
            dict(ref="refs/heads/main", object=dict(type="commit", sha=COMMIT))
        ).encode(),
        ("commits", COMMIT): commit,
        ("trees", TREE): tree,
    }, {PATH: BODY}


@pytest.mark.parametrize("missing", [False, True])
def test_full_saved_membership_and_replay_are_distinct_from_database_proof(
    tmp_path, monkeypatch, missing
):
    metadata, documents = fixtures()
    if missing:
        documents.clear()
    monkeypatch.setattr(
        "standalone.evidence_pipeline.collection.public_collection.download",
        lambda *a, **kw: pytest.fail("Synthetic/replay contacted network"),
    )
    run = str(uuid4())
    result = collect(
        "WA SOC",
        tmp_path / "run",
        origin="synthetic",
        execution_id=run,
        synthetic_objects=metadata,
        synthetic_payloads=documents,
    )
    assert result.enumeration_finished
    assert result.collection_complete is not missing
    assert result.database_complete is None and result.snapshot_published is None
    assert result.outcomes[0]["outcome"] == ("pending" if missing else "success")
    replay = collect(
        "WA SOC",
        tmp_path / "run",
        origin="synthetic",
        execution_id=run,
        replay_only=True,
        metadata_limit=0,
    )
    assert replay.collection_complete is not missing
    assert replay.metadata_collected == 0


def test_saved_repository_requires_exact_imports_before_publication(db, tmp_path):

    from standalone.evidence_pipeline.parsing.wasoc_discovery import plan
    from standalone.evidence_pipeline.collection.github_dispatch import source_scope
    from standalone.evidence_pipeline.parsing.devices import stable_id
    from standalone.evidence_pipeline.collection.public_collection import prepare
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.cve_current import publish
    from standalone.operations.repository_proof import published_run

    metadata, documents = fixtures()
    run = str(uuid4())
    bundle = tmp_path / run
    result = collect(
        "WA SOC",
        bundle,
        origin="synthetic",
        execution_id=run,
        synthetic_objects=metadata,
        synthetic_payloads=documents,
    )
    assert result.collection_complete
    with db.cursor() as cur:
        database_schema.verify(cur)
        assert not publish(cur, "WA SOC", bundle, origin="synthetic", execution_id=run)
    for file in plan(COMMIT, metadata["commits", COMMIT], metadata["trees", TREE]):
        chosen = source_scope(file, "synthetic")
        attempt = stable_id("github-discovered-attempt", run, chosen.connection_id)
        snapshot = prepare(
            chosen, attempt, bundle / "records" / attempt, replay_only=True
        )
        with db.cursor() as cur:
            authorize_connection(cur, snapshot)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        persist_public(db, snapshot)
    with db.cursor() as cur:
        assert publish(cur, "WA SOC", bundle, origin="synthetic", execution_id=run)
        assert publish(cur, "WA SOC", bundle, origin="synthetic", execution_id=run)
        assert published_run(
            cur, "WA SOC", tmp_path, origin="synthetic", execution_id=run
        )
        assert not published_run(
            cur, "WA SOC", tmp_path, origin="public", execution_id=run
        )
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT native_id,source_url FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
            (chosen.connection_id,),
        )
        assert cur.fetchone() == ("20990101001", chosen.scope_reference)
