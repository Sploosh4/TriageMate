"""Committed synthetic GitHub collection through registration and the SQL reader."""

import json
from uuid import uuid4

from .commands import register, ingest_public
from .test_retained_public_fixture import prepare
from .test_github_advisories import COMMIT, PATH, IDENTITY, scope
from .test_osv import document
from .test_osv_commands import clear


def test_committed_github_bundle_and_reader(tmp_path, monkeypatch):
    from standalone.evidence_pipeline.collection import public_collection

    monkeypatch.setattr(
        public_collection,
        "download",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Unexpected network")),
    )
    source = scope()
    raw = dict(document(), id=IDENTITY, aliases=[])
    execution = str(uuid4())
    bundle = tmp_path / "github"
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(source)
        assert not register(source)
        value = prepare(
            source,
            execution,
            bundle,
            repository_commit=COMMIT,
            repository_path=PATH,
            synthetic_payload=json.dumps(raw).encode(),
        )
        assert not ingest_public(value)["replayed"]
        replay = prepare(
            source,
            execution,
            bundle,
            repository_commit=COMMIT,
            repository_path=PATH,
            replay_only=True,
        )
        assert ingest_public(replay)["replayed"]
        result = PostgreSQLQueries().execute(
            {
                "requestId": str(uuid4()),
                "sql": "SELECT source_name,advisory_id,source_url FROM evidence_pipeline.current_osv_advisories WHERE connection_id='"
                + source.connection_id
                + "'::uuid",
            }
        )
        assert json.loads(result)["rows"] == [
            ["GitHub", IDENTITY, source.scope_reference]
        ]
    finally:
        clear(source, [])
