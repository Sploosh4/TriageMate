"""Real restricted-writer commands and reader queries with owned synthetic cleanup."""

import json
from uuid import uuid4

from .commands import register, ingest_public
from .test_retained_public_fixture import prepare
from .test_osv import document
from .test_osv_commands import clear
from .test_ubuntu_advisories import scope


def test_committed_ubuntu_collection_and_relationship_reader(tmp_path):
    chosen = scope("USN-9999-1")
    raw = dict(
        document(),
        id="USN-9999-1",
        aliases=[],
        upstream=["UBUNTU-CVE-2099-1234"],
        related=["USN-9998-1"],
    )
    value = prepare(
        chosen,
        str(uuid4()),
        tmp_path / "bundle",
        advisory_id=raw["id"],
        synthetic_payload=json.dumps(raw).encode(),
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(chosen)
        assert not register(chosen)
        assert not ingest_public(value)["replayed"]
        replayed = prepare(
            chosen,
            value.execution_id,
            tmp_path / "bundle",
            advisory_id=raw["id"],
            replay_only=True,
        )
        assert ingest_public(replayed)["replayed"]
        response = PostgreSQLQueries().execute(
            {
                "requestId": str(uuid4()),
                "sql": "SELECT relationship_kind,target_id,source_name FROM evidence_pipeline.current_osv_relationships WHERE connection_id='"
                + chosen.connection_id
                + "'::uuid ORDER BY relationship_kind",
            }
        )
        assert json.loads(response)["rows"] == [
            ["related", "USN-9998-1", "Ubuntu"],
            ["upstream", "UBUNTU-CVE-2099-1234", "Ubuntu"],
        ]
    finally:
        clear(chosen, [])
