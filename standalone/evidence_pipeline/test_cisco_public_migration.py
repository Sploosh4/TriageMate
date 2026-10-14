"""Generated Cisco fixtures exercise public-route authority, never live collection."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection


from standalone.evidence_pipeline.parsing.cisco_rss import endpoint
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cisco_advisories import example
from .test_store import db as database_fixture

db = database_fixture


def test_upgrade_preserves_old_verifier_and_rejects_authority_drift(db):

    with db.cursor() as cur:
        cur.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        previous = cur.fetchone()[0]
        database_schema.verify(cur)
        cur.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        assert cur.fetchone() == (previous,)
        cur.execute(
            "ALTER FUNCTION evidence_pipeline.reference_claim(uuid) SECURITY DEFINER"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)


@pytest.mark.parametrize("origin", ["public", "synthetic"])
def test_fixed_route_persistence_replay_reader_and_completeness(db, origin):
    scope, document = example()
    native = document["document"]["tracking"]["id"]
    scope = replace(scope, origin=origin, scope_reference=endpoint(native))
    now = datetime.now(timezone.utc)
    snapshot = PublicSnapshot(
        scope, str(uuid4()), now, now, "success", True, json.dumps(document).encode()
    )
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, snapshot)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    assert not persist_public(db, snapshot)["replayed"]
    assert persist_public(db, snapshot)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT native_id,origin,source_url,source_fields FROM evidence_pipeline.current_public_references WHERE connection_id=%s",
            (scope.connection_id,),
        )
        assert cur.fetchone() == (
            native,
            origin,
            scope.scope_reference,
            {"document": document},
        )
        cur.execute(
            "SELECT domain,populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='vendor-advisory'",
            ([scope.connection_id],),
        )
        assert cur.fetchone() == ("vendor-advisory", 6, 6)
        cur.execute(
            "SELECT completeness_domain FROM evidence_pipeline.product_collection_coverage WHERE connection_id=%s",
            (scope.connection_id,),
        )
        assert cur.fetchone() == ("public-native",)


@pytest.mark.parametrize(
    "change",
    ["valid", "query", "fragment", "http", "foreign", "case", "other_file", "encoded"],
)
def test_database_route_matches_exact_python_route(db, change):
    url = endpoint("cisco-sa-synthetic-AbC")
    url = {
        "valid": url,
        "query": url + "?x=1",
        "fragment": url + "#x",
        "http": url.replace("https:", "http:"),
        "foreign": url.replace(".com/", ".com.evil/"),
        "case": url.replace("AbC.json", "abc.json"),
        "other_file": url.replace("AbC.json", "other.json"),
        "encoded": url.replace("AbC", "%41bC"),
    }[change]
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "SELECT evidence_pipeline.reference_source_allowed('Cisco','advisories',%s)",
            (url,),
        )
        assert cur.fetchone() == (change == "valid",)
