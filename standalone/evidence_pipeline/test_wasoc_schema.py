"""Transactional WA SOC schema checks with generated Markdown and restricted roles."""

from backend.database import schema as database_schema

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_store import db as database_fixture
from .test_wasoc_advisories import scope, BODY, COMMIT, PATH
from standalone.evidence_pipeline.parsing.wasoc_advisories import repository_endpoint

db = database_fixture


def install(db):
    with db.cursor() as cur:
        database_schema.verify(cur)


@pytest.mark.parametrize(
    "name",
    ["Synthetic", "Space name", "Unicode café", ".NET", "Quote's", "Brackets(1)"],
)
def test_encoded_route_matches_python(db, name):
    install(db)
    path = PATH.replace("Synthetic", name)
    url = repository_endpoint(COMMIT, path, "20990101001")
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline.wasoc_source_url(%s,%s),evidence_pipeline.wasoc_source_allowed(%s,%s)",
            (COMMIT, path, "20990101001", url),
        )
        assert cur.fetchone() == (url, True)


@pytest.mark.parametrize(
    "change",
    [
        "foreign",
        "mutable",
        "zero",
        "query",
        "fragment",
        "encoded_slash",
        "encoded_unreserved",
        "lower_hex",
        "wrong_id",
        "path_escape",
    ],
)
def test_noncanonical_or_wrong_identity_rejected(db, change):
    install(db)
    url = repository_endpoint(COMMIT, PATH.replace("Synthetic", "Café"), "20990101001")
    native = "20990101001"
    if change == "foreign":
        url = url.replace("githubusercontent.com", "githubusercontent.com.evil")
    elif change == "mutable":
        url = url.replace(COMMIT, "main")
    elif change == "zero":
        url = url.replace(COMMIT, "0" * 40)
    elif change == "query":
        url += "?x=1"
    elif change == "fragment":
        url += "#x"
    elif change == "encoded_slash":
        url = url.replace("/docs/", "/%64ocs%2F")
    elif change == "encoded_unreserved":
        url = url.replace("Caf", "%43af")
    elif change == "lower_hex":
        url = url.replace("%C3", "%c3")
    elif change == "wrong_id":
        native = "20990101002"
    else:
        url = url.replace("/docs/", "/../docs/")
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT evidence_pipeline.wasoc_source_allowed(%s,%s)", (native, url)
        )
        assert cur.fetchone() == (False,)


def put(db, chosen, at):
    snapshot = PublicSnapshot(chosen, str(uuid4()), at, at, "success", True, BODY)
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION DEFAULT")
        cur.execute(
            "SELECT 1 FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
            (chosen.connection_id,),
        )
        if cur.fetchone() is None:
            authorize_connection(cur, snapshot)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_public(db, snapshot)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute(
            "SELECT r.id::text FROM evidence.observation_receipts r WHERE collection_attempt_id=%s",
            (snapshot.execution_id,),
        )
        return cur.fetchone()[0]


def publish(db, commit, at, members):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO evidence_pipeline.wasoc_repository_snapshots VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
            (
                "WA SOC",
                str(uuid4()),
                "synthetic",
                commit,
                at,
                json.dumps(
                    dict(ref="refs/heads/main", object=dict(type="commit", sha=commit))
                ),
                json.dumps(members),
            ),
        )


def current(db):
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT source_url FROM evidence_pipeline.current_public_references WHERE source_name='WA SOC' AND origin='synthetic' ORDER BY source_url"
        )
        rows = [r[0] for r in cur.fetchall()]
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        return rows


def test_complete_snapshot_selection_preserves_old_until_published_and_distinct_paths(
    db,
):
    install(db)
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence_pipeline.wasoc_repository_snapshots")
        existing_snapshots = cur.fetchone()[0]
    at = datetime.now(timezone.utc)
    first = scope()
    one = put(db, first, at)
    assert current(db) == []
    publish(db, COMMIT, at, [dict(path=PATH, receipt_id=one)])
    assert current(db) == [first.scope_reference]
    # A repeated import of the same immutable commit must not displace the
    # receipt pinned by the previously published snapshot.
    repeated = put(db, first, at + timedelta(microseconds=1))
    assert repeated != one
    assert current(db) == [first.scope_reference]
    with db.cursor() as cur:
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='vendor-advisory'",
            ([first.connection_id],),
        )
        assert cur.fetchone() == (4, 4)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    next_commit = "b" * 40
    second = replace(
        scope(), scope_reference=repository_endpoint(next_commit, PATH, "20990101001")
    )
    two = put(db, second, at + timedelta(seconds=1))
    # A partial newer collection does not hide the previous complete snapshot.
    assert current(db) == [first.scope_reference]
    other_path = PATH.replace("Synthetic", "Distinct")
    third = replace(
        scope(),
        scope_reference=repository_endpoint(next_commit, other_path, "20990101001"),
    )
    three = put(db, third, at + timedelta(seconds=1))
    publish(
        db,
        next_commit,
        at + timedelta(seconds=1),
        [dict(path=PATH, receipt_id=two), dict(path=other_path, receipt_id=three)],
    )
    assert current(db) == sorted([second.scope_reference, third.scope_reference])
    with db.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence_pipeline.wasoc_repository_snapshots")
        assert cur.fetchone() == (existing_snapshots + 2,)
    publish(db, "c" * 40, at + timedelta(seconds=2), [])
    assert current(db) == []


@pytest.mark.parametrize("change", ["commit", "path", "duplicate", "receipt", "origin"])
def test_membership_cannot_cross_commit_origin_or_receipt_boundaries(db, change):
    import psycopg2

    install(db)
    at = datetime.now(timezone.utc)
    chosen = scope()
    receipt = put(db, chosen, at)
    members = [dict(path=PATH, receipt_id=receipt)]
    commit = COMMIT
    origin = "synthetic"
    if change == "commit":
        commit = "b" * 40
    elif change == "path":
        members[0]["path"] = PATH.replace("Synthetic", "Other")
    elif change == "duplicate":
        members *= 2
    elif change == "receipt":
        members[0]["receipt_id"] = str(uuid4())
    else:
        origin = "public"
    with db.cursor() as cur:
        cur.execute("SAVEPOINT reject_membership")
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(
                "INSERT INTO evidence_pipeline.wasoc_repository_snapshots VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
                (
                    "WA SOC",
                    str(uuid4()),
                    origin,
                    commit,
                    at,
                    json.dumps(
                        dict(
                            ref="refs/heads/main",
                            object=dict(type="commit", sha=commit),
                        )
                    ),
                    json.dumps(members),
                ),
            )
        cur.execute("ROLLBACK TO SAVEPOINT reject_membership")
    assert current(db) == []


def test_explicit_upgrade_idempotency_prior_verifier_and_authority_drift(db):

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
            "GRANT UPDATE ON evidence_pipeline.wasoc_repository_snapshots TO tm_pipeline_writer"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
