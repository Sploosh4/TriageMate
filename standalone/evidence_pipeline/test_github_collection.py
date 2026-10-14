"""Synthetic GitHub bundles and draft publisher authority in rolled-back SQL."""

from backend.database import schema as database_schema

import json
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.collection import public_collection as collector
from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.parsing.github_advisories import parse_github_advisory
from standalone.evidence_pipeline.parsing.public_snapshot import PARSERS
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.store import atomic
from .test_github_advisories import COMMIT, PATH, IDENTITY, scope
from .test_osv import document
from .test_store import db  # noqa: F401


@pytest.fixture
def enabled(monkeypatch):
    assert PARSERS["GitHub", "advisories"] is parse_github_advisory
    monkeypatch.setattr(
        collector,
        "download",
        lambda *args, **kwargs: pytest.fail("Synthetic or replay fetched HTTP"),
    )


def prepare(chosen, bundle, execution=None, payload=None, replay=False, commit=COMMIT):
    from .test_retained_public_fixture import prepare as fixture_snapshot

    return fixture_snapshot(
        chosen,
        execution or str(uuid4()),
        bundle,
        repository_commit=commit,
        repository_path=PATH,
        synthetic_payload=payload,
        replay_only=replay,
    )


def payload(**changes):
    return json.dumps(dict(document(), id=IDENTITY, **changes)).encode()


def setup(connection, value):
    with connection.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")

        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")


def test_github_publisher_receipts_reader_and_failed_refresh(db, tmp_path, enabled):  # noqa: F811
    chosen = scope()
    first = prepare(chosen, tmp_path / "first", payload=payload(aliases=[]))
    setup(db, first)
    assert not persist_public(db, first)["replayed"]
    assert persist_public(db, first)["replayed"]
    failed = prepare(chosen, tmp_path / "failed", payload=b"invalid synthetic response")
    assert persist_public(db, failed)["outcome"] == "failure"
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT source_name,advisory_id,withdrawn_text,source_url FROM evidence_pipeline.current_osv_advisories WHERE connection_id=%s",
            (chosen.connection_id,),
        )
        assert cur.fetchall() == [("GitHub", IDENTITY, None, chosen.scope_reference)]
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    withdrawn = prepare(
        chosen,
        tmp_path / "withdrawn",
        payload=payload(aliases=[], withdrawn="2099-09-14T00:00:00Z"),
    )
    persist_public(db, withdrawn)
    with db.cursor() as cur:
        cur.execute(
            "SELECT source_name,withdrawn_text FROM evidence_pipeline.current_osv_advisories WHERE connection_id=%s",
            (chosen.connection_id,),
        )
        assert cur.fetchall() == [("GitHub", "2099-09-14T00:00:00Z")]


def test_github_projection_is_reconstructed_by_attribution(db, tmp_path, enabled):  # noqa: F811
    from standalone.evidence_pipeline.persistence.osv_attribution import (
        verify_osv_receipt,
    )

    value = prepare(scope(), tmp_path / "github", payload=payload())
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            "SELECT to_jsonb(c) FROM evidence.source_connections c WHERE id=%s",
            (value.scope.connection_id,),
        )
        source = cur.fetchone()[0]
        cur.execute(
            "SELECT to_jsonb(r) FROM evidence.source_revisions r WHERE connection_id=%s",
            (source["id"],),
        )
        revision = cur.fetchone()[0]
        cur.execute(
            "SELECT to_jsonb(r) FROM evidence.observation_receipts r WHERE source_revision_id=%s",
            (revision["id"],),
        )
        receipt = cur.fetchone()[0]
        cur.execute(
            "SELECT claim FROM evidence_pipeline.public_claims WHERE source_revision_id=%s",
            (revision["id"],),
        )
        claim = cur.fetchone()[0]
        verified, cves = verify_osv_receipt(cur, source, revision, receipt, claim)
        assert len(verified["osv_advisory_observations"]) == 1 and len(cves) == 2
        with pytest.raises((ValueError, AssertionError)):
            verify_osv_receipt(
                cur,
                dict(
                    source,
                    scope_reference=source["scope_reference"].replace(COMMIT, "main"),
                ),
                revision,
                receipt,
                claim,
            )


def test_github_writer_cannot_add_unmatched_projection(db, tmp_path, enabled):  # noqa: F811
    value = prepare(scope(), tmp_path / "github", payload=payload())
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT o.receipt_id FROM evidence.osv_advisory_observations o JOIN evidence.observation_receipts r ON r.id=o.receipt_id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        receipt = cur.fetchone()[0]
        with pytest.raises(psycopg2.Error):
            with atomic(cur):
                cur.execute(
                    "INSERT INTO evidence.osv_aliases VALUES(%s,%s,%s,99,'CVE-2099-9999')",
                    (str(uuid4()), receipt, IDENTITY),
                )


@pytest.mark.parametrize("damage", ["missing_aliases", "wrong_source_url"])
def test_github_requires_complete_projection_and_exact_source_url(
    db,  # noqa: F811
    tmp_path,
    enabled,
    monkeypatch,
    damage,
):
    from standalone.evidence_pipeline.persistence import public_store

    value = prepare(scope(), tmp_path / "github", payload=payload())
    setup(db, value)
    original = public_store._insert_many

    def damaged(cursor, schema, table, values, **kwargs):
        if damage == "missing_aliases" and table == "osv_aliases":
            return
        if damage == "wrong_source_url" and table == "source_revisions":
            values = [
                dict(row, source_url="https://example.invalid/other") for row in values
            ]
        return original(cursor, schema, table, values, **kwargs)

    monkeypatch.setattr(public_store, "_insert_many", damaged)
    with pytest.raises(psycopg2.Error):
        persist_public(db, value)
    with db.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0,)


@pytest.mark.full_baseline
def test_github_passes_full_retained_attribution(db, tmp_path, enabled):  # noqa: F811
    from .test_attribution import verify

    value = prepare(scope(), tmp_path / "github", payload=payload())
    setup(db, value)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verify(cur)
