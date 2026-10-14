"""Real rolled-back CVE membership, replacement and writer/reader boundaries."""

from backend.database import schema as database_schema

import json
from uuid import uuid4

import psycopg2
import pytest

from standalone.evidence_pipeline.persistence import cve_current

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.collection.cve_repository import collect
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.github_dispatch import source_scope
from standalone.evidence_pipeline.collection.github_scan import scan
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cve_repository import repository
from .test_cve_discovery import COMMIT
from .test_store import db  # noqa: F401


def saved_run(db, path, source, *, commit=COMMIT, empty=False, import_records=True):  # noqa: F811
    objects, payloads = repository(source)
    if commit != COMMIT:
        original = json.loads(objects.pop(("commits", COMMIT)))
        original["sha"] = commit
        objects[("commits", commit)] = json.dumps(original).encode()
        key = ("ref", "heads/main" if source == "CVE" else "heads/develop")
        ref = json.loads(objects[key])
        ref["object"]["sha"] = commit
        objects[key] = json.dumps(ref).encode()
    if empty:
        for key, wire in list(objects.items()):
            value = json.loads(wire)
            if key[0] == "trees" and any(
                item.get("type") == "blob" for item in value["tree"]
            ):
                value["tree"] = []
                objects[key] = json.dumps(value).encode()
    execution = str(uuid4())
    result = collect(
        source,
        path,
        origin="synthetic",
        execution_id=execution,
        synthetic_objects=objects,
        synthetic_payloads=payloads,
    )
    assert result.collection_complete
    if import_records:
        selected = scan(
            commit,
            path / "partition-2099-1xxx",
            source=source,
            origin="synthetic",
            replay_only=True,
            partition="2099/1xxx",
            object_cache=path / "objects",
        )
        for file in selected.discovery.files:
            scope = source_scope(file, "synthetic")
            attempt = stable_id(
                "github-discovered-attempt", execution, scope.connection_id
            )
            snapshot = prepare(
                scope,
                attempt,
                path / "records" / attempt,
                cve=file.cve_id,
                repository_commit=commit,
                repository_path=file.path,
                replay_only=True,
            )
            with db.cursor() as cur:
                cur.execute("RESET SESSION AUTHORIZATION")
                authorize_connection(cur, snapshot)
                cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
            persist_public(db, snapshot)
    return execution


@pytest.mark.parametrize("source", ["CVE", "CISA"])
def test_complete_partial_empty_and_old_replay(db, tmp_path, source):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
    first = saved_run(db, tmp_path / "first", source)
    with db.cursor() as cur:
        assert cve_current.publish(
            cur, source, tmp_path / "first", origin="synthetic", execution_id=first
        )
        cur.execute(
            "SELECT cve_id FROM evidence_pipeline.current_cve_repository_records WHERE source_name=%s AND origin='synthetic' ORDER BY cve_id",
            (source,),
        )
        assert cur.fetchall() == [("CVE-2099-1234",), ("CVE-2099-1235",)]
    partial = saved_run(
        db, tmp_path / "partial", source, commit="b" * 40, import_records=False
    )
    with db.cursor() as cur:
        assert not cve_current.publish(
            cur, source, tmp_path / "partial", origin="synthetic", execution_id=partial
        )
        cur.execute(
            "SELECT run_id::text FROM evidence_pipeline.current_cve_repository_snapshot WHERE source_name=%s AND origin='synthetic'",
            (source,),
        )
        assert cur.fetchone() == (first,)
    empty = saved_run(db, tmp_path / "empty", source, commit="c" * 40, empty=True)
    with db.cursor() as cur:
        assert cve_current.publish(
            cur, source, tmp_path / "empty", origin="synthetic", execution_id=empty
        )
        assert cve_current.publish(
            cur, source, tmp_path / "first", origin="synthetic", execution_id=first
        )
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT run_id::text FROM evidence_pipeline.current_cve_repository_snapshot WHERE source_name=%s AND origin='synthetic'",
            (source,),
        )
        assert cur.fetchone() == (empty,)
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.current_cve_repository_records WHERE source_name=%s AND origin='synthetic'",
            (source,),
        )
        assert cur.fetchone() == (0,)
        cur.execute(
            "SELECT count(*) FROM evidence_pipeline.cve_repository_snapshots WHERE source_name=%s AND origin='synthetic'",
            (source,),
        )
        assert cur.fetchone() == (2,)
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute("DELETE FROM evidence_pipeline.cve_repository_snapshots")


@pytest.mark.parametrize(
    "damage",
    ["source", "origin", "commit", "path", "receipt", "duplicate", "reference"],
)
def test_membership_policy_rejects_mismatched_receipts(db, tmp_path, damage):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
    execution = saved_run(db, tmp_path / "run", "CVE")
    with db.cursor() as cur:
        assert cve_current.publish(
            cur, "CVE", tmp_path / "run", origin="synthetic", execution_id=execution
        )
        cur.execute(
            "SELECT source_name,origin,repository_commit,reference_observed_at,reference_payload,members FROM evidence_pipeline.cve_repository_snapshots WHERE run_id=%s",
            (execution,),
        )
        provider, origin, commit, observed, reference, members = cur.fetchone()
        if damage == "source":
            provider = "CISA"
            reference["ref"] = "refs/heads/develop"
        elif damage == "origin":
            origin = "public"
        elif damage == "commit":
            commit = "d" * 40
            reference["object"]["sha"] = commit
        elif damage == "path":
            members[0]["path"] = members[0]["path"].replace("1xxx", "2xxx")
        elif damage == "receipt":
            members[0]["receipt_id"] = str(uuid4())
        elif damage == "duplicate":
            members.append(members[0])
        elif damage == "reference":
            reference = {}
        with pytest.raises(
            (psycopg2.errors.InsufficientPrivilege, psycopg2.errors.CheckViolation)
        ):
            cur.execute(
                "INSERT INTO evidence_pipeline.cve_repository_snapshots VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)",
                (
                    provider,
                    str(uuid4()),
                    origin,
                    commit,
                    observed,
                    json.dumps(reference),
                    json.dumps(members),
                ),
            )


def test_upgrade_replay_and_predecessor_projection(db):  # noqa: F811

    from .test_public_migration import (
        test_upgrade_repeat_and_legacy_schema_verification,
    )

    with db.cursor() as cur:
        database_schema.verify(cur)
    test_upgrade_repeat_and_legacy_schema_verification(db)


def test_upgrade_rejects_authority_drift(db):  # noqa: F811
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT UPDATE ON evidence_pipeline.cve_repository_snapshots TO tm_pipeline_writer"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
