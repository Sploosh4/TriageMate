"""Rollback-only Ubuntu publication, failure preservation and reader authority."""

from backend.database import schema as database_schema

import json
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from standalone.evidence_pipeline.collection.cve_repository import collect
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.github_dispatch import source_scope
from standalone.evidence_pipeline.collection.github_scan import scan
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_ubuntu_repository import fixtures
from .test_ubuntu_discovery import COMMIT
from .test_store import db as database_fixture


db = database_fixture


def saved_run(db, path, *, commit=COMMIT, empty=False, import_records=True):
    objects, payloads = fixtures()
    value = json.loads(objects.pop(("commits", COMMIT)))
    value["sha"] = commit
    objects["commits", commit] = json.dumps(value).encode()
    reference = json.loads(objects["ref", "heads/main"])
    reference["object"]["sha"] = commit
    objects["ref", "heads/main"] = json.dumps(reference).encode()
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
        "Ubuntu",
        path,
        origin="synthetic",
        execution_id=execution,
        synthetic_objects=objects,
        synthetic_payloads=payloads,
    )
    assert result.collection_complete
    if import_records:
        for partition in ("cve/2099", "lsn", "usn"):
            selected = scan(
                commit,
                path / ("partition-" + partition.replace("/", "-")),
                source="Ubuntu",
                origin="synthetic",
                replay_only=True,
                partition=partition,
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
                    advisory_id=file.advisory_id,
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


def test_migration_replay_all_predecessors_and_drift(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT UPDATE ON evidence_pipeline.ubuntu_repository_snapshots TO tm_pipeline_writer"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
