"""WA SOC scheduled process requires complete pinned publication and restarts Off."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import time
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.runtime import local_database
from standalone.evidence_pipeline.test_osv_commands import clear
from standalone.evidence_pipeline.test_wasoc_repository import fixtures
from standalone.evidence_pipeline.test_wasoc_discovery import COMMIT, TREE
from standalone.evidence_pipeline.parsing.wasoc_discovery import plan
from standalone.evidence_pipeline.collection.github_dispatch import source_scope


def isolated_repository():
    metadata, payloads = fixtures()
    commit = uuid4().hex + "a" * 8
    wire = json.loads(metadata.pop(("commits", COMMIT)))
    wire["sha"] = commit
    metadata["commits", commit] = json.dumps(wire).encode()
    metadata["ref", "heads/main"] = json.dumps(
        dict(ref="refs/heads/main", object=dict(type="commit", sha=commit))
    ).encode()
    scopes = [
        source_scope(file, "synthetic")
        for file in plan(commit, metadata["commits", commit], metadata["trees", TREE])
    ]
    return metadata, payloads, scopes


@pytest.mark.parametrize(
    "pass_limit,mode",
    [
        (100, "once"),
        (1, "once"),
        (100, "repeat"),
        (100, "changed_commit"),
        (100, "recovery"),
    ],
)
def test_application_schedules_complete_repository(tmp_path, pass_limit, mode):
    metadata, payloads, scopes = isolated_repository()
    complete_payloads = dict(payloads)
    if mode == "recovery":
        payloads = {}
    fixture = tmp_path / "synthetic-repository.json"
    fixture.write_text(
        json.dumps(
            {
                "origin": "synthetic",
                "objects": [
                    dict(kind=kind, identity=identity, payload=wire.decode())
                    for (kind, identity), wire in metadata.items()
                ],
                "records": {path: wire.decode() for path, wire in payloads.items()},
            }
        )
    )
    fixture.chmod(0o600)
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    key, input_id = "synthetic-repository-service-" + str(uuid4()), str(uuid4())
    config = tmp_path / "operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=5,
                inputs=[
                    dict(
                        scope=dict(
                            connection_id=input_id,
                            source="WA SOC",
                            input_kind="repository",
                            scope_reference="https://github.com/wagov/wasocshared",
                            origin="synthetic",
                            provenance="Explicitly synthetic repository service acceptance",
                        ),
                        schedule=dict(
                            kind="interval",
                            seconds=5 if mode != "once" else 3600,
                            anchor=(
                                datetime.now(timezone.utc) + timedelta(seconds=1)
                            ).isoformat(),
                            offset_seconds=0,
                        ),
                        bundle_root=str(root),
                        synthetic_input=str(fixture),
                        allow_network=False,
                        parameters=dict(
                            metadata_limit=2, record_limit=1, pass_limit=pass_limit
                        ),
                    )
                ],
            )
        )
    )
    config.chmod(0o600)
    from app.services.operations_api import create_service
    from app.services.postgres_query import PostgreSQLQueries

    service, run = None, None
    try:
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        service.request_mode("running")
        deadline = time.monotonic() + 30
        changed = False
        expected_runs = 1 if mode == "once" else 2
        while time.monotonic() < deadline:
            status = service.status()
            runs = [path.name for path in root.iterdir() if path.is_dir()]
            if (
                mode == "recovery"
                and not changed
                and len(runs) == 1
                and not status["inputs"][0]["active"]
            ):
                from .notifications import load

                assert status["inputs"][0]["latest_success"] is False
                assert load(key)[0]["status"] == "unresolved"
                failure_notice = load(key)[0]["id"]
                fixture.write_text(
                    json.dumps(
                        dict(
                            origin="synthetic",
                            objects=[
                                dict(
                                    kind=kind, identity=identity, payload=wire.decode()
                                )
                                for (kind, identity), wire in metadata.items()
                            ],
                            records={
                                path: wire.decode()
                                for path, wire in complete_payloads.items()
                            },
                        )
                    )
                )
                changed = True
            if (
                mode == "changed_commit"
                and not changed
                and len(runs) == 1
                and not status["inputs"][0]["active"]
            ):
                assert status["inputs"][0]["latest_success"] is True
                metadata, payloads, added_scopes = isolated_repository()
                tree = json.loads(metadata["trees", TREE])
                original = tree["tree"][1]
                additional = dict(
                    original,
                    path=original["path"].replace("Synthetic", "Second-Synthetic"),
                )
                tree["tree"].append(additional)
                metadata["trees", TREE] = json.dumps(tree).encode()
                payloads[additional["path"]] = payloads[original["path"]]
                commit = next(
                    identity for kind, identity in metadata if kind == "commits"
                )
                added_scopes = [
                    source_scope(file, "synthetic")
                    for file in plan(
                        commit, metadata["commits", commit], metadata["trees", TREE]
                    )
                ]
                scopes.extend(added_scopes)
                fixture.write_text(
                    json.dumps(
                        dict(
                            origin="synthetic",
                            objects=[
                                dict(
                                    kind=kind, identity=identity, payload=wire.decode()
                                )
                                for (kind, identity), wire in metadata.items()
                            ],
                            records={
                                path: wire.decode() for path, wire in payloads.items()
                            },
                        )
                    )
                )
                changed = True
            if (
                len(runs) == expected_runs
                and not status["inputs"][0]["active"]
                and not status["recovery_required"]
            ):
                break
            time.sleep(0.05)
        assert len(runs) == expected_runs and not status["inputs"][0]["active"], status
        assert status["inputs"][0]["latest_success"] is (pass_limit == 100), status
        run = status["inputs"][0]["latest_snapshot"] if pass_limit == 100 else runs[0]
        expected_snapshot = run if pass_limit == 100 else None
        assert status["inputs"][0]["latest_snapshot"] == expected_snapshot
        response = PostgreSQLQueries().execute(
            dict(
                requestId=str(uuid4()),
                sql="SELECT count(*) FROM evidence_pipeline.current_wasoc_repository_snapshot WHERE run_id='"
                + run
                + "'::uuid",
            )
        )
        assert json.loads(response)["rows"] == [[1 if pass_limit == 100 else 0]]
        response = PostgreSQLQueries().execute(
            dict(
                requestId=str(uuid4()),
                sql="SELECT count(*) FROM evidence_pipeline.current_public_references WHERE connection_id IN ("
                + ",".join("'" + scope.connection_id + "'::uuid" for scope in scopes)
                + ")",
            )
        )
        assert json.loads(response)["rows"] == [
            [(2 if mode == "changed_commit" else 1) if pass_limit == 100 else 0]
        ]
        from .notifications import load

        if mode == "recovery":
            assert len(load(key)) == 1
            assert load(key)[0]["id"] == failure_notice
            assert load(key)[0]["status"] == "resolved"
        elif pass_limit == 100:
            assert load(key) == []
        service.request_mode("off")
        service.close(timeout=5)
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        assert service.status()["inputs"][0]["latest_snapshot"] == expected_snapshot
    finally:
        if service is not None:
            service.close(timeout=5)
        with (
            closing(local_database().connect()) as connection,
            connection,
            connection.cursor() as cursor,
        ):
            # Every owned run is discoverable even if an assertion fails before
            # the supervisor acknowledges its committed publication.
            runs = [path.name for path in root.iterdir() if path.is_dir()]
            for own_run in runs:
                cursor.execute(
                    "DELETE FROM evidence_pipeline.wasoc_repository_snapshots WHERE run_id=%s",
                    (own_run,),
                )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        for scope in scopes:
            with local_database().connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)",
                    (scope.connection_id,),
                )
            clear(scope, [])
