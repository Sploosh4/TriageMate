"""Synthetic recurrence/failure/recovery through real worker processes and SQL."""

from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import time
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.runtime import connect, local_database
from standalone.evidence_pipeline.test_commands import cleanup
from standalone.windows_inventory.test_contract import sample
from .test_windows_inventory_worker import case
from .dispatch import Job

pytestmark = pytest.mark.xdist_group("retained_evidence_schema")


def test_scheduled_inventory_repeats_recovers_and_replays_without_fixture(
    tmp_path, monkeypatch
):
    from app.services.operations_api import create_service
    from app.services.postgres_query import PostgreSQLQueries

    recipe, _ = case(tmp_path)
    device_path = tmp_path / "device.json"
    device_path.write_text(
        json.dumps(
            [
                dict(
                    id=recipe.native_device_id,
                    deviceId=recipe.binding.device_id,
                    displayName="Synthetic inventory acceptance device",
                )
            ]
        )
    )
    device_path.chmod(0o600)

    def fresh_fixture():
        data = sample()
        now = datetime.now(timezone.utc).isoformat()
        data.update(started_at=now, finished_at=now)
        recipe.synthetic_input.write_text(json.dumps(data))

    fresh_fixture()
    anchor = datetime.now(timezone.utc) + timedelta(seconds=2)

    def item(scope, fixture, seconds, parameters):
        return dict(
            scope=asdict(scope),
            bundle_root=str(recipe.bundle_root),
            synthetic_input=str(fixture),
            allow_network=False,
            parameters=parameters,
            schedule=dict(
                kind="interval",
                seconds=seconds,
                anchor=anchor.isoformat(),
                offset_seconds=0,
            ),
        )

    config = tmp_path / "operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=1,
                inputs=[
                    item(
                        recipe.scope,
                        recipe.synthetic_input,
                        2,
                        dict(
                            device_input=recipe.device_scope.connection_id,
                            binding=asdict(recipe.binding),
                            native_device_id=recipe.native_device_id,
                        ),
                    ),
                    item(recipe.device_scope, device_path, 60, {}),
                ],
            )
        )
    )
    config.chmod(0o600)
    key = "synthetic-windows-inventory-" + str(uuid4())
    service = None

    def rows(sql, parameters=()):
        with closing(connect()) as connection, connection.cursor() as cur:
            cur.execute(sql, parameters)
            return cur.fetchall()

    def wait_for(condition):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            result = condition()
            if result:
                return result
            time.sleep(0.05)
        pytest.fail(
            "Bounded inventory service did not reach expected state: "
            + str(service.status())
        )

    try:
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        service.request_mode("running")
        attempts = wait_for(
            lambda: (
                found
                if len(
                    found := rows(
                        "SELECT a.id::text,s.device_attempt_id::text FROM evidence.collection_attempts a "
                        "JOIN evidence_pipeline.windows_inventory_runs s ON s.attempt_id=a.id "
                        "WHERE a.connection_id=%s ORDER BY a.started_at,a.id",
                        (recipe.scope.connection_id,),
                    )
                )
                >= 2
                else None
            )
        )
        assert len({row[0] for row in attempts}) >= 2
        assert len({row[1] for row in attempts}) == 1
        data = json.loads(
            PostgreSQLQueries().execute(
                dict(
                    requestId=str(uuid4()),
                    sql="SELECT kind,version FROM evidence_pipeline.current_windows_inventory WHERE connection_id='"
                    + recipe.scope.connection_id
                    + "'::uuid ORDER BY kind",
                )
            )
        )
        assert data["rows"] == [["appx", "01.002.0"], ["registry", "01.002.0"]]

        checks = rows(
            "SELECT inventory_attempt_id::text,metadata->>'defender_coverage' "
            "FROM evidence_pipeline.component_check_runs WHERE inventory_attempt_id "
            "IN (SELECT id FROM evidence.collection_attempts WHERE connection_id=%s)",
            (recipe.scope.connection_id,),
        )
        assert {row[0] for row in attempts}.issubset({row[0] for row in checks})
        assert all(row[1] == "unverified" for row in checks)

        recipe.synthetic_input.write_text("intentionally malformed synthetic inventory")
        wait_for(
            lambda: rows(
                "SELECT id FROM evidence.collection_attempts WHERE connection_id=%s AND outcome='failure'",
                (recipe.scope.connection_id,),
            )
        )
        assert rows(
            "SELECT count(*) FROM evidence_pipeline.current_windows_inventory WHERE connection_id=%s",
            (recipe.scope.connection_id,),
        ) == [(2,)]
        assert (
            rows(
                "SELECT count(*) FROM evidence.notifications WHERE connection_id=%s",
                (recipe.scope.connection_id,),
            )[0][0]
            >= 1
        )
        fresh_fixture()
        wait_for(
            lambda: rows(
                "SELECT id FROM evidence.notifications WHERE connection_id=%s AND resolved_at IS NOT NULL",
                (recipe.scope.connection_id,),
            )
        )
        service.request_mode("off")
        assert service.close(timeout=5)

        recipe.synthetic_input.unlink()
        first_run, device_run = attempts[0]
        job = Job(
            first_run,
            recipe.scope.connection_id,
            anchor,
            anchor,
            ((recipe.device_scope.connection_id, device_run),),
        )
        assert recipe.collect(job)["replayed"]
        # A later component assessment can change without a new inventory import.
        # Its watermark must become visible only after commit, never on rollback
        # or duplicate replay. The native fixture has already been removed.
        from app.services.evidence_revision import EvidenceRevision
        from standalone.windows_inventory import bundle, component_store

        revision = EvidenceRevision(PostgreSQLQueries())

        def watermark():
            revision.checked = float("-inf")
            return revision.read()

        def no_collect():
            pytest.fail("Retained component reevaluation attempted collection")

        initial = watermark()
        with monkeypatch.context() as patch:
            patch.setattr(component_store, "engine_fingerprint", lambda: "f" * 64)
            with bundle.prepare(
                recipe.scope,
                first_run,
                recipe.bundle_root,
                recipe.binding,
                device_run,
                collect=no_collect,
            ) as (_, staged):
                with closing(connect()) as connection:

                    def evaluate():
                        return component_store.persist(
                            connection,
                            first_run,
                            staged,
                            binding=recipe.binding,
                            origin="synthetic",
                        )

                    assert not evaluate()["replayed"]
                    assert watermark() == initial
                    connection.rollback()
                    assert watermark() == initial
                    assert not evaluate()["replayed"]
                    connection.commit()
                    published = watermark()
                    assert published != initial
                    assert evaluate()["replayed"]
                    connection.commit()
                    assert watermark() == published
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off" and service.status()["active"] == 0
    finally:
        if service is not None:
            assert service.close(timeout=5)
        # Only this test's random synthetic connection/service identifiers.
        with (
            closing(local_database().connect()) as connection,
            connection,
            connection.cursor() as cur,
        ):
            cur.execute("SET CONSTRAINTS ALL DEFERRED")
            for table in ("operation_events", "operation_checkpoints"):
                cur.execute(
                    f"DELETE FROM evidence_pipeline.{table} WHERE service_key=%s",
                    (key,),
                )
            for table in (
                "component_check_seals",
                "component_check_results",
                "component_check_source_chunks",
            ):
                cur.execute(
                    f"DELETE FROM evidence_pipeline.{table} WHERE check_id IN "
                    "(SELECT c.id FROM evidence_pipeline.component_check_runs c JOIN evidence.collection_attempts a "
                    "ON a.id=c.inventory_attempt_id WHERE a.connection_id=%s)",
                    (recipe.scope.connection_id,),
                )
            cur.execute(
                "DELETE FROM evidence_pipeline.component_check_runs WHERE inventory_attempt_id IN "
                "(SELECT id FROM evidence.collection_attempts WHERE connection_id=%s)",
                (recipe.scope.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.windows_inventory_observations WHERE attempt_id IN (SELECT id FROM evidence.collection_attempts WHERE connection_id=%s)",
                (recipe.scope.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.windows_inventory_runs WHERE attempt_id IN (SELECT id FROM evidence.collection_attempts WHERE connection_id=%s)",
                (recipe.scope.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.windows_inventory_bindings WHERE connection_id=%s",
                (recipe.scope.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
                (recipe.scope.connection_id,),
            )
        cleanup(recipe.scope)
        cleanup(recipe.device_scope)
