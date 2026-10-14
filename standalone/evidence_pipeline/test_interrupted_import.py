"""Terminate a synthetic import before commit; authoritative evidence stays absent."""

import multiprocessing
import pytest
from uuid import uuid4

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .runtime import local_database
from standalone.evidence_pipeline.persistence.store import persist_devices
from .test_devices import make


def import_before_commit(snapshot, ready, wait):
    with local_database().connect() as conn, conn.cursor() as cur:
        authorize_connection(cur, snapshot)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        persist_devices(conn, snapshot)
        ready.set()
        wait.wait(30)


def test_process_cancellation_rolls_back_evidence_and_releases_transaction():
    from standalone.operations.process_worker import ProcessHandle

    snapshot = make(
        "Defender",
        [{"id": "synthetic-interruption-" + str(uuid4()), "osPlatform": "Windows11"}],
    )
    context = multiprocessing.get_context("spawn")
    ready, wait = context.Event(), context.Event()
    process = context.Process(target=import_before_commit, args=(snapshot, ready, wait))
    process.start()
    try:
        assert ready.wait(10)
        ProcessHandle(process).cancel()
        process.join(timeout=5)
        assert not process.is_alive() and process.exitcode != 0
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute("SET statement_timeout='2s'")
            cur.execute(
                "SELECT count(*) FROM evidence.source_connections WHERE id=%s",
                (snapshot.scope.connection_id,),
            )
            assert cur.fetchone() == (0,)
            cur.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                (snapshot.execution_id,),
            )
            assert cur.fetchone() == (0,)
            # The same identity can be imported after cancellation: no held locks,
            # half-committed attempt or poisoned transaction remains.
            authorize_connection(cur, snapshot)
            cur.execute("SET LOCAL ROLE tm_pipeline_writer")
            assert not persist_devices(conn, snapshot)["replayed"]
            conn.rollback()
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)


def _large_public_import(snapshot, scratch, channel, mode):
    import os
    import tempfile
    from contextlib import closing
    from unittest.mock import patch
    import psycopg2
    from standalone.evidence_pipeline.persistence import public_store

    os.environ["SQLITE_TMPDIR"] = scratch
    os.environ["TMPDIR"] = scratch
    tempfile.tempdir = scratch
    original = public_store._batches
    with closing(local_database().connect()) as conn:

        def paused_batches(records):
            with closing(original(records)) as batches:
                for index, batch in enumerate(batches):
                    yield batch
                    if index == 0:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
                                (snapshot.execution_id,),
                            )
                            channel.send(cur.fetchone()[0])
                            channel.recv()
                            if mode == "timeout":
                                # Inject delay with the test owner's connection;
                                # the restricted product writer gets no new grant.
                                cur.execute("RESET ROLE")
                                cur.execute("SET LOCAL statement_timeout='50ms'")
                                cur.execute("SELECT pg_sleep(2)")

        try:
            with conn.cursor() as cur:
                authorize_connection(cur, snapshot)
                cur.execute("SET LOCAL ROLE tm_pipeline_writer")
            with patch.object(public_store, "_batches", paused_batches):
                public_store.persist_public(conn, snapshot)
            raise AssertionError("Interrupted import unexpectedly completed")
        except psycopg2.errors.QueryCanceled:
            conn.rollback()
            channel.send("statement_timeout")
        finally:
            conn.rollback()


def _large_public_snapshot(tmp_path):
    from dataclasses import replace
    import hashlib
    import json
    from .file_payload import FilePayload
    from .test_cvrf_store import snapshot
    from .test_cvrf_updates import document

    base = snapshot()
    root = document()
    record = root["Vulnerability"][0]
    record["Notes"] = [
        {"Title": "Synthetic interruption note", "Value": "x" * 64000}
        for _ in range(250)
    ]
    path = tmp_path / "retained-synthetic-cvrf.json"
    with path.open("w") as stream:
        stream.write('{"ProductTree":')
        json.dump(root["ProductTree"], stream)
        stream.write(',"Vulnerability":[')
        for index in range(3):
            if index:
                stream.write(",")
            json.dump({**record, "CVE": f"CVE-2099-{8000000 + index}"}, stream)
        stream.write("]}")
    path.chmod(0o600)
    assert path.stat().st_size > 45_000_000
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return replace(base, payload=FilePayload(path.resolve(), digest)), path, digest


@pytest.mark.parametrize("mode", ["terminate", "timeout"])
def test_large_public_partial_import_cancellation_cleanup_and_retry(tmp_path, mode):
    import hashlib
    import time
    from contextlib import closing
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from standalone.operations.process_worker import ProcessHandle

    snapshot, path, digest = _large_public_snapshot(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe()
    process = context.Process(
        target=_large_public_import, args=(snapshot, str(scratch), child, mode)
    )
    process.start()
    try:
        assert parent.poll(30), "Import did not reach first persisted batch"
        assert parent.recv() == 1, "Cancellation must follow actual partial persistence"
        started = time.monotonic()
        if mode == "terminate":
            ProcessHandle(process).cancel()
        else:
            parent.send(True)
            assert parent.poll(5)
            assert parent.recv() == "statement_timeout"
        process.join(5)
        assert not process.is_alive()
        assert process.exitcode == (-15 if mode == "terminate" else 0)
        assert time.monotonic() - started < 5
        assert list(scratch.iterdir()) == []
        with path.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == digest
        with closing(local_database().connect()) as conn, conn.cursor() as cur:
            try:
                cur.execute("SET statement_timeout='30s'")
                cur.execute(
                    "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
                    (snapshot.execution_id,),
                )
                assert cur.fetchone() == (0,)
                cur.execute(
                    "SELECT count(*) FROM evidence.source_connections WHERE id=%s",
                    (snapshot.scope.connection_id,),
                )
                assert cur.fetchone() == (0,)
                authorize_connection(cur, snapshot)
                cur.execute("SET LOCAL ROLE tm_pipeline_writer")
                assert not persist_public(conn, snapshot)["replayed"]
                cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
                cur.execute(
                    "SELECT count(*) FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
                    (snapshot.execution_id,),
                )
                assert cur.fetchone() == (3,)
                assert persist_public(conn, snapshot)["replayed"]
            finally:
                conn.rollback()
    finally:
        if process.is_alive():
            process.terminate()
        process.join(5)
        parent.close()
        child.close()
