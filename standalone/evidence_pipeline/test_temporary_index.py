"""Spillable parser scratch storage survives hard exits without orphan files."""

import io
import multiprocessing
import os
import sqlite3
import stat
import sys
import tempfile

import pytest

from .temporary_index import temporary_index


def test_private_connections_and_exception_cleanup():
    with temporary_index() as first, temporary_index() as other:
        first.execute("CREATE TABLE evidence (value TEXT)")
        first.execute("INSERT INTO evidence VALUES ('synthetic')")
        assert first.execute("PRAGMA cache_size").fetchone() == (-1024,)
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            other.execute("SELECT * FROM evidence")
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        first.execute("SELECT 1")
    with pytest.raises(KeyboardInterrupt):
        with temporary_index() as failed:
            raise KeyboardInterrupt
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        failed.execute("SELECT 1")


def _parser_child(root, channel, exit_kind):
    # Direct SQLite and Python temporary storage into this test-owned directory.
    os.environ["SQLITE_TMPDIR"] = root
    os.environ["TMPDIR"] = root
    tempfile.tempdir = root
    from .json_stream import object_members

    members = object_members(io.BytesIO(b'{"synthetic":1,"second":2}'))
    assert next(members) == ("synthetic", 1)
    with temporary_index() as scratch:
        scratch.execute("CREATE TABLE keys(name TEXT PRIMARY KEY)")
        scratch.executemany(
            "INSERT INTO keys VALUES (?)",
            ((str(i) + "x" * 200,) for i in range(50_000)),
        )
        files = []
        for fd in os.listdir("/proc/self/fd"):
            try:
                info = os.fstat(int(fd))
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 0:
                files.append(info.st_size)
        channel.send(sum(files))
        channel.recv()
        if exit_kind == "lease_exit":
            os._exit(125)
        members.close()


@pytest.mark.skipif(
    sys.platform != "linux", reason="Supported Linux VFS hard-exit check"
)
@pytest.mark.parametrize("exit_kind", ["terminate", "lease_exit", "normal"])
def test_disk_spill_and_hard_exit_preserve_other_files(tmp_path, exit_kind):
    from standalone.operations.process_worker import ProcessHandle

    retained = tmp_path / "retained-source.json"
    retained.write_bytes(b'{"synthetic":true}')
    active = tmp_path / "another-active-import.sqlite"
    with sqlite3.connect(active) as other:
        other.execute("CREATE TABLE preserved(value INTEGER)")
        other.execute("INSERT INTO preserved VALUES (1)")
        other.commit()
        expected = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(
            target=_parser_child, args=(str(tmp_path), child, exit_kind)
        )
        process.start()
        try:
            assert parent.poll(20), "Parser did not reach live scratch index"
            assert parent.recv() > 10_000_000, "Index must actually spill to disk"
            if exit_kind == "terminate":
                ProcessHandle(process).cancel()
            else:
                parent.send(True)
            process.join(20)
            assert not process.is_alive()
            assert (
                process.exitcode
                == {"terminate": -15, "lease_exit": 125, "normal": 0}[exit_kind]
            )
            assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == expected
            assert other.execute("SELECT value FROM preserved").fetchone() == (1,)
        finally:
            if process.is_alive():
                process.terminate()
                process.join(10)
            parent.close()
            child.close()
    # A restarted parser has a clean private index; retained evidence is unchanged.
    from .json_stream import object_members

    assert dict(object_members(io.BytesIO(retained.read_bytes()))) == {
        "synthetic": True
    }
