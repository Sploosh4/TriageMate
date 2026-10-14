"""Fresh, private PostgreSQL clusters prove fixture-free installation boundaries."""

from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

import pytest
import psycopg2
from psycopg2 import sql

from . import bootstrap
from .runtime import local_database


def postgres_runtime():
    runtime = bootstrap.ROOT / "ui-engine/work/postgresql/runtime/usr"
    binary = runtime / "lib/postgresql/16/bin"
    if not (binary / "initdb").exists():
        installed = shutil.which("initdb")
        if installed is None:
            pytest.fail(
                "Installed PostgreSQL 16 binaries required; no download performed"
            )
        binary = Path(installed).resolve().parent
        runtime = binary.parents[3]
    version = subprocess.check_output([str(binary / "initdb"), "--version"], text=True)
    assert "(PostgreSQL) 16." in version, (
        "Isolated bootstrap tests require PostgreSQL 16"
    )
    return runtime, binary


@contextmanager
def isolated_database(monkeypatch, *, owner="tm_mock_owner", name="empty_test"):
    """Disposable PostgreSQL 16 cluster; never uses the retained CI environment."""
    runtime, binary = postgres_runtime()
    with TemporaryDirectory(prefix="tm-empty-") as directory:
        root = Path(directory)
        work = root / "state"
        work.mkdir(mode=0o700)
        socket = root / "socket"
        socket.mkdir(mode=0o700)
        password = secrets.token_urlsafe(32)
        credential = work / "credentials.json"
        credential.write_text(
            json.dumps({"owner": password, "reader": secrets.token_urlsafe(32)})
        )
        credential.chmod(0o600)
        pw = root / "pw"
        pw.write_text(password)
        pw.chmod(0o600)
        target = root / "target.json"
        target.write_text(
            json.dumps(
                {
                    "host": str(socket),
                    "port": 5432,
                    "database": name,
                    "work": str(work),
                }
            )
        )
        target.chmod(0o600)
        monkeypatch.setenv("TRIAGEMATE_DATABASE_TARGET", str(target))
        database = local_database()
        subprocess.run(
            [
                str(binary / "initdb"),
                "-D",
                str(root / "pg"),
                "-U",
                owner,
                "--auth-local=scram-sha-256",
                "--auth-host=scram-sha-256",
                "--pwfile",
                str(pw),
                "--encoding=UTF8",
                "--locale=C.UTF-8",
                "-L",
                str(runtime / "share/postgresql/16"),
            ],
            check=True,
            capture_output=True,
        )
        pw.unlink()
        with (root / "pg/postgresql.conf").open("a") as stream:
            stream.write(
                "\nlisten_addresses=''\njit=off\ntimezone='UTC'\nshared_buffers='16MB'\nmax_connections=15\ndynamic_shared_memory_type=mmap\n"
            )
        subprocess.run(
            [
                str(binary / "pg_ctl"),
                "-D",
                str(root / "pg"),
                "-l",
                str(root / "server.log"),
                "-o",
                "-k " + str(socket),
                "-w",
                "start",
            ],
            check=True,
            capture_output=True,
        )
        try:
            with closing(
                psycopg2.connect(
                    host=str(socket),
                    port=5432,
                    dbname="postgres",
                    user=owner,
                    password=password,
                    connect_timeout=5,
                )
            ) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(
                        sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(
                            sql.Identifier(name)
                        )
                    )
            yield database
        finally:
            subprocess.run(
                [
                    str(binary / "pg_ctl"),
                    "-D",
                    str(root / "pg"),
                    "-m",
                    "fast",
                    "-w",
                    "stop",
                ],
                check=True,
                capture_output=True,
            )


@pytest.fixture
def empty_database(monkeypatch):
    with isolated_database(monkeypatch) as database:
        yield database


def command(*args):
    result = subprocess.run(
        [sys.executable, *args],
        cwd=bootstrap.ROOT,
        env=os.environ,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_empty_install_has_no_fixture_dependency_and_verifies(
    empty_database, monkeypatch
):
    database = empty_database
    original = Path.read_text

    def no_fixture(path, *args, **kwargs):
        assert path.name != "fixtures.json", (
            "Empty installation opened synthetic fixtures"
        )
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", no_fixture)
    with closing(database.connect()) as conn:
        bootstrap.populate(conn, database)
        with conn.cursor() as cur:
            bootstrap.verify_empty(cur)
            cur.execute(
                "SELECT rolcanlogin FROM pg_roles WHERE rolname='tm_mock_fixture'"
            )
            assert cur.fetchone() == (False,)
            cur.execute(
                "SELECT 1 FROM information_schema.role_table_grants WHERE grantee='tm_mock_fixture' AND privilege_type IN ('INSERT','UPDATE','DELETE')"
            )
            assert cur.fetchone() is None
        assert not bootstrap.populate(conn, database)
    command("-m", "standalone.evidence_pipeline.runtime", "check")
    command("-m", "standalone.evidence_pipeline.runtime", "upgrade")
    with closing(database.connect()) as conn, conn.cursor() as cur:
        bootstrap.verify_empty(cur)
    with closing(database.connect(reader=True)) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM evidence.source_connections")
        assert cur.fetchone() == (0,)
        with pytest.raises(Exception, match="read-only|permission denied"):
            cur.execute(
                "INSERT INTO evidence.source_connections(id,source_name,input_kind) VALUES(gen_random_uuid(),'x','epss')"
            )


@pytest.mark.parametrize(
    "existing", ["annotation", "schema", "table", "function", "type", "role"]
)
def test_existing_state_is_preserved_and_refused(empty_database, existing):
    database = empty_database
    statements = {
        "annotation": "COMMENT ON DATABASE empty_test IS 'unrecognized'",
        "schema": "CREATE SCHEMA unrelated",
        "table": "CREATE TABLE public.unrelated(id int)",
        "function": "CREATE FUNCTION public.unrelated() RETURNS int LANGUAGE sql AS $$SELECT 1$$",
        "type": "CREATE TYPE public.unrelated AS ENUM ('a')",
        "role": "CREATE ROLE tm_pipeline_writer NOLOGIN",
    }
    with closing(database.connect()) as conn:
        with conn, conn.cursor() as cur:
            cur.execute(statements[existing])
        with pytest.raises(ValueError):
            bootstrap.populate(conn, database)
        with conn.cursor() as cur:
            cur.execute("SELECT to_regnamespace('evidence')")
            assert cur.fetchone() == (None,)
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname='tm_mock_reader'")
            assert cur.fetchone() is None


def test_empty_manifest_is_distinct_and_hash_checked():
    value = bootstrap.manifest()
    assert bootstrap.matches_manifest(value)
    assert value["synthetic"] is False
    assert value["fixture_sha256"] is None
    value["fixture_sha256"] = "0" * 64
    assert not bootstrap.matches_manifest(value)
    assert not bootstrap.matches_manifest(None)
    assert not bootstrap.matches_manifest({"bootstrap": bootstrap.MODE})


def test_full_baseline_starts_without_fixture_rows(empty_database):
    database = empty_database
    with closing(database.connect()) as conn:
        bootstrap.populate(conn, database)
    bootstrap.upgrade(database)
    with closing(database.connect()) as conn, conn.cursor() as cur:
        bootstrap.verify_empty(cur)
        cur.execute(
            "SELECT version FROM evidence_pipeline.installation WHERE singleton"
        )
        from backend.database.schema import latest_version

        assert cur.fetchone() == (latest_version(),)
    command("-m", "standalone.evidence_pipeline.runtime", "check")
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from .test_public_snapshot import attempt
    from .test_attribution import verify
    from .runtime import connect

    # Explicit synthetic test payload, inserted only after the entire empty
    # consolidated baseline: accepted evidence must still have normal attribution.
    value = attempt()
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        authorize_connection(cur, value)
    with closing(connect()) as conn, conn:
        assert not persist_public(conn, value)["replayed"]
        assert persist_public(conn, value)["replayed"]
    with closing(database.connect()) as conn, conn.cursor() as cur:
        assert verify(cur)["epss_observations"] == 1
        cur.execute("SAVEPOINT valid_evidence")
        cur.execute("UPDATE evidence.epss_observations SET probability=0.99")
        with pytest.raises(AssertionError):
            verify(cur)
        cur.execute("ROLLBACK TO SAVEPOINT valid_evidence")
        cur.execute(
            "INSERT INTO evidence.software(id,product_name) VALUES(gen_random_uuid(),'Unattributed synthetic test')"
        )
        with pytest.raises(AssertionError, match="Unexplained"):
            verify(cur)


@pytest.mark.parametrize("damage", ["public", "symlink", "short", "oversized"])
def test_unsafe_credentials_are_refused_before_bootstrap(tmp_path, damage):
    from types import SimpleNamespace

    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"owner": "x" * 32, "reader": "y" * 32}))
    path.chmod(0o600)
    if damage == "public":
        path.chmod(0o644)
    elif damage == "symlink":
        original = tmp_path / "original"
        path.rename(original)
        path.symlink_to(original)
    elif damage == "short":
        path.write_text(json.dumps({"owner": "short", "reader": "y" * 32}))
    else:
        path.write_bytes(b" " * 16385)
    with pytest.raises((ValueError, OSError)):
        bootstrap.credentials(SimpleNamespace(CREDENTIALS=tmp_path))
