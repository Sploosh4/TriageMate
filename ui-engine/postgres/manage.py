"""Explicit local synthetic PostgreSQL lifecycle. Never used by application startup."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from psycopg2 import sql

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from backend.database.target import load_target  # noqa: E402
from backend.database.connections import LocalDatabase  # noqa: E402
from backend.database.credentials import read_credentials  # noqa: E402
from backend.database.installation import setup as install_schema  # noqa: E402

TARGET = load_target()
WORK = TARGET.work
BIN = WORK / "runtime/usr/lib/postgresql/16/bin"
DATA = WORK / "data"
SOCKET = WORK / "socket"
DB = TARGET.database
OWNER = "tm_mock_owner"
READER = "tm_mock_reader"
PORT = TARGET.port


def credentials():
    return read_credentials(
        TARGET.credential_directory / "credentials.json", frozenset({"owner", "reader"})
    )


def connect(database=DB, reader=False):
    return LocalDatabase(TARGET).connect(database, reader=reader)


def native(name, *args, check=True):
    if TARGET.external:
        raise RuntimeError("External local database lifecycle is managed separately")
    return subprocess.run(
        [str(BIN / name), *map(str, args)], check=check, capture_output=True, text=True
    )


def initialize():
    if TARGET.external:
        raise RuntimeError(
            "An external target must already be provisioned; no new instance is created"
        )
    WORK.mkdir(parents=True, exist_ok=True)
    WORK.chmod(0o700)
    SOCKET.mkdir(exist_ok=True, mode=0o700)
    if not (BIN / "initdb").exists():
        raise RuntimeError(
            "Native PostgreSQL 16 runtime missing; see README. No automatic download."
        )
    if not (TARGET.credential_directory / "credentials.json").exists():
        if DATA.exists():
            raise RuntimeError(
                "Existing data directory has no credentials; refuse to replace it."
            )
        path = TARGET.credential_directory / "credentials.json"
        with path.open("x") as f:
            os.chmod(path, 0o600)
            json.dump(
                {
                    "owner": secrets.token_urlsafe(32),
                    "reader": secrets.token_urlsafe(32),
                },
                f,
            )
    if not (DATA / "PG_VERSION").exists():
        pw = WORK / "init-password"
        with pw.open("x") as f:
            os.chmod(pw, 0o600)
            f.write(credentials()["owner"])
        try:
            native(
                "initdb",
                "-D",
                DATA,
                "-U",
                OWNER,
                "--auth-local=scram-sha-256",
                "--auth-host=scram-sha-256",
                "--pwfile",
                pw,
                "--encoding=UTF8",
                "--locale=C.UTF-8",
                "-L",
                WORK / "runtime/usr/share/postgresql/16",
            )
        finally:
            pw.unlink()


def start():
    if TARGET.external:
        raise RuntimeError("External local database lifecycle is managed separately")
    config = DATA / "postgresql.conf"
    text = config.read_text()
    if "# TriageMate synthetic runtime" not in text:
        with config.open("a") as f:
            f.write("\n# TriageMate synthetic runtime\njit=off\ntimezone=UTC\n")
    if native("pg_ctl", "-D", DATA, "status", check=False).returncode == 0:
        return
    # Paths contain spaces: postgres parses this option string, not a shell.
    native(
        "pg_ctl",
        "-D",
        DATA,
        "-l",
        WORK / "server.log",
        "-o",
        f'-p {PORT} -k "" -h 127.0.0.1',
        "-w",
        "start",
    )


def setup():
    """Explicit local lifecycle followed by the complete synthetic baseline.

    Existing installations must pass the shared schema/authority checks. Legacy
    databases require verified backup and adoption; setup never resets them.
    """
    initialize()
    start()
    with closing(connect("postgres")) as admin:
        admin.autocommit = True
        with admin.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (DB,))
            if cur.fetchone() is None:
                cur.execute(
                    sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(
                        sql.Identifier(DB)
                    )
                )
                cur.execute(
                    sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(
                        sql.Identifier(DB)
                    )
                )
    created = install_schema(LocalDatabase(TARGET), profile="synthetic")
    print(
        "Created and verified the complete synthetic database baseline."
        if created
        else "Existing database baseline verified; no data reseeded."
    )


def status():
    with closing(connect()) as conn, conn.cursor() as c:
        c.execute(
            "SELECT version(), pg_database_size(current_database()), pg_postmaster_start_time()"
        )
        print(
            json.dumps(
                dict(zip(["version", "database_bytes", "started_at"], c.fetchone())),
                default=str,
            )
        )
        c.execute(
            "SELECT backend_type,count(*) FROM pg_stat_activity GROUP BY backend_type ORDER BY backend_type"
        )
        print(json.dumps(c.fetchall()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["setup", "start", "stop", "status"])
    action = parser.parse_args().action
    try:
        if action == "stop":
            native("pg_ctl", "-D", DATA, "-m", "fast", "-w", "stop")
        else:
            globals()[action]()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"PostgreSQL {Path(exc.cmd[0]).name} failed: {exc.stderr or exc.stdout}"
        ) from exc
