"""Restore provenance-checked synthetic v113 test data, never a live target."""

from contextlib import closing
import gzip
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

from backend.database.schema import (
    InstallPasswords,
    provision_empty,
    verify_predecessor,
)

FIXTURES = Path(__file__).with_name("fixtures") / "v113"


def restore_predecessor(database, temporary, *, profile="empty"):
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    assert manifest["origin"] == "synthetic"
    reference = manifest["profiles"][profile]
    raw = (FIXTURES / reference["archive"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference["sha256"]
    expanded = gzip.decompress(raw)
    assert hashlib.sha256(expanded).hexdigest() == reference["uncompressed_sha256"]
    archive = temporary / "synthetic-predecessor.dump"
    descriptor = os.open(archive, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(expanded)
    runtime = (
        Path(__file__).resolve().parents[2]
        / "ui-engine/work/postgresql/runtime/usr/lib/postgresql/16/bin/pg_restore"
    )
    binary = runtime if runtime.exists() else Path(shutil.which("pg_restore"))
    passwords = InstallPasswords(*(secrets.token_urlsafe(32) for _ in range(3)))
    with closing(database.connect()) as conn:
        with conn, conn.cursor() as cur:
            provision_empty(
                cur, database=database.DB, passwords=passwords, profile=profile
            )
        result = subprocess.run(
            [
                str(binary),
                "--single-transaction",
                "--exit-on-error",
                "--no-password",
                "--dbname",
                database.DB,
                str(archive),
            ],
            env={
                **{
                    key: value
                    for key, value in os.environ.items()
                    if not key.startswith("PG")
                },
                "PGHOST": database.TARGET.host,
                "PGPORT": str(database.PORT),
                "PGUSER": database.OWNER,
                "PGPASSWORD": conn.info.password,
            },
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr
        with conn, conn.cursor() as cur:
            from psycopg2 import sql

            cur.execute(
                sql.SQL("COMMENT ON DATABASE {} IS %s").format(
                    sql.Identifier(database.DB)
                ),
                (json.dumps(reference["annotation"], sort_keys=True),),
            )
            assert verify_predecessor(cur) == profile
