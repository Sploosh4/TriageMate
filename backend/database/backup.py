"""Protected, consistent logical backups for an explicit local database target.

Backup completion is not restore verification or adoption authority. No source
objects, evidence, passwords or installation metadata are changed by capture.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import TYPE_CHECKING, BinaryIO

from psycopg2 import sql
from psycopg2.extensions import connection, cursor

from backend.configuration.paths import validate_directory
from .baseline.catalogue import fingerprint
from .baseline.evidence import evidence_receipt
from .connections import LocalDatabase
from . import retained_runner

if TYPE_CHECKING:
    from .schema import InstallPasswords

FORMAT = "triagemate-database-backup-v1"


def _private_file(path: Path) -> BinaryIO:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    return os.fdopen(descriptor, "wb")


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _durable_write(path: Path, value: object) -> None:
    with _private_file(path) as stream:
        stream.write((json.dumps(value, sort_keys=True, indent=2) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def sequence_receipt(cur: cursor) -> dict[str, list[int | bool]]:
    """Sequence state is not MVCC; compare before and after a quiescent capture."""
    cur.execute(
        "SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' ORDER BY 1,2"
    )
    result = {}
    for schema, name in cur.fetchall():
        cur.execute(
            sql.SQL("SELECT last_value,is_called FROM {}").format(
                sql.Identifier(schema, name)
            )
        )
        row = cur.fetchone()
        if row is None:
            raise ValueError("Sequence state unavailable")
        result[f"{schema}.{name}"] = [int(row[0]), bool(row[1])]
    return result


def database_identity(cur: cursor) -> dict[str, str | int]:
    cur.execute(
        "SELECT current_database(),current_user,current_setting('server_version_num')::integer,(SELECT system_identifier::text FROM pg_control_system()),(SELECT oid::integer FROM pg_database WHERE datname=current_database())"
    )
    row = cur.fetchone()
    if row is None or row[1] != "tm_mock_owner" or not 160000 <= row[2] < 170000:
        raise ValueError("Explicit PostgreSQL 16 application-owner target required")
    return {
        "database": row[0],
        "owner": row[1],
        "server_version": row[2],
        "cluster": row[3],
        "database_oid": row[4],
    }


def _environment(conn: connection) -> dict[str, str]:
    # Do not inherit a service, host, option or passfile override that could send
    # a subprocess to a different target. Never put credentials in argv or logs.
    params = conn.get_dsn_parameters()
    return {
        **{key: value for key, value in os.environ.items() if not key.startswith("PG")},
        "PGHOST": params["host"],
        "PGPORT": params["port"],
        "PGDATABASE": params["dbname"],
        "PGUSER": params["user"],
        "PGPASSWORD": conn.info.password or "",
        "PGCONNECT_TIMEOUT": "5",
        "PGAPPNAME": "triagemate-backup",
    }


def lock_relations(cur: cursor, *, installation: bool = True) -> None:
    """Hold SHARE locks on stored relations, optionally excepting the ledger."""
    cur.execute("SET LOCAL lock_timeout='20s'")
    cur.execute(
        "SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','m') AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' ORDER BY 1,2"
    )
    for schema, table in cur.fetchall():
        if not installation and (schema, table) == (
            "evidence_pipeline",
            "installation",
        ):
            continue
        cur.execute(
            sql.SQL("LOCK TABLE {} IN SHARE MODE").format(sql.Identifier(schema, table))
        )


def lock_source(cur: cursor, *, installation: bool = True) -> None:
    """Hold writer locks and SHARE relation locks until caller commit/rollback."""
    cur.execute("SET LOCAL lock_timeout='20s'")
    for key in (731904215, 731904216, 731904217):
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
    lock_relations(cur, installation=installation)


def capture(database: LocalDatabase, directory: Path, *, binary: Path) -> Path:
    """Capture an immutable archive and matching receipt; refuse path reuse.

    Stop application-owned writers before capture. The source remains locked
    against row/schema changes while PostgreSQL exports a shared snapshot for
    pg_dump and the evidence receipt. Sequence changes invalidate the capture.
    Partial files are retained privately on failure, without a completion receipt.
    """
    from .schema import verify_supported

    validate_directory(directory.parent)
    if not binary.is_absolute() or binary.name != "pg_dump":
        raise ValueError("Explicit installed pg_dump path required")
    version = subprocess.check_output([str(binary), "--version"], text=True)
    if "(PostgreSQL) 16." not in version:
        raise ValueError("Backup requires PostgreSQL 16 pg_dump")
    directory.mkdir(mode=0o700)
    validate_directory(directory)
    with closing(database.connect()) as guard, guard, guard.cursor() as lock:
        identity = database_identity(lock)
        if identity["database"] != database.DB:
            raise ValueError("Backup target identity differs")
        lock_source(lock)
        with closing(database.connect()) as conn:
            conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
            with conn.cursor() as cur:
                cur.execute("SELECT pg_export_snapshot()")
                snapshot = cur.fetchone()
                if snapshot is None:
                    raise ValueError("Could not export database snapshot")
                schema = fingerprint(cur)
                verify_supported(cur)
                sequences = sequence_receipt(cur)
                rows = evidence_receipt(cur)
                cur.execute(
                    "SELECT version,artifacts,signature FROM evidence_pipeline.installation WHERE singleton"
                )
                installation = cur.fetchall()
                if len(installation) != 1:
                    raise ValueError("Exactly one installation record required")
                cur.execute(
                    "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
                )
                annotation = cur.fetchone()
                archive = directory / "database.dump"
                with (
                    _private_file(archive) as stream,
                    _private_file(directory / "dump.log") as log,
                ):
                    completed = subprocess.run(
                        [
                            str(binary),
                            "--format=custom",
                            "--no-password",
                            "--snapshot",
                            snapshot[0],
                        ],
                        env=_environment(conn),
                        stdout=stream,
                        stderr=log,
                        timeout=1800,
                        check=False,
                    )
                    stream.flush()
                    os.fsync(stream.fileno())
                if completed.returncode:
                    raise ValueError(
                        "Database backup failed; inspect the protected dump log"
                    )
                if sequence_receipt(cur) != sequences:
                    raise ValueError(
                        "Sequence changed during backup; stop owned writers and retry into a new directory"
                    )
                if fingerprint(cur) != schema:
                    raise ValueError("Schema or global authority changed during backup")
                if retained_runner.matches(schema):
                    retained_runner.verify(cur)
                receipt = {
                    "format": FORMAT,
                    "source": identity,
                    "schema": schema,
                    "rows": rows,
                    "sequences": sequences,
                    "installation": installation[0],
                    "annotation": annotation[0] if annotation else None,
                    "archive_sha256": _digest(archive),
                }
                _durable_write(directory / "receipt.json", receipt)
                descriptor = os.open(
                    directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                )
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
    return directory / "receipt.json"


def _read_private(path: Path, *, limit: int = 16 * 1024 * 1024) -> bytes:
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError(
                "Backup files must be owner-only regular files with mode 0600"
            )
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Backup receipt is oversized")
    return value


def _archive_digest(path: Path) -> str:
    import stat

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError(
                "Backup archive must be an owner-only regular file with mode 0600"
            )
        return hashlib.file_digest(stream, "sha256").hexdigest()


def restore_isolated(
    database: LocalDatabase,
    directory: Path,
    *,
    binary: Path,
    passwords: "InstallPasswords",
) -> Path:
    """Restore only into an empty database on a different PostgreSQL cluster.

    Source files remain untouched. A failed restore leaves its isolated target
    available for investigation; no reset, cleanup or source fallback occurs.
    Completion checks schema/authority, every row, sequences and metadata.
    """
    from .schema import provision_empty
    from .baseline.profiles import identify_layout

    validate_directory(directory)
    receipt_raw = _read_private(directory / "receipt.json")
    receipt = json.loads(receipt_raw)
    if (
        not isinstance(receipt, dict)
        or receipt.get("format") != FORMAT
        or not isinstance(receipt.get("source"), dict)
    ):
        raise ValueError("Unrecognized backup receipt")
    if not isinstance(receipt.get("schema"), dict):
        raise ValueError("Backup schema is not a trusted supported baseline layout")
    profile, _ = identify_layout(receipt["schema"])
    archive = directory / "database.dump"
    if _archive_digest(archive) != receipt.get("archive_sha256"):
        raise ValueError("Backup archive digest differs")
    if not binary.is_absolute() or binary.name != "pg_restore":
        raise ValueError("Explicit installed pg_restore path required")
    version = subprocess.check_output([str(binary), "--version"], text=True)
    if "(PostgreSQL) 16." not in version:
        raise ValueError("Restore requires PostgreSQL 16 pg_restore")
    if (directory / "restore.json").exists() or (directory / "restore.log").exists():
        raise ValueError(
            "Restore attempt already recorded; preserve it before retrying"
        )
    with closing(database.connect()) as conn:
        with conn, conn.cursor() as cur:
            identity = database_identity(cur)
            if identity["cluster"] == receipt["source"].get("cluster"):
                raise ValueError(
                    "Restore must use a different isolated PostgreSQL cluster"
                )
            provision_empty(
                cur, database=database.DB, passwords=passwords, profile=profile
            )
            if retained_runner.matches(receipt["schema"]):
                retained_runner.prepare_isolated_restore(cur)
        with _private_file(directory / "restore.log") as log:
            completed = subprocess.run(
                [
                    str(binary),
                    "--single-transaction",
                    "--exit-on-error",
                    "--no-password",
                    "--dbname",
                    database.DB,
                    str(archive),
                ],
                env=_environment(conn),
                stdout=log,
                stderr=log,
                timeout=1800,
                check=False,
            )
        if completed.returncode:
            raise ValueError(
                "Isolated restore failed; inspect the protected restore log"
            )
        with conn, conn.cursor() as cur:
            cur.execute(
                sql.SQL("COMMENT ON DATABASE {} IS %s").format(
                    sql.Identifier(database.DB)
                ),
                (receipt.get("annotation"),),
            )
    return verify_restored(database, directory)


def verify_restored(database: LocalDatabase, directory: Path) -> Path:
    """Finish a restored copy's integrity checks without restoring over it.

    An interrupted comparison may be retried against the preserved isolated
    target. No source/target data, roles or annotation are repaired. All original
    archive, schema, row, sequence and metadata checks still have to pass.
    """
    from .schema import contract
    from .baseline.profiles import identify_layout

    validate_directory(directory)
    if (directory / "restore.json").exists():
        raise ValueError("Completed restore proof already exists; preserve it")
    receipt_raw = _read_private(directory / "receipt.json")
    receipt = json.loads(receipt_raw)
    if (
        not isinstance(receipt, dict)
        or receipt.get("format") != FORMAT
        or not isinstance(receipt.get("source"), dict)
        or not isinstance(receipt.get("schema"), dict)
    ):
        raise ValueError("Unrecognized backup receipt")
    profile, _ = identify_layout(receipt["schema"])
    archive = directory / "database.dump"
    if _archive_digest(archive) != receipt.get("archive_sha256"):
        raise ValueError("Backup archive digest differs")
    with closing(database.connect()) as conn:
        with conn.cursor() as cur:
            identity = database_identity(cur)
            if identity["cluster"] == receipt["source"].get("cluster"):
                raise ValueError(
                    "Restore must use a different isolated PostgreSQL cluster"
                )
        conn.rollback()
        conn.set_session(isolation_level="REPEATABLE READ", readonly=True)
        with conn.cursor() as cur:
            # pg_dump reparses four equivalent predecessor definitions; the
            # fresh-layout contract was independently constructed for this case.
            retained = retained_runner.matches(receipt["schema"])
            expected = (
                retained_runner.contract() if retained else contract(profile=profile)
            )
            if fingerprint(cur) != expected:
                raise ValueError(
                    "Restored schema or authority differs from its trusted contract"
                )
            if retained:
                retained_runner.verify(cur)
            cur.execute(
                "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
            )
            if cur.fetchone() != (receipt.get("annotation"),):
                raise ValueError("Restored database annotation differs")
            if evidence_receipt(cur) != receipt.get("rows"):
                raise ValueError("Restored evidence row counts or hashes differ")
            if sequence_receipt(cur) != receipt.get("sequences"):
                raise ValueError("Restored sequence state differs")
            cur.execute(
                "SELECT version,artifacts,signature FROM evidence_pipeline.installation WHERE singleton"
            )
            rows = cur.fetchall()
            if len(rows) != 1 or list(rows[0]) != receipt.get("installation"):
                raise ValueError("Restored installation metadata differs")
        if _archive_digest(archive) != receipt.get("archive_sha256"):
            raise ValueError("Backup archive changed during restore")
        if _read_private(directory / "receipt.json") != receipt_raw:
            raise ValueError("Backup receipt changed during verification")
        result = {
            "format": "triagemate-database-restore-v1",
            "source": receipt["source"],
            "target": identity,
            "archive_sha256": receipt["archive_sha256"],
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "verified": True,
        }
        _durable_write(directory / "restore.json", result)
    return directory / "restore.json"


def verified_restore_receipt(directory: Path) -> dict[str, object]:
    """Require an intact archive and a matching completed isolated-restore proof."""
    validate_directory(directory)
    raw = _read_private(directory / "receipt.json")
    receipt = json.loads(raw)
    restored = json.loads(_read_private(directory / "restore.json"))
    if (
        not isinstance(receipt, dict)
        or receipt.get("format") != FORMAT
        or not isinstance(restored, dict)
        or restored.get("format") != "triagemate-database-restore-v1"
    ):
        raise ValueError("Unrecognized backup or restore receipt")
    source, target = restored.get("source"), restored.get("target")
    if (
        not isinstance(source, dict)
        or not isinstance(target, dict)
        or not source.get("cluster")
        or source.get("cluster") == target.get("cluster")
    ):
        raise ValueError("Independent restore target proof required")
    if (
        restored.get("verified") is not True
        or source != receipt.get("source")
        or restored.get("receipt_sha256") != hashlib.sha256(raw).hexdigest()
        or restored.get("archive_sha256") != receipt.get("archive_sha256")
        or _archive_digest(directory / "database.dump") != receipt.get("archive_sha256")
    ):
        raise ValueError("Backup/restore proof differs from the protected artifacts")
    return dict(receipt)
