"""Explicit synthetic schema preparation inside the retained native CI database.

Never creates/starts a cluster or database. Not called by UI startup or CI runs.
"""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import sys

import psycopg2

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.database.connections import LocalDatabase  # noqa: E402
from backend.database.target import load_target  # noqa: E402
from backend.database.credentials import read_credentials  # noqa: E402
from backend.database.installation import prepare_passwords, setup as verify_logins  # noqa: E402
from backend.database.schema import install, upgrade, verify  # noqa: E402


def private_json(path, value=None):
    """Create once; never replace credentials or follow a file symlink."""
    if path.exists() or path.is_symlink():
        with os.fdopen(
            os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "r"
        ) as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("CI state must be an owner-only regular file")
            return json.load(stream)
    if value is None:
        raise ValueError("Existing CI evidence schema has no local credentials")
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return value


def paths(ci_root):
    if os.environ.get("GITHUB_ACTIONS") == "true":
        raise ValueError("Evidence provisioning is manual only")
    if not ci_root.is_absolute() or ci_root.resolve() != ci_root:
        raise ValueError("CI environment must be an absolute non-symlink path")
    if (ci_root / "workspace").read_text().strip() != str(ROOT):
        raise ValueError("Use the already provisioned CI checkout")
    if (ci_root / "pg").resolve() != ci_root / "pg":
        raise ValueError("CI PostgreSQL directory must not be a symlink")
    if (ci_root / "pg/PG_VERSION").read_text().strip() != "16":
        raise ValueError("Existing PostgreSQL 16 cluster required")
    socket = ci_root / "socket"
    if not socket.is_dir() or socket.resolve() != socket:
        raise ValueError("Existing local CI socket directory required")
    work = ci_root / "ui-postgresql"
    if work.is_symlink():
        raise ValueError("CI evidence state must not be a symlink")
    work.mkdir(mode=0o700, exist_ok=True)
    if work.stat().st_uid != os.getuid() or work.stat().st_mode & 0o077:
        raise ValueError("CI evidence state must be owner-only")
    target = {
        "host": str(socket),
        "port": 5432,
        "database": "triagemate",
        "work": str(work),
    }
    path = ci_root / "ui-postgresql-target.json"
    if private_json(path, target) != target:
        raise ValueError("Existing CI target differs; no configuration replaced")
    return path, target


def seed(connection, database, ci_root):
    """Roles and initial schema commit together; unknown installations are refused."""
    try:
        result = _seed(connection, database, ci_root)
        connection.commit()
        return result
    except Exception:
        connection.rollback()
        raise


def _seed(connection, database, ci_root):
    # Role preparation and baseline installation share one caller-owned transaction.
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(731904215)")
        cursor.execute(
            "SELECT current_database(), current_user, current_setting('data_directory')"
        )
        if cursor.fetchone() != ("triagemate", "triagemate", str(ci_root / "pg")):
            raise ValueError("Connection is not the retained native CI database")
        cursor.execute(
            "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
        )
        manifest = cursor.fetchone()[0]
        cursor.execute(
            "SELECT nspname FROM pg_namespace WHERE nspname IN ('evidence','mock_support','epss_import','evidence_pipeline') ORDER BY 1"
        )
        schemas = cursor.fetchall()
        credential_path = database.CREDENTIALS / "credentials.json"
        if schemas:
            # Current metadata, the complete catalogue and all authority must match.
            # Legacy v113 requires the separate backup/restore/adoption workflow.
            read_credentials(credential_path, frozenset({"owner", "reader"}))
            cursor.execute("SET LOCAL ROLE tm_mock_owner")
            verify(cursor, require_latest=False)
            upgrade(cursor, database="triagemate")
            return False
        if manifest is not None:
            raise ValueError("Unknown database annotation; no reset or reseed")
        cursor.execute("SELECT rolname FROM pg_roles WHERE left(rolname,3)='tm_'")
        if cursor.fetchall():
            raise ValueError(
                "Reserved evidence roles already exist without a recognized schema"
            )
        credentials = private_json(
            credential_path,
            {"owner": secrets.token_urlsafe(32), "reader": secrets.token_urlsafe(32)},
        )
        credentials = read_credentials(credential_path, frozenset({"owner", "reader"}))
        # Mirrors the dedicated synthetic workstation's initdb owner authority.
        # Reader and importer roles retain their separately tested restrictions.
        cursor.execute(
            "CREATE ROLE tm_mock_owner LOGIN SUPERUSER PASSWORD %s",
            (credentials["owner"],),
        )
        cursor.execute("SET LOCAL ROLE tm_mock_owner")
        install(
            cursor,
            database="triagemate",
            passwords=prepare_passwords(database, cursor),
            profile="runner",
        )
    return True


@contextmanager
def operation_lock(ci_root):
    if not ci_root.is_absolute() or ci_root.resolve() != ci_root:
        raise ValueError("CI environment must be an absolute non-symlink path")
    descriptor = os.open(
        ci_root / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "r+") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("CI operation lock must be a regular file")
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def prepare(ci_root):
    with operation_lock(ci_root):
        _prepare(ci_root)


def _prepare(ci_root):
    target_path, target = paths(ci_root)
    os.environ["TRIAGEMATE_DATABASE_TARGET"] = str(target_path)
    database = LocalDatabase(load_target())
    connection = psycopg2.connect(
        host=target["host"],
        port=5432,
        dbname="triagemate",
        user="triagemate",
        connect_timeout=5,
    )
    try:
        seed(connection, database, ci_root)
    finally:
        connection.close()

    # Repeat-safe complete verification also exercises each restricted login.
    verify_logins(database, profile="runner")
    print(
        "Retained CI database evidence schema prepared; no instance or database created."
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: ci_evidence_database.py /absolute/persistent/ci/environment"
        )
    try:
        prepare(Path(sys.argv[1]))
    except Exception:
        raise SystemExit(
            "CI evidence preparation failed; preserve the state and inspect the local schema/configuration. No automatic reset."
        ) from None
