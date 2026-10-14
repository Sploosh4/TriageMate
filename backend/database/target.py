"""Explicit local PostgreSQL target; never creates or discovers an instance."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat

from backend.configuration.paths import load_paths, storage_layout

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class DatabaseTarget:
    host: str = "127.0.0.1"
    port: int = 55439
    database: str = "triagemate_ui_synthetic"
    work: Path = ROOT / "ui-engine/work/postgresql"
    external: bool = False
    credentials: Path | None = None

    @property
    def credential_directory(self) -> Path:
        """Explicit credential location; omitted keeps the retained layout."""
        return self.work if self.credentials is None else self.credentials


def load_target() -> DatabaseTarget:
    """An owner-only config may select an existing local instance.

    No passwords belong in this file. An optional credentials directory separates
    the existing role-specific files from runtime work; omission retains the old
    layout. Remote hosts are not supported by this local development/CI override.
    """
    configured = os.environ.get("TRIAGEMATE_DATABASE_TARGET")
    if configured is None:
        if storage_layout() == "legacy":
            return DatabaseTarget()
        configured = str(load_paths().config / "database.json")
    path = Path(configured)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Database target config must be absolute without symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError(
                "Database target config must be an owner-only regular file"
            )
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("Database target config is oversized")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate database target field")
            result[key] = value
        return result

    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) not in (
        {"host", "port", "database", "work"},
        {"host", "port", "database", "work", "credentials"},
    ):
        raise ValueError("Invalid database target fields")
    host, port, database, work = (
        data[key] for key in ("host", "port", "database", "work")
    )
    container_database = (
        os.environ.get("TRIAGEMATE_DEPLOYMENT") == "container" and host == "db"
    )
    if not isinstance(host, str) or not (
        host == "127.0.0.1" or host.startswith("/") or container_database
    ):
        raise ValueError("Database target must use loopback or a local Unix socket")
    if host.startswith("/") and ("," in host or Path(host).resolve() != Path(host)):
        raise ValueError("Invalid local database socket path")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid database target port")
    if not isinstance(database, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{0,62}", database
    ):
        raise ValueError("Invalid database target name")
    if (
        not isinstance(work, str)
        or not Path(work).is_absolute()
        or Path(work).resolve() != Path(work)
    ):
        raise ValueError("Database work directory must be absolute without symlinks")
    if Path(work).exists():
        info = Path(work).stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("Database work directory must be owner-only")
    credentials = None
    if "credentials" in data:
        value = data["credentials"]
        if (
            not isinstance(value, str)
            or not value
            or "\0" in value
            or ".." in Path(value).parts
            or not Path(value).is_absolute()
            or Path(value).resolve() != Path(value)
        ):
            raise ValueError("Credential directory must be absolute without symlinks")
        credentials = Path(value)
        if credentials.exists():
            info = credentials.stat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                raise ValueError("Credential directory must be owned with mode 0700")
    return DatabaseTarget(host, port, database, Path(work), True, credentials)
