"""Owner-only local database credential files, without implicit rotation."""

import json
import os
from pathlib import Path
import stat
from collections.abc import Mapping

from backend.configuration.paths import validate_directory


def read_credentials(path: Path, fields: frozenset[str]) -> dict[str, str]:
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("Credential path must be absolute without symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("Credential file must be an owner-only regular file")
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError("Credential file is oversized")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate credential field")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or any(
            not isinstance(secret, str) or len(secret) < 32 or "\0" in secret
            for secret in value.values()
        )
    ):
        raise ValueError("Invalid database credential fields")
    return dict(value)


def create_credentials(path: Path, values: Mapping[str, str]) -> None:
    """Create once before the SQL transaction; retries retain the same secrets."""
    validate_directory(path.parent)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w") as stream:
        json.dump(dict(values), stream)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
