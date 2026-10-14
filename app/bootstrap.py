"""Prepare a fresh container installation; never reset retained data or secrets."""

import json
import os
from pathlib import Path
import secrets

from backend.configuration.paths import validate_directory
from backend.database.connections import LocalDatabase
from backend.database.credentials import create_credentials, read_credentials
from backend.database.installation import setup
from backend.database.target import load_target


def main() -> None:
    os.umask(0o077)
    root = Path("/var/lib/triagemate")
    root.mkdir(mode=0o700, exist_ok=True)
    validate_directory(root)
    for name in ("credentials", "state", "evidence"):
        path = root / name
        path.mkdir(mode=0o700, exist_ok=True)
        validate_directory(path)
    owner = os.environ["TRIAGEMATE_DB_OWNER_PASSWORD"]
    if len(owner) < 32:
        raise ValueError("Database password must have at least 32 characters")
    credential = root / "credentials/credentials.json"
    if credential.exists():
        if (
            read_credentials(credential, frozenset({"owner", "reader"}))["owner"]
            != owner
        ):
            raise ValueError(
                "Database password differs; use explicit credential recovery"
            )
    else:
        create_credentials(
            credential, {"owner": owner, "reader": secrets.token_urlsafe(32)}
        )
    target = root / "database.json"
    expected = {
        "host": "db",
        "port": 5432,
        "database": "triagemate",
        "work": str(root),
        "credentials": str(root / "credentials"),
    }
    if target.exists():
        if json.loads(target.read_text()) != expected:
            raise ValueError(
                "Database configuration differs; existing configuration preserved"
            )
    else:
        with target.open("x") as stream:
            json.dump(expected, stream)
    database = LocalDatabase(load_target())
    setup(database, profile="empty")
    print(
        "Database schema verified. Existing evidence and credentials preserved.",
        flush=True,
    )


if __name__ == "__main__":
    main()
