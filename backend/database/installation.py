"""Explicit application-schema setup on an already provisioned local target."""

from contextlib import closing
import secrets

import psycopg2
from psycopg2.extensions import cursor

from .connections import LocalDatabase
from .credentials import create_credentials, read_credentials
from .schema import InstallPasswords, install, upgrade


def prepare_passwords(database: LocalDatabase, cur: cursor) -> InstallPasswords:
    existing = read_credentials(
        database.CREDENTIALS / "credentials.json", frozenset({"owner", "reader"})
    )
    passwords = {"reader": existing["reader"]}
    for key, role, name in (
        ("importer", "tm_epss_importer", "epss-importer.json"),
        ("writer", "tm_pipeline_writer", "pipeline-writer.json"),
    ):
        path = database.CREDENTIALS / name
        if not path.exists() and not path.is_symlink():
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,))
            if cur.fetchone():
                raise ValueError(
                    "An existing database role has no credential; explicit recovery required"
                )
            create_credentials(path, {"password": secrets.token_urlsafe(32)})
        passwords[key] = read_credentials(path, frozenset({"password"}))["password"]
    return InstallPasswords(
        passwords["reader"], passwords["importer"], passwords["writer"]
    )


def setup(database: LocalDatabase, *, profile: str = "empty") -> bool:
    """Prepare immutable credentials, install atomically, verify all login roles.

    Does not create/start a PostgreSQL cluster or database. Existing credentials
    and roles are never reset, even after an uncertain commit acknowledgement.
    """
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        passwords = prepare_passwords(database, cur)
        created = install(
            cur, database=database.DB, passwords=passwords, profile=profile
        )
    for role, password in passwords.validated().items():
        with (
            closing(
                psycopg2.connect(
                    host=database.TARGET.host,
                    port=database.PORT,
                    dbname=database.DB,
                    user=role,
                    password=password,
                    connect_timeout=5,
                )
            ) as conn,
            conn.cursor() as cur,
        ):
            cur.execute("SELECT current_user")
            if cur.fetchone() != (role,):
                raise ValueError("Unexpected database login identity")
    return created


def upgrade_existing(database: LocalDatabase) -> bool:
    """Run only registered post-baseline revisions; caller requests this explicitly."""
    with closing(database.connect()) as conn, conn, conn.cursor() as cur:
        return upgrade(cur, database=database.DB)
