"""Explicit fixture-free baseline setup on an already provisioned local target."""

import argparse
from contextlib import closing

from psycopg2 import sql

from backend.database.credentials import read_credentials
from backend.database.installation import prepare_passwords, upgrade_existing
from backend.database.metadata import annotation, original_tables
from backend.database.schema import install, verify
from backend.database.target import ROOT as ROOT  # retained public source-root contract

MODE = "triagemate-baseline-v1"


def manifest():
    return annotation("empty")


def matches_manifest(value):
    return value == manifest()


def base_tables():
    return original_tables()


def verify_empty(cur):
    for namespace, table in original_tables():
        cur.execute(
            sql.SQL("SELECT EXISTS(SELECT 1 FROM {})").format(
                sql.Identifier(namespace, table)
            )
        )
        if cur.fetchone() != (False,):
            raise ValueError("Empty bootstrap contains records: " + table)


def credentials(database):
    return read_credentials(
        database.CREDENTIALS / "credentials.json", frozenset({"owner", "reader"})
    )


def populate(conn, database):
    """Atomically install the complete schema; no cluster creation or fixture rows."""
    if not database.TARGET.external:
        raise ValueError("Empty bootstrap requires an explicit local database target")
    with conn, conn.cursor() as cur:
        passwords = prepare_passwords(database, cur)
        created = install(
            cur, database=database.DB, passwords=passwords, profile="empty"
        )
        if created:
            verify_empty(cur)
        verify(cur)
    return created


def upgrade(database):
    """Run registered future revisions, never historical per-feature upgrades."""
    if not database.TARGET.external:
        raise ValueError("Empty bootstrap requires an explicit local database target")
    return upgrade_existing(database)


def main():
    from .runtime import local_database

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "upgrade"))
    args = parser.parse_args()
    database = local_database()
    if args.action == "upgrade":
        changed = upgrade(database)
    else:
        with closing(database.connect()) as conn:
            changed = populate(conn, database)
    print(
        "Evidence schema updated."
        if changed
        else "Evidence schema verified; unchanged."
    )


if __name__ == "__main__":
    main()
