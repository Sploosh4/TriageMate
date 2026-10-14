"""Register an explicit package query and import its durable evidence atomically."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import sys
from uuid import uuid4

import psycopg2

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .commands import load_scope
from .contracts import Snapshot
from standalone.evidence_pipeline.parsing.osv_query import (
    package_query,
    query_bytes,
    validate_scope,
)
from backend.database.schema import verify
from standalone.evidence_pipeline.persistence.osv_query_snapshot import from_collection
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .runtime import connect, local_database
from standalone.evidence_pipeline.persistence.store import (
    ReplayConflict,
    source_connection,
)


def register(scope, query):
    validate_scope(scope, synthetic=True)
    encoded = query_bytes(query).decode()
    now = datetime.now(timezone.utc)
    envelope = Snapshot(scope, str(uuid4()), now, now, "success", True, b"[]")
    with closing(local_database().connect()) as conn, conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(731904216)")
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        verify(cur)
        source_connection(cur, envelope)
        cur.execute(
            "SELECT origin FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
            (scope.connection_id,),
        )
        authorized = cur.fetchone()
        if authorized is None:
            authorize_connection(cur, envelope)
        elif authorized != (scope.origin,):
            raise ReplayConflict("Query source authorization differs")
        cur.execute(
            "INSERT INTO evidence_pipeline.osv_query_bindings(connection_id,query_document) VALUES(%s,%s) ON CONFLICT DO NOTHING",
            (scope.connection_id, encoded),
        )
        cur.execute(
            "SELECT query_document FROM evidence_pipeline.osv_query_bindings WHERE connection_id=%s",
            (scope.connection_id,),
        )
        if cur.fetchone() != (encoded,):
            raise ReplayConflict(
                "Connection already belongs to a different package query"
            )


def ingest(collection):
    snapshot = from_collection(collection)
    with closing(connect()) as conn, conn:
        result = persist_public(conn, snapshot)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["register"])
    parser.add_argument("--scope", required=True)
    parser.add_argument("--name")
    parser.add_argument("--ecosystem")
    parser.add_argument("--purl")
    parser.add_argument("--version")
    args = parser.parse_args(argv)
    try:
        scope = load_scope(args.scope)
        query = package_query(
            name=args.name,
            ecosystem=args.ecosystem,
            purl=args.purl,
            version=args.version,
        )
        register(scope, query)
        print(json.dumps(dict(connection_id=scope.connection_id, registered=True)))
        return 0
    except (ValueError, OSError, psycopg2.Error):
        print("OSV query registration could not be verified", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
