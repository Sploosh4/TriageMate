"""Explicit owner registration of exact source scopes; setup belongs to backend.database."""

from standalone.evidence_pipeline.persistence.store import source_connection


def authorize_connection(cursor, snapshot):
    """Owner-only registration of the exact configured scope, not runtime self-enrolment."""
    source_connection(cursor, snapshot)
    cursor.execute(
        "INSERT INTO evidence_pipeline.authorized_connections(connection_id,origin) VALUES(%s,%s)",
        (snapshot.scope.connection_id, snapshot.scope.origin),
    )
