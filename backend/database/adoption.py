"""Explicit metadata adoption after consistent backup and isolated restore proof.

Only the verified v113 predecessor is supported. This operation changes no
stored source facts, derived rows, source provenance, table definitions or roles.
"""

from collections.abc import Callable
from contextlib import closing
import json
from pathlib import Path

from psycopg2.extensions import cursor
from psycopg2.extras import Json
from psycopg2 import sql

from .backup import (
    database_identity,
    lock_source,
    lock_relations,
    sequence_receipt,
    verified_restore_receipt,
)
from .baseline.catalogue import fingerprint
from .baseline.profiles import identify_layout
from .baseline.evidence import evidence_receipt
from .connections import LocalDatabase
from .metadata import annotation as current_annotation
from . import retained_runner
from .schema import (
    BASE,
    VERSION,
    artifacts,
    installed_version,
    verify,
    verify_predecessor,
)


def adopt(
    database: LocalDatabase,
    directory: Path,
    *,
    verify_evidence: Callable[[cursor], object],
) -> bool:
    """Own one atomic adoption transaction; refuse stale backups or unknown state.

    Stop application-owned writers first. Source locks prevent row/DDL changes
    throughout verification and metadata replacement. Any exception rolls back.
    The caller supplies the current full source-attribution verifier; exceptions
    prevent metadata replacement. Repeating a completed adoption verifies the installed result without writes.
    """
    receipt = verified_restore_receipt(directory)
    construction = json.loads((BASE / "construction.json").read_text())
    # Acquire all write barriers before the verification connection establishes
    # its stable snapshot. Otherwise a writer that commits while a lock is being
    # acquired could be absent from that snapshot and escape the backup check.
    with closing(database.connect()) as guard, guard, guard.cursor() as barriers:
        if database_identity(barriers) != receipt.get("source"):
            raise ValueError("Backup source identity does not match adoption target")
        lock_source(barriers, installation=False)
        with closing(database.connect()) as conn:
            conn.set_session(isolation_level="REPEATABLE READ")
            with conn, conn.cursor() as cur:
                identity = database_identity(cur)
                if (
                    identity != receipt.get("source")
                    or identity["database"] != database.DB
                ):
                    raise ValueError(
                        "Backup source identity does not match adoption target"
                    )
                lock_relations(cur)
                version = installed_version(cur)
                if version == VERSION:
                    verify(cur)
                    return False
                if version != construction["predecessor"]:
                    raise ValueError(
                        "Unsupported predecessor; no historical upgrade path exists"
                    )
                actual = fingerprint(cur)
                profile, _ = identify_layout(actual)
                verify_predecessor(cur)
                if actual != receipt.get("schema"):
                    raise ValueError("Source schema differs from the verified backup")
                cur.execute(
                    "SELECT version,artifacts,signature FROM evidence_pipeline.installation WHERE singleton"
                )
                rows = cur.fetchall()
                if (
                    len(rows) != 1
                    or list(rows[0]) != receipt.get("installation")
                    or rows[0][1] != construction["predecessor_artifacts"]
                ):
                    raise ValueError(
                        "Predecessor metadata differs from the trusted construction or backup"
                    )
                cur.execute(
                    "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
                )
                annotation = cur.fetchone()
                if annotation is None or annotation[0] != receipt.get("annotation"):
                    raise ValueError(
                        "Database annotation changed since the verified backup"
                    )
                before = evidence_receipt(cur, locked=True)
                if before != receipt.get("rows") or sequence_receipt(
                    cur
                ) != receipt.get("sequences"):
                    raise ValueError(
                        "Evidence changed since backup; capture and verify a fresh snapshot"
                    )
                verify_evidence(cur)
                cur.execute(
                    "UPDATE evidence_pipeline.installation SET version=%s,artifacts=%s,signature=%s WHERE singleton",
                    (
                        VERSION,
                        Json(artifacts(retained=retained_runner.matches(actual))),
                        Json(actual),
                    ),
                )
                cur.execute(
                    sql.SQL("COMMENT ON DATABASE {} IS %s").format(
                        sql.Identifier(database.DB)
                    ),
                    (json.dumps(current_annotation(profile), sort_keys=True),),
                )
                verify(cur)
                if evidence_receipt(cur, locked=True) != before or sequence_receipt(
                    cur
                ) != receipt.get("sequences"):
                    raise ValueError("Evidence changed during metadata adoption")
    return True
