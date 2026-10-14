"""Committed synthetic query imports through the actual SQL reader and CLI."""

from dataclasses import replace
import json
from uuid import uuid4

import pytest
from psycopg2 import sql

from . import osv_query_commands as commands
from standalone.evidence_pipeline.collection import osv_query_collection as collection
from standalone.evidence_pipeline.parsing.osv_query import URL, package_query
from .runtime import local_database
from .test_osv import scope
from .test_osv_commands import clear


@pytest.fixture
def registered():
    source = replace(scope(), scope_reference=URL)
    query = package_query(name="synthetic-package", ecosystem="PyPI", version="1")
    try:
        commands.register(source, query)
        yield source, query
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            for table in (
                "osv_query_advisory_links",
                "osv_query_pages",
                "osv_query_batches",
            ):
                cur.execute(
                    sql.SQL(
                        "DELETE FROM evidence_pipeline.{} WHERE attempt_id IN (SELECT id FROM evidence.collection_attempts WHERE connection_id=%s)"
                    ).format(sql.Identifier(table)),
                    (source.connection_id,),
                )
            cur.execute(
                "DELETE FROM evidence_pipeline.osv_query_bindings WHERE connection_id=%s",
                (source.connection_id,),
            )
        clear(source, [])


def prepare(source, tmp_path, raw):
    return collection.prepare(
        source,
        str(uuid4()),
        tmp_path / str(uuid4()),
        name="synthetic-package",
        ecosystem="PyPI",
        version="1",
        synthetic_pages=[json.dumps(raw).encode()],
    )
