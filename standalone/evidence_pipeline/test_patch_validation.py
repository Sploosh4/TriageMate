"""Changed-edge validation keeps cycle and synthetic compatibility protections."""

from backend.database import schema as database_schema

from uuid import uuid4
import pytest
import psycopg2
from psycopg2 import sql
from .test_store import db as database_fixture
from .test_cvrf_store import snapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.authority import authorize_connection


db = database_fixture


@pytest.mark.parametrize("change", ("reverse", "self", "acyclic"))
def test_changed_replacement_edges_check_final_graph(db, change):
    value = snapshot()
    with db.cursor() as c:
        database_schema.verify(c)
        authorize_connection(c, value)
    persist_public(db, value)
    with db.cursor() as c:
        c.execute("SET CONSTRAINTS ALL DEFERRED")
        c.execute(
            "SELECT id,patch_id,superseded_patch_id,receipt_id FROM evidence.patch_replacements WHERE receipt_id IN (SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s)",
            (value.execution_id,),
        )
        edge, patch, old, receipt = c.fetchone()
        if change == "reverse":
            c.execute(
                "INSERT INTO evidence.patch_replacements(id,patch_id,superseded_patch_id,receipt_id) VALUES(%s,%s,%s,%s)",
                (str(uuid4()), old, patch, receipt),
            )
        elif change == "self":
            with pytest.raises(psycopg2.errors.CheckViolation):
                c.execute(
                    "UPDATE evidence.patch_replacements SET superseded_patch_id=patch_id WHERE id=%s",
                    (edge,),
                )
            return
        else:
            c.execute(
                "UPDATE evidence.patch_replacements SET patch_id=%s,superseded_patch_id=%s WHERE id=%s",
                (old, patch, edge),
            )
        if change == "acyclic":
            c.execute("SET CONSTRAINTS evidence.patch_graph IMMEDIATE")
        else:
            with pytest.raises(
                psycopg2.DatabaseError, match="Patch supersedence cycle"
            ):
                c.execute("SET CONSTRAINTS evidence.patch_graph IMMEDIATE")


@pytest.mark.parametrize("table", ("software", "patch_applicability"))
def test_changed_compatibility_parent_still_rejects_invalid_match(db, table):
    with db.cursor() as c:
        database_schema.verify(c)
        c.execute("SET CONSTRAINTS ALL DEFERRED")
        if table == "software":
            selection = "SELECT f.software_id FROM mock_support.mock_fix_matches m JOIN evidence.vulnerability_findings f ON f.id=m.finding_id LIMIT 1"
        else:
            selection = (
                "SELECT applicability_id FROM mock_support.mock_fix_matches LIMIT 1"
            )
        c.execute(
            sql.SQL(
                "UPDATE evidence.{} SET publisher='synthetic-incompatible-publisher' WHERE id=({})"
            ).format(sql.Identifier(table), sql.SQL(selection))
        )
        assert c.rowcount == 1
        with pytest.raises(psycopg2.DatabaseError, match="Synthetic fix match"):
            c.execute("SET CONSTRAINTS evidence.patch_graph IMMEDIATE")
