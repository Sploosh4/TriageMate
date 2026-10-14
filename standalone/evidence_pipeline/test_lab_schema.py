"""Rollback-only lab schema checks using entirely generated tenant identities."""

from backend.database import schema as database_schema

from uuid import uuid4

import psycopg2
import pytest

from .test_store import db as database_fixture

db = database_fixture


def apply(cursor):

    database_schema.verify(cursor)


def tenant(cursor, external, origin):
    value = str(uuid4())
    cursor.execute(
        "INSERT INTO evidence.microsoft_tenants(id,external_tenant_id,cloud_label,evidence_origin) VALUES(%s,%s,'Microsoft',%s)",
        (value, external, origin),
    )
    return value


def connection(cursor, tenant_id, origin, source="Entra"):
    value = str(uuid4())
    cursor.execute(
        "INSERT INTO evidence.source_connections(id,source_name,input_kind,tenant_id,scope_reference,collector_reference) VALUES(%s,%s,'devices',%s,'synthetic-test','synthetic-test')",
        (value, source, tenant_id),
    )
    cursor.execute(
        "INSERT INTO evidence_pipeline.authorized_connections VALUES(%s,%s)",
        (value, origin),
    )
    return value


def test_same_external_tenant_can_exist_once_per_origin(db):
    with db.cursor() as cursor:
        apply(cursor)
        external = str(uuid4())
        assert tenant(cursor, external, "synthetic") != tenant(cursor, external, "lab")
        with pytest.raises(psycopg2.IntegrityError):
            tenant(cursor, external, "lab")


@pytest.mark.parametrize(
    "tenant_origin,connection_origin,source",
    (
        ("synthetic", "lab", "Entra"),
        ("lab", "synthetic", "Intune"),
        ("lab", "lab", "FIRST"),
    ),
)
def test_registration_cannot_cross_origins_or_use_public_sources(
    db, tenant_origin, connection_origin, source
):
    with db.cursor() as cursor:
        apply(cursor)
        connection(
            cursor,
            tenant(cursor, str(uuid4()), tenant_origin),
            connection_origin,
            source,
        )
        with pytest.raises(psycopg2.Error, match="origin and tenant"):
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_original_fields_and_rows_are_unchanged(db):
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT to_jsonb(t) FROM evidence.microsoft_tenants t ORDER BY id"
        )
        before = [
            {"evidence_origin": "synthetic", **row[0]} for row in cursor.fetchall()
        ]
        apply(cursor)
        cursor.execute(
            "SELECT to_jsonb(t) FROM evidence.microsoft_tenants t ORDER BY id"
        )
        assert [row[0] for row in cursor.fetchall()] == before


def test_registered_lab_connection_accepts_lab_revision(db):
    with db.cursor() as cursor:
        apply(cursor)
        source = connection(cursor, tenant(cursor, str(uuid4()), "lab"), "lab")
        cursor.execute(
            "INSERT INTO evidence.source_revisions(id,connection_id,source_record_id,content_hash,origin,collected_at,licence_or_provenance) VALUES(%s,%s,'synthetic-record',%s,'lab','2026-09-12T00:00:00Z','Explicitly synthetic test')",
            (str(uuid4()), source, "a" * 64),
        )
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


@pytest.mark.parametrize(
    "mutation", ("delete_registration", "change_tenant_origin", "change_source")
)
def test_existing_lab_revision_prevents_inconsistent_parent_changes(db, mutation):
    with db.cursor() as cursor:
        apply(cursor)
        tenant_id = tenant(cursor, str(uuid4()), "lab")
        source = connection(cursor, tenant_id, "lab")
        cursor.execute(
            "INSERT INTO evidence.source_revisions(id,connection_id,source_record_id,content_hash,origin,collected_at,licence_or_provenance) VALUES(%s,%s,'synthetic-record',%s,'lab','2026-09-12T00:00:00Z','Explicitly synthetic test')",
            (str(uuid4()), source, "a" * 64),
        )
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute("SET CONSTRAINTS ALL DEFERRED")
        if mutation == "delete_registration":
            cursor.execute(
                "DELETE FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
                (source,),
            )
        elif mutation == "change_tenant_origin":
            cursor.execute(
                "UPDATE evidence.microsoft_tenants SET evidence_origin='synthetic' WHERE id=%s",
                (tenant_id,),
            )
        else:
            cursor.execute(
                "UPDATE evidence.source_connections SET source_name='FIRST' WHERE id=%s",
                (source,),
            )
        with pytest.raises(psycopg2.Error, match="lab|Lab"):
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


def test_actual_writer_can_insert_registered_lab_revision_but_not_register(db):
    with db.cursor() as cursor:
        apply(cursor)
        source = connection(cursor, tenant(cursor, str(uuid4()), "lab"), "lab")
        cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        cursor.execute(
            "INSERT INTO evidence.source_revisions(id,connection_id,source_record_id,content_hash,origin,collected_at,licence_or_provenance) VALUES(%s,%s,'synthetic-record',%s,'lab','2026-09-12T00:00:00Z','Explicitly synthetic test')",
            (str(uuid4()), source, "a" * 64),
        )
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cursor.execute(
                "DELETE FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
                (source,),
            )


def test_unregistered_lab_revision_rejected_even_for_owner(db):
    with db.cursor() as cursor:
        apply(cursor)
        source = connection(
            cursor, tenant(cursor, str(uuid4()), "synthetic"), "synthetic"
        )
        cursor.execute(
            "INSERT INTO evidence.source_revisions(id,connection_id,source_record_id,content_hash,origin,collected_at,licence_or_provenance) VALUES(%s,%s,'synthetic-record',%s,'lab','2026-09-12T00:00:00Z','Explicitly synthetic test')",
            (str(uuid4()), source, "a" * 64),
        )
        with pytest.raises(psycopg2.Error, match="registered.*lab"):
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
