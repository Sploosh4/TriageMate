"""Every supported source domain has explicit inspectable eligible facts."""

from backend.database import schema as database_schema

from standalone.evidence_pipeline.persistence.authority import authorize_connection

from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.catalogue_store import persist_catalogue
from .test_cvrf_store import snapshot as msrc_snapshot
from .test_vulnerability_catalogue import snapshot as catalogue_snapshot
from .test_store import db as database_fixture

db = database_fixture


def ingest(db, value, writer):
    with db.cursor() as cur:
        database_schema.verify(cur)
        authorize_connection(cur, value)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    writer(db, value)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")


def test_msrc_source_relationships_are_in_the_selected_denominator(db):
    value = msrc_snapshot()
    ingest(db, value, persist_public)
    with db.cursor() as cur:
        cur.execute(
            "SELECT domain,populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[])",
            ([value.scope.connection_id],),
        )
        assert cur.fetchall() == [
            ("msrc-update", 3, 5),
            ("public-patch", 6, 10),
            ("whole-product", 9, 15),
        ]
        cur.execute(
            "SELECT eligible_cells,completeness_assessment FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (15, "Provisional definition")


def test_catalogue_false_and_zero_are_populated_source_facts(db):
    value = catalogue_snapshot([dict(id="CVE-2099-12345", publicExploit=False, epss=0)])
    ingest(db, value, persist_catalogue)
    with db.cursor() as cur:
        cur.execute(
            "SELECT field_name,value,populated FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND field_name IN ('publicExploit','epss') ORDER BY field_name",
            ([value.scope.connection_id],),
        )
        assert cur.fetchall() == [("epss", "0", True), ("publicExploit", False, True)]
        cur.execute(
            "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain=%s",
            ([value.scope.connection_id], "whole-product"),
        )
        assert cur.fetchone() == (3, 19)


def test_successful_empty_catalogue_is_not_assessable(db):
    value = catalogue_snapshot([])
    ingest(db, value, persist_catalogue)
    with db.cursor() as cur:
        cur.execute(
            "SELECT percentage,assessment FROM evidence_pipeline.completeness_summary(%s::uuid[])",
            ([value.scope.connection_id],),
        )
        assert cur.fetchone() == (None, "Not assessable")
        cur.execute(
            "SELECT eligible_cells,completeness_assessment FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
            (value.scope.connection_id,),
        )
        assert cur.fetchone() == (0, "Not assessable: no eligible evidence cells")


def test_public_reference_domains_have_inspectable_source_facts(db):
    from .test_reference_store import snapshot

    for kind, domain, fields, populated in (
        ("exploit", "exploit-metadata", 8, 3),
        ("ctid", "cve-attack-mapping", 6, 4),
        ("attack", "attack-definition", 8, 5),
    ):
        value = snapshot(kind)
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
        ingest(db, value, persist_public)
        with db.cursor() as cur:
            cur.execute(
                "SELECT domain,populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain<>'whole-product'",
                ([value.scope.connection_id],),
            )
            assert cur.fetchall() == [(domain, populated, fields)]
            cur.execute(
                "SELECT completeness_domain,eligible_cells FROM evidence_pipeline.product_completeness_coverage WHERE connection_id=%s",
                (value.scope.connection_id,),
            )
            assert cur.fetchone() == ("public-reference", fields)
            if kind == "exploit":
                cur.execute(
                    "SELECT value,populated FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[] AND field_name='verified'",
                    ([value.scope.connection_id],),
                )
                assert cur.fetchone() == (False, True)


def test_overlapping_advisories_preserve_scope_cells_and_replay_counts(db):
    from dataclasses import replace
    from uuid import uuid4

    first = msrc_snapshot()
    second = replace(
        first,
        scope=replace(first.scope, connection_id=str(uuid4())),
        execution_id=str(uuid4()),
    )
    for value in (first, second):
        with db.cursor() as cur:
            cur.execute("RESET ROLE")
        ingest(db, value, persist_public)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    assert persist_public(db, second)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET ROLE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        for selected, expected in (
            ([first.scope.connection_id], (9, 15)),
            ([first.scope.connection_id, second.scope.connection_id], (18, 30)),
            ([first.scope.connection_id, first.scope.connection_id], (9, 15)),
        ):
            cur.execute(
                "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(%s::uuid[]) WHERE domain='whole-product'",
                (selected,),
            )
            assert cur.fetchone() == expected
            cur.execute(
                "SELECT count(DISTINCT receipt_id) FROM evidence_pipeline.current_product_completeness_cells WHERE scope_connections && %s::uuid[]",
                (selected,),
            )
            assert cur.fetchone()[0] == len(set(selected))
