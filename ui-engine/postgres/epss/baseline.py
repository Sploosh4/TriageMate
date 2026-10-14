"""Exact original fixtures plus explicitly attributed EPSS slice rows; no count waivers."""

import json
from pathlib import Path
from psycopg2 import sql

CONNECTION = "086b7bfe-d067-4213-9681-97b7ebf2b5c7"
ROOT = Path(__file__).resolve().parents[1]
MOCK = {
    "completeness_definitions",
    "completeness_fields",
    "mock_snapshot_selections",
    "mock_fix_matches",
}


def verify_consistent(connect, allow_slice=True):
    """Verify an existing database using one consistent read snapshot.

    Callers that need to verify their own uncommitted writes use verify(cursor)
    inside a REPEATABLE READ/SERIALIZABLE transaction established before queries.
    """
    from contextlib import closing

    with closing(connect()) as connection:
        connection.set_session(isolation_level="REPEATABLE READ", readonly=True)
        with connection, connection.cursor() as cursor:
            return verify(cursor, allow_slice=allow_slice)


def verify(cur, allow_slice=True):
    from standalone.evidence_pipeline.verification_spool import VerificationSpool

    with VerificationSpool() as spool:
        return _verify(cur, allow_slice, spool)


def _verify(cur, allow_slice, spool):
    from standalone.evidence_pipeline.verification_spool import streamed_rows
    from standalone.evidence_pipeline.persistence.public_attribution import (
        PUBLIC_PROJECTION_TABLES,
    )

    if not __debug__:
        raise RuntimeError("Baseline verification requires Python without optimization")
    import hashlib

    cur.execute(
        "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()"
    )
    recorded = json.loads(cur.fetchone()[0])
    from backend.database.metadata import BOOTSTRAP, original_tables
    from backend.database.schema import verify_supported
    from backend.database.fixtures import FIXTURES

    verify_supported(cur)
    empty_install = recorded.get("bootstrap") == "empty-evidence-v1" or (
        recorded.get("bootstrap") == BOOTSTRAP and recorded.get("profile") == "empty"
    )
    if not empty_install:
        expected_hash = (
            recorded["fixture_sha256"]
            if recorded.get("bootstrap") == BOOTSTRAP
            else recorded["sha256"]["fixtures.json"]
        )
        if hashlib.sha256(FIXTURES.read_bytes()).hexdigest() != expected_hash:
            raise AssertionError("Original fixture manifest changed")
    fixtures = (
        {table: [] for _, table in original_tables()}
        if empty_install
        else json.loads(FIXTURES.read_text())["tables"]
    )
    cur.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='evidence' AND table_name='collection_attempts'"
    )
    migrated = ("input_fingerprint",) in cur.fetchall()
    extras = {}
    for table, records in fixtures.items():
        schema = "mock_support" if table in MOCK else "evidence"
        name = sql.Identifier(schema, table)
        if records:
            columns = list(records[0])
            eq = sql.SQL(" AND ").join(
                sql.SQL("t.{} IS NOT DISTINCT FROM b.{}").format(
                    sql.Identifier(k), sql.Identifier(k)
                )
                for k in columns
            )
            q = sql.SQL(
                "SELECT count(*) FROM jsonb_populate_recordset(NULL::{},%s::jsonb) b WHERE (SELECT count(*) FROM {} t WHERE {})=1"
            ).format(name, name, eq)
            cur.execute(q, (json.dumps(records),))
            if cur.fetchone()[0] != len(records):
                raise AssertionError("Original fixture altered: " + table)
            if table == "microsoft_tenants":
                cur.execute(
                    "SELECT 1 FROM information_schema.columns WHERE table_schema='evidence' AND table_name='microsoft_tenants' AND column_name='evidence_origin'"
                )
                if cur.fetchone():
                    cur.execute(
                        sql.SQL(
                            "SELECT count(*) FROM {} t JOIN jsonb_populate_recordset(NULL::{},%s::jsonb) b ON t.id=b.id WHERE t.evidence_origin<>'synthetic'"
                        ).format(name, name),
                        (json.dumps(records),),
                    )
                    assert cur.fetchone()[0] == 0, "Original tenant origin changed"
            if table == "collection_attempts" and migrated:
                cur.execute(
                    sql.SQL(
                        "SELECT count(*) FROM {} t JOIN jsonb_populate_recordset(NULL::{},%s::jsonb) b ON t.id=b.id WHERE t.input_fingerprint IS NOT NULL"
                    ).format(name, name),
                    (json.dumps(records),),
                )
                assert cur.fetchone()[0] == 0, "Baseline fingerprint changed"
            new_column = {
                "software_observations": "inventory_id",
                "patches": "source_product_id",
                "vulnerability_findings": "fixing_patch_reference",
            }.get(table)
            if new_column:
                cur.execute(
                    "SELECT 1 FROM information_schema.columns WHERE table_schema='evidence' AND table_name=%s AND column_name=%s",
                    (table, new_column),
                )
                if cur.fetchone():
                    cur.execute(
                        sql.SQL(
                            "SELECT count(*) FROM {} t JOIN jsonb_populate_recordset(NULL::{},%s::jsonb) b ON t.id=b.id WHERE t.{} IS NOT NULL"
                        ).format(name, name, sql.Identifier(new_column)),
                        (json.dumps(records),),
                    )
                    assert cur.fetchone()[0] == 0, "Baseline source metadata changed"
            query = sql.SQL(
                "SELECT to_jsonb(t) FROM {} t WHERE NOT EXISTS(SELECT 1 FROM jsonb_populate_recordset(NULL::{},%s::jsonb) b WHERE {})"
            ).format(name, name, eq)
            parameters = (json.dumps(records),)
        else:
            query = sql.SQL("SELECT to_jsonb(t) FROM {} t").format(name)
            parameters = None
        with streamed_rows(
            cur, query, parameters, exact_json=table in PUBLIC_PROJECTION_TABLES
        ) as source:
            extras[table] = spool.rows(r[0] for r in source)
    all_extra_counts = {k: len(v) for k, v in extras.items() if v}
    if allow_slice and migrated:
        import sys

        sys.path.insert(0, str(ROOT.parents[1]))
        from standalone.evidence_pipeline.persistence.attribution import (
            separate_pipeline,
        )

        extras = separate_pipeline(cur, extras, spool=spool)
    if empty_install:
        for table, rows in extras.items():
            assert not rows, "Unexplained empty-install records: " + table
        return all_extra_counts
    allowed = (
        {
            "source_connections",
            "collection_attempts",
            "source_revisions",
            "observation_receipts",
            "vulnerabilities",
            "epss_observations",
        }
        if allow_slice and migrated
        else set()
    )
    for table, rows in extras.items():
        assert not rows or table in allowed, "Unexplained extra records: " + table
    if not migrated or not allow_slice:
        return {k: len(v) for k, v in extras.items() if v}
    expected_connection = {
        "id": CONNECTION,
        "source_name": "Synthetic EPSS",
        "input_kind": "epss",
        "tenant_id": None,
        "collector_reference": "triagemate-synthetic-epss-v1",
        "scope_reference": "offline-synthetic-epss-v1",
    }
    assert extras["source_connections"] == [expected_connection], (
        "Unexpected slice connection"
    )
    attempts = {r["id"]: r for r in extras["collection_attempts"]}
    revisions = {r["id"]: r for r in extras["source_revisions"]}
    receipts = {r["id"]: r for r in extras["observation_receipts"]}
    for a in attempts.values():
        assert (
            a["connection_id"] == CONNECTION
            and a["input_fingerprint"]
            and len(a["input_fingerprint"]) == 64
            and all(c in "0123456789abcdef" for c in a["input_fingerprint"])
        )
        assert (
            a["outcome"] in ("success", "failure")
            and a["complete"] == (a["outcome"] == "success")
            and a["finished_at"] is not None
        )
        assert (
            a["error_code"] in (None, "invalid_input", "persistence_failure")
            and a["revision"] == 1
        )
    for r in revisions.values():
        assert (
            r["connection_id"] == CONNECTION
            and r["origin"] == "synthetic"
            and r["source_updated_at"] is None
            and r["source_url"] is None
        )
        assert r["licence_or_provenance"].startswith("TriageMate invented fixture: ")
        assert any(x["source_revision_id"] == r["id"] for x in receipts.values()), (
            "Orphan revision"
        )
    for r in receipts.values():
        assert (
            r["source_revision_id"] in revisions
            and r["collection_attempt_id"] in attempts
        )
        assert attempts[r["collection_attempt_id"]]["outcome"] == "success", (
            "Failed attempt owns evidence"
        )
    observations = extras["epss_observations"]
    assert len(observations) == len(receipts) and {
        e["receipt_id"] for e in observations
    } == set(receipts), "Duplicate/missing slice observations"
    unmatched_cves = {v["cve_id"] for v in extras["vulnerabilities"]} ^ {
        e["cve_id"] for e in observations
    }
    assert not unmatched_cves, (
        f"Unexplained CVE: {len(unmatched_cves)} mismatched identities; "
        f"first 20: {sorted(unmatched_cves)[:20]}"
    )
    # Validate hashes and identities using exact PostgreSQL numeric text, never JSON float values.
    cur.execute(
        """SELECT e.id,e.cve_id,e.probability::text,e.percentile::text,e.score_date::text,e.model_version,
      r.id,r.collection_attempt_id,v.id,v.source_record_id,v.content_hash,v.licence_or_provenance
      FROM evidence.epss_observations e JOIN evidence.observation_receipts r ON r.id=e.receipt_id
      JOIN evidence.source_revisions v ON v.id=r.source_revision_id WHERE v.connection_id=%s""",
        (CONNECTION,),
    )
    import hashlib
    from decimal import Decimal
    import sys

    sys.path.insert(0, str(ROOT.parents[1]))
    from standalone.synthetic_epss import parse_payload

    def identity(kind, key):
        import uuid

        return str(
            uuid.UUID(
                hashlib.sha256(
                    ("offline-synthetic-epss-v1/" + kind + "/" + key).encode()
                ).hexdigest()[:32]
            )
        )

    for (
        eid,
        cve,
        prob,
        pct,
        stamp,
        model,
        rid,
        aid,
        vid,
        key,
        h,
        provenance,
    ) in cur.fetchall():
        fixture = provenance.removeprefix("TriageMate invented fixture: ")
        parsed = parse_payload(
            json.dumps(
                {
                    "origin": "synthetic",
                    "fixture_id": fixture,
                    "data": [
                        {
                            "cve": cve,
                            "epss": prob,
                            "percentile": pct,
                            "date": stamp,
                            "model_version": model,
                        }
                    ],
                }
            ).encode()
        ).observations[0]
        assert (
            parsed.probability == Decimal(prob)
            and parsed.content_hash == h
            and key == cve + "/" + stamp
        )
        assert (
            vid == identity("revision", key + "/" + h)
            and rid == identity("receipt", aid + "/" + vid)
            and eid == identity("observation", rid)
        )
    return all_extra_counts
