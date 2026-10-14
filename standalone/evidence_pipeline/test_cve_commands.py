"""Committed synthetic CVE inputs reach the actual UI reader and full verifier."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from psycopg2 import sql

from .commands import register, ingest_public
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from .runtime import local_database
from .test_commands import cleanup
from .test_cve_program import document, scope
from .test_attribution import verify


def clear(source, cve):
    with local_database().connect() as conn, conn.cursor() as cur:
        for table in ("cve_contributions", "cve_record_observations"):
            cur.execute(
                sql.SQL(
                    "DELETE FROM evidence.{} WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)"
                ).format(sql.Identifier(table)),
                (source.connection_id,),
            )
        cur.execute(
            "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
            (source.connection_id,),
        )
        cur.execute("DELETE FROM evidence.vulnerabilities WHERE cve_id=%s", (cve,))
    cleanup(source)


@pytest.mark.parametrize(
    "provider,kind", [("CVE", "records"), ("CISA", "vulnrichment")]
)
@pytest.mark.parametrize(
    "audit_full_baseline", [False, pytest.param(True, marks=pytest.mark.full_baseline)]
)
def test_committed_cve_input_and_reader(provider, kind, audit_full_baseline):
    source = replace(scope(), source=provider, input_kind=kind)
    raw = document()
    cve = ("CVE-2099-" + str(uuid4().int))[:28]
    raw["cveMetadata"]["cveId"] = cve
    now = datetime.now(timezone.utc)
    value = PublicSnapshot(
        source, str(uuid4()), now, now, "success", True, json.dumps(raw).encode()
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(source)
        assert not register(source)
        assert not ingest_public(value)["replayed"]
        assert ingest_public(value)["replayed"]
        query = PostgreSQLQueries()
        statement = (
            "SELECT cve_id,record_state,contributor_kind FROM evidence_pipeline.current_cve_contributions WHERE connection_id='"
            + source.connection_id
            + "'::uuid ORDER BY contributor_kind"
        )

        def read():
            return json.loads(
                query.execute({"requestId": str(uuid4()), "sql": statement})
            )["rows"]

        assert read() == [[cve, "PUBLISHED", "adp"], [cve, "PUBLISHED", "cna"]]
        failure = replace(
            value,
            execution_id=str(uuid4()),
            finished_at=now + timedelta(seconds=1),
            outcome="failure",
            complete=False,
            payload=b"",
            error_code="public_transport_failed",
        )
        assert ingest_public(failure)["outcome"] == "failure"
        assert read() == [[cve, "PUBLISHED", "adp"], [cve, "PUBLISHED", "cna"]]
        raw["cveMetadata"]["state"] = "REJECTED"
        raw["containers"] = {
            "cna": {
                "providerMetadata": raw["containers"]["cna"]["providerMetadata"],
                "rejectedReasons": [{"lang": "en", "value": "Synthetic rejection"}],
            }
        }
        rejected = replace(
            value,
            execution_id=str(uuid4()),
            finished_at=now + timedelta(seconds=2),
            payload=json.dumps(raw).encode(),
        )
        ingest_public(rejected)
        assert read() == [[cve, "REJECTED", "cna"]]
        if audit_full_baseline:
            with local_database().connect() as conn, conn.cursor() as cur:
                verify(cur)
    finally:
        clear(source, cve)


@pytest.mark.parametrize("provider", ["CVE", "CISA"])
def test_repository_records_commit_and_replay_through_reader(tmp_path, provider):
    from standalone.evidence_pipeline.collection.cve_repository import collect
    from standalone.evidence_pipeline.collection.github_scan import scan
    from standalone.evidence_pipeline.collection.github_dispatch import source_scope
    from .test_cve_repository import repository
    from .test_cve_discovery import COMMIT

    prefix = str(uuid4().int)[:14]
    cves = tuple("CVE-2099-" + prefix + tail for tail in ("1234", "1235"))
    objects, payloads = repository(provider, cves)
    run = tmp_path / "repository"
    execution = str(uuid4())
    sources = []
    try:
        # Index first so cleanup owns every connection even if an import fails.
        bucket = cves[0].split("-")[2][:-3] + "xxx"
        part = "2099/" + bucket
        indexed = scan(
            COMMIT,
            tmp_path / "inventory",
            origin="synthetic",
            source=provider,
            synthetic_objects=objects,
            partition=part,
        )
        assert indexed.complete
        sources = [
            (source_scope(file, "synthetic"), file.cve_id)
            for file in indexed.discovery.files
        ]
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT cve_id FROM evidence.vulnerabilities WHERE cve_id=ANY(%s)",
                (list(cves),),
            )
            assert cur.fetchall() == []
        result = collect(
            provider,
            run,
            origin="synthetic",
            execution_id=execution,
            synthetic_objects=objects,
            synthetic_payloads=payloads,
            import_records=True,
        )
        assert result.enumeration_finished and len(result.outcomes) == 2
        assert (
            result.collection_complete
            and result.database_complete
            and result.snapshot_published
        )
        assert all(
            item["outcome"] == "success"
            and item["database_imported"]
            and not item["replayed"]
            for item in result.outcomes
        )
        replay = collect(
            provider,
            run,
            origin="synthetic",
            execution_id=execution,
            replay_only=True,
            metadata_limit=0,
            import_records=True,
        )
        assert all(
            item["database_imported"] and item["replayed"] for item in replay.outcomes
        )
        assert (
            replay.collection_complete
            and replay.database_complete
            and replay.snapshot_published
        )
        from app.services.postgres_query import PostgreSQLQueries

        query = PostgreSQLQueries()
        current = json.loads(
            query.execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT cve_id,origin FROM evidence_pipeline.current_cve_repository_records WHERE run_id='"
                    + execution
                    + "'::uuid ORDER BY cve_id",
                }
            )
        )["rows"]
        assert current == [[cve, "synthetic"] for cve in sorted(cves)]
        for bound, cve in sources:
            rows = json.loads(
                query.execute(
                    {
                        "requestId": str(uuid4()),
                        "sql": "SELECT cve_id,record_state,origin,source_url FROM evidence_pipeline.current_cve_records WHERE connection_id='"
                        + bound.connection_id
                        + "'::uuid",
                    }
                )
            )["rows"]
            assert rows == [[cve, "PUBLISHED", "synthetic", bound.scope_reference]]
            assert "/" + COMMIT + "/" in rows[0][3]
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence_pipeline.cve_repository_snapshots WHERE source_name=%s AND run_id=%s AND origin='synthetic'",
                (provider, execution),
            )
        for bound, cve in sources:
            clear(bound, cve)
