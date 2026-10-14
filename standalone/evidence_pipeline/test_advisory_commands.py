"""Actual restricted writer and application reader for an owned synthetic notice."""

import json
from dataclasses import replace
import re
from uuid import uuid4

from .commands import register, ingest_public
from .test_retained_public_fixture import prepare
from .runtime import local_database
from .test_commands import cleanup
import pytest
from .test_advisory_feeds import fixture
from .test_advisory_store import SOURCES


@pytest.mark.parametrize("source", SOURCES)
def test_advisory_restricted_ingestion_and_duplicate_ingestion(tmp_path, source):
    chosen, raw = fixture(source)
    # Each committed test owns its CVE identifiers as well as its connection.
    identities = {
        match: "CVE-2099-" + str(uuid4().int)[:18]
        for match in re.findall(r"CVE-\d{4}-\d+", raw.decode())
    }
    raw = re.sub(
        r"CVE-\d{4}-\d+", lambda match: identities[match[0]], raw.decode()
    ).encode()
    chosen = replace(
        chosen,
        scope_reference=re.sub(
            r"CVE-\d{4}-\d+",
            lambda match: identities[match[0]],
            chosen.scope_reference,
        ),
    )
    cves = list(identities.values())
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT cve_id FROM evidence.vulnerabilities WHERE cve_id=ANY(%s)",
            (cves,),
        )
        assert cur.fetchall() == [], "Synthetic CVE identifiers must be test-owned"
    value = prepare(chosen, str(uuid4()), tmp_path / "bundle", synthetic_payload=raw)
    from app.services.postgres_query import PostgreSQLQueries

    try:
        assert register(chosen)
        assert not register(chosen)
        assert not ingest_public(value)["replayed"]
        # Fixture reuse proves duplicate ingestion, not saved-bundle replay.
        duplicate = prepare(
            chosen,
            value.execution_id,
            tmp_path / "bundle",
            replay_only=True,
        )
        assert ingest_public(duplicate)["replayed"]
        result = PostgreSQLQueries().execute(
            {
                "requestId": str(uuid4()),
                "sql": "SELECT native_id,origin FROM evidence_pipeline.current_public_references WHERE connection_id='"
                + chosen.connection_id
                + "'::uuid",
            }
        )
        rows = json.loads(result)["rows"]
        assert len(rows) == (2 if source == "Debian" else 1)
        assert {row[1] for row in rows} == {"synthetic"}
        assert {row[0] for row in rows} == {
            record.source_record_id for record in value.feed().records
        }
    finally:
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN (SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)",
                (chosen.connection_id,),
            )
            cur.execute(
                "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN (SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                (chosen.connection_id,),
            )
        cleanup(chosen)
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM evidence.vulnerabilities WHERE cve_id=ANY(%s)",
                (cves,),
            )
    with local_database().connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT cve_id FROM evidence.vulnerabilities WHERE cve_id=ANY(%s)",
            (cves,),
        )
        assert cur.fetchall() == [], "Acceptance must not leave unexplained CVEs"
