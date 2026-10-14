"""Exact PostgreSQL text, hostile delimiters and unchanged writer restrictions."""

from types import SimpleNamespace
from uuid import uuid4
import psycopg2
import pytest
from standalone.evidence_pipeline.persistence import large_text_parameter as adapter
from .test_store import db as db
from standalone.evidence_pipeline.persistence.store import atomic


@pytest.mark.parametrize("tamper", [False, True])
def test_large_claim_pipeline_exact_content_and_atomicity(db, monkeypatch, tamper):
    """Exercise the production size switch, deferred checks and replay together."""
    from dataclasses import replace
    import json
    from standalone.evidence_pipeline.persistence.authority import authorize_connection
    from standalone.evidence_pipeline.parsing.cvrf_records import UpdateRecord
    from standalone.evidence_pipeline.parsing.public_records import normalize_public
    from standalone.evidence_pipeline.persistence.public_store import persist_public
    from .test_cvrf_store import snapshot
    from .test_cvrf_updates import document

    raw = document()
    raw["Vulnerability"][0]["Notes"] = [
        {"Value": ("Synthetic 😀 漢字 \\ '; SELECT pg_sleep(10); --\n" * 1000)}
        for _ in range(40)
    ]
    value = replace(snapshot(), payload=json.dumps(raw).encode())
    expected = [record.claim for record in normalize_public(value.feed())]
    assert len(expected) == 1 and len(expected[0]) > 1_000_000
    with db.cursor() as cur:
        authorize_connection(cur, value)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    if tamper:
        original = UpdateRecord.evidence_rows

        def changed(self, receipt):
            for table, row in original(self, receipt):
                if table == "patch_applicability":
                    row["version_expression"] = "invented synthetic range"
                yield table, row

        monkeypatch.setattr(UpdateRecord, "evidence_rows", changed)
        with pytest.raises(Exception, match="CVRF"):
            persist_public(db, value)
    else:
        assert not persist_public(db, value)["replayed"]
        assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT claim FROM evidence_pipeline.public_claims c "
            "JOIN evidence.source_revisions r ON r.id=c.source_revision_id "
            "WHERE r.connection_id=%s",
            (value.scope.connection_id,),
        )
        assert [row[0] for row in cur.fetchall()] == ([] if tamper else expected)
        cur.execute(
            "SELECT count(*) FROM evidence.collection_attempts WHERE id=%s",
            (value.execution_id,),
        )
        assert cur.fetchone() == (0 if tamper else 1,)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "plain",
        "'; SELECT pg_sleep(10); --",
        "\\N\t\r\n\\x00",
        "Emoji 😀 漢字 café",
        "$$ $tag$",
        "A" * 16383 + "😀" + "\\" * 16384,
    ],
)
def test_exact_text_under_restricted_writer(db, value):
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        cur.execute("SELECT %s::text", (adapter.LargeTextParameter(value),))
        assert cur.fetchone() == (value,)


def test_delimiter_collision_across_encoding_boundary(db, monkeypatch):
    values = iter([SimpleNamespace(hex="0" * 32), SimpleNamespace(hex="1" * 32)])
    monkeypatch.setattr(adapter, "uuid4", lambda: next(values))
    value = "x" * 16380 + "$tm_claim_" + "0" * 32 + "$; SELECT pg_sleep(10); --"
    with db.cursor() as cur:
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
        cur.execute("SELECT %s::text", (adapter.LargeTextParameter(value),))
        assert cur.fetchone() == (value,)


@pytest.mark.parametrize("value", ["nul\x00payload", "surrogate\ud800"])
def test_invalid_text_rejected_before_execution(db, value):
    with db.cursor() as cur:
        with pytest.raises((ValueError, UnicodeEncodeError)):
            cur.execute("SELECT %s::text", (adapter.LargeTextParameter(value),))
        cur.execute("SELECT 1")
        assert cur.fetchone() == (1,)


def test_row_policy_and_reader_still_reject_inserts(db):
    with db.cursor() as cur:
        for role in ("tm_pipeline_writer", "tm_mock_reader"):
            cur.execute("SET LOCAL ROLE " + role)
            with pytest.raises(psycopg2.Error):
                with atomic(cur):
                    cur.execute(
                        "INSERT INTO evidence_pipeline.public_claims (source_revision_id,claim) VALUES (%s,%s)",
                        (
                            str(uuid4()),
                            adapter.LargeTextParameter("synthetic unauthorized claim"),
                        ),
                    )
            cur.execute("RESET ROLE")


def test_unprepared_and_incompatible_encodings_rejected():
    value = adapter.LargeTextParameter("synthetic")
    with pytest.raises(ValueError):
        value.getquoted()
    with pytest.raises(ValueError):
        value.prepare(SimpleNamespace(encoding="LATIN1"))
    with pytest.raises(TypeError):
        adapter.LargeTextParameter(b"not text")
    assert value.__conform__(object()) is None
