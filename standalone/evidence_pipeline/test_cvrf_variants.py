"""Synthetic metadata variants retain both sources and one patch projection."""

from copy import deepcopy
from dataclasses import replace
import json
import pytest

from standalone.evidence_pipeline.parsing.cvrf_records import normalize_cvrf_updates
from standalone.evidence_pipeline.parsing.cvrf_stream import StreamedCvrfUpdates
from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_updates
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_stream import saved
from .test_cvrf_updates import document, source
from .test_cvrf_store import prepare
from .test_store import db  # noqa: F401


def duplicated(value):
    first = value["Vulnerability"][0]
    first.update(
        Ordinal="10",
        CWE=[{"ID": "CWE-400", "Value": "Synthetic weakness"}],
        RevisionHistory=[{"Number": "1.0", "Date": "2099-09-11"}],
    )
    second = deepcopy(first)
    second.update(
        Ordinal="11",
        CWE=None,
        RevisionHistory=[{"Number": "1.0", "Date": "2099-09-04"}],
    )
    value["Vulnerability"].append(second)
    return value


def test_variants_keep_sources_without_disputed_metadata_or_duplicate_patches(tmp_path):
    value = duplicated(document())
    payload = json.dumps(value).encode()
    scope = source()
    ordinary = list(normalize_cvrf_updates(parse_cvrf_updates(payload, scope=scope)))
    streamed = list(
        normalize_public(StreamedCvrfUpdates(scope, saved(tmp_path, payload)))
    )
    assert streamed == ordinary and len(ordinary) == 1
    record = ordinary[0]
    claim = json.loads(record.claim)
    assert claim["source_variants"] == value["Vulnerability"]
    assert not (
        {"Ordinal", "CWE", "RevisionHistory"} & claim["source_vulnerability"].keys()
    )
    single = deepcopy(value)
    single["Vulnerability"] = single["Vulnerability"][:1]
    expected = list(
        normalize_cvrf_updates(
            parse_cvrf_updates(json.dumps(single).encode(), scope=scope)
        )
    )[0]
    assert record.rows == expected.rows


@pytest.mark.parametrize(
    "damage",
    [
        "same_ordinal",
        "numeric_alias",
        "missing_ordinal",
        "remediation",
        "status",
        "title",
    ],
)
def test_ambiguous_identity_or_operational_difference_remains_rejected(
    tmp_path, damage
):
    value = duplicated(document())
    later = value["Vulnerability"][1]
    if damage == "same_ordinal":
        later["Ordinal"] = "10"
    elif damage == "numeric_alias":
        later["Ordinal"] = "010"
    elif damage == "missing_ordinal":
        del later["Ordinal"]
    elif damage == "remediation":
        later["Remediations"] = []
    elif damage == "status":
        later["ProductStatuses"] = []
    else:
        later["Title"] = {"Value": "Different synthetic title"}
    payload = json.dumps(value).encode()
    with pytest.raises(ValueError, match="Duplicate CVRF"):
        parse_cvrf_updates(payload, scope=source())
    with pytest.raises(ValueError, match="Duplicate CVRF"):
        list(normalize_public(StreamedCvrfUpdates(source(), saved(tmp_path, payload))))


def test_variants_persist_replay_and_verify_exact_sources(db):  # noqa: F811
    value = prepare(db)
    payload = json.dumps(duplicated(json.loads(value.payload))).encode()
    value = replace(value, payload=payload)
    assert not persist_public(db, value)["replayed"]
    assert persist_public(db, value)["replayed"]
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        cur.execute(
            "SELECT to_jsonb(s),to_jsonb(v),to_jsonb(r),p.claim FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id JOIN evidence.source_connections s ON s.id=v.connection_id JOIN evidence_pipeline.public_claims p ON p.source_revision_id=v.id WHERE r.collection_attempt_id=%s",
            (value.execution_id,),
        )
        rows = cur.fetchall()
        assert len(rows) == 1
        from standalone.evidence_pipeline.persistence.cvrf_attribution import (
            verify_update_receipt,
        )

        verify_update_receipt(cur, *rows[0])
        claim = json.loads(rows[0][3])
        assert len(claim["source_variants"]) == 2
        cur.execute(
            "SELECT populated,applicable FROM evidence_pipeline.completeness_summary(ARRAY[%s]::uuid[]) WHERE domain=%s",
            (value.scope.connection_id, "msrc-update"),
        )
        populated, applicable = cur.fetchone()
        assert applicable == 5 and populated <= applicable
        claim["source_variants"][1]["CWE"] = claim["source_variants"][0]["CWE"]
        forged = json.dumps(claim, sort_keys=True, separators=(",", ":"))
        with pytest.raises(AssertionError, match="identity changed"):
            verify_update_receipt(cur, *rows[0][:3], forged)
        # Even a self-consistently rehashed claim cannot select disputed metadata.
        from standalone.evidence_pipeline.parsing.devices import stable_id
        from .text_bytes import utf8_sha256

        source_row, revision, receipt = deepcopy(rows[0][:3])
        revision["content_hash"] = utf8_sha256(forged)
        revision["id"] = stable_id(
            "public-revision",
            source_row["id"],
            revision["source_record_id"],
            revision["content_hash"],
        )
        receipt["source_revision_id"] = revision["id"]
        receipt["id"] = stable_id(
            "public-receipt", revision["id"], receipt["collection_attempt_id"]
        )
        with pytest.raises(AssertionError, match="disagrees with retained source"):
            verify_update_receipt(cur, source_row, revision, receipt, forged)
