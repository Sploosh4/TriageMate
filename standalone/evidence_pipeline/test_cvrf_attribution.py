"""CVRF source and row reconstruction reject tampering beyond foreign keys."""

import hashlib
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.persistence.cvrf_attribution import (
    verify_update_receipt,
    ReceiptRowsReader,
)
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_records import canonical
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .test_cvrf_store import prepare
from .test_csaf_attribution import context
from .test_store import db  # noqa: F401


def test_cvrf_roundtrip_and_source_decimal_reconstruction(db):  # noqa: F811
    from dataclasses import replace

    value = prepare(db)
    # Exercise decimal JSON in raw publisher metadata without a float roundtrip.
    wire = value.payload.replace(
        b'"ProductTree":', b'"SyntheticMetric":0.1234567890123456789,"ProductTree":', 1
    )
    value = replace(value, payload=wire)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        verified = verify_update_receipt(cur, *context(cur, value.execution_id))
        assert {key: len(ids) for key, ids in verified.items()} == {
            "patches": 2,
            "patch_vulnerabilities": 1,
            "patch_applicability": 1,
            "patch_replacements": 1,
        }


@pytest.mark.parametrize(
    "damage", ["patch", "missing", "map", "batch", "claim", "recipe", "receipt"]
)
@pytest.mark.parametrize("warm_cache", [False, True])
@pytest.mark.parametrize("prepared", [False, True])
def test_cvrf_damage_is_rejected(db, damage, warm_cache, prepared):  # noqa: F811
    from standalone.evidence_pipeline.persistence.cvrf_attribution import (
        UpdateReconstruction,
    )

    value = prepare(db)
    persist_public(db, value)
    with db.cursor() as cur, ReceiptRowsReader(cur) as reader:
        cur.execute("RESET SESSION AUTHORIZATION")
        source, revision, receipt, claim = context(cur, value.execution_id)
        reconstruction = UpdateReconstruction() if warm_cache else None
        if warm_cache:
            verify_update_receipt(
                cur,
                source,
                revision,
                receipt,
                claim,
                reconstruction=reconstruction,
                row_reader=reader if prepared else None,
            )
        if damage == "patch":
            cur.execute(
                "UPDATE evidence.patches SET product_names=ARRAY['Synthetic wrong'] WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "missing":
            cur.execute(
                "DELETE FROM evidence.patch_replacements WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "map":
            cur.execute(
                "DELETE FROM evidence_pipeline.cvrf_projection WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "batch":
            cur.execute(
                "UPDATE evidence_pipeline.cvrf_batches SET row_count=row_count+1 WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "claim":
            claim += " "
        elif damage == "recipe":
            document = json.loads(claim)
            document["projection"][0][1][0][1] = "KB9999999"
            claim = canonical(document)
            digest = hashlib.sha256(claim.encode()).hexdigest()
            revision = dict(
                revision,
                content_hash=digest,
                id=stable_id(
                    "public-revision",
                    source["id"],
                    revision["source_record_id"],
                    digest,
                ),
            )
            receipt = dict(
                receipt,
                source_revision_id=revision["id"],
                id=stable_id(
                    "public-receipt", revision["id"], receipt["collection_attempt_id"]
                ),
            )
        else:
            receipt = dict(receipt, id=str(uuid4()))
        with pytest.raises(AssertionError, match="CVRF"):
            verify_update_receipt(
                cur,
                source,
                revision,
                receipt,
                claim,
                reconstruction=reconstruction,
                row_reader=reader if prepared else None,
            )


def test_same_revision_reuses_reconstruction_but_checks_each_receipt(db, monkeypatch):  # noqa: F811
    from dataclasses import replace
    from standalone.evidence_pipeline.persistence import cvrf_attribution

    first = prepare(db)
    second = replace(first, execution_id=str(uuid4()))
    persist_public(db, first)
    persist_public(db, second)
    original = cvrf_attribution.reconstruct_update
    calls = []

    def reconstruct(*args):
        calls.append(args[1]["id"])
        return original(*args)

    monkeypatch.setattr(cvrf_attribution, "reconstruct_update", reconstruct)
    cache = cvrf_attribution.UpdateReconstruction()
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        one = context(cur, first.execution_id)
        two = context(cur, second.execution_id)
        assert one[1]["id"] == two[1]["id"] and one[2]["id"] != two[2]["id"]
        first_ids = verify_update_receipt(cur, *one, reconstruction=cache)
        second_ids = verify_update_receipt(cur, *two, reconstruction=cache)
        assert len(calls) == 1
        assert not (first_ids["patches"] & second_ids["patches"])
        cur.execute(
            "DELETE FROM evidence.patch_replacements WHERE receipt_id=%s",
            (two[2]["id"],),
        )
        with pytest.raises(AssertionError, match="projection changed or missing"):
            verify_update_receipt(cur, *two, reconstruction=cache)
        assert len(calls) == 1


@pytest.mark.parametrize(
    "field",
    [
        "id",
        "scope_reference",
        "origin",
        "licence_or_provenance",
        "source_record_id",
        "claim",
    ],
)
def test_reconstruction_cache_does_not_cross_source_context(field, monkeypatch):
    from standalone.evidence_pipeline.persistence import cvrf_attribution

    calls = []
    monkeypatch.setattr(
        cvrf_attribution,
        "reconstruct_update",
        lambda *args: calls.append(args) or object(),
    )
    source = {"id": "source", "scope_reference": "scope"}
    revision = {
        "origin": "synthetic",
        "licence_or_provenance": "synthetic",
        "source_record_id": "record",
    }
    cache = cvrf_attribution.UpdateReconstruction()
    before = cache.read(source, revision, "claim")
    assert cache.read(dict(source), dict(revision), "claim") is before
    changed_source, changed_revision, claim = dict(source), dict(revision), "claim"
    if field in changed_source:
        changed_source[field] = "changed"
    elif field in changed_revision:
        changed_revision[field] = "changed"
    else:
        claim = "changed claim"
    assert cache.read(changed_source, changed_revision, claim) is not before
    assert len(calls) == 2
    assert cache.read(source, revision, "claim") is not before
    assert len(calls) == 3  # Only one reconstruction is retained.


@pytest.mark.parametrize("fail", [False, True])
def test_prepared_receipt_reader_releases_statement(db, fail):  # noqa: F811
    value = prepare(db)
    persist_public(db, value)
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        args = context(cur, value.execution_id)
        expected = verify_update_receipt(cur, *args)
        try:
            with ReceiptRowsReader(cur) as reader:
                assert verify_update_receipt(cur, *args, row_reader=reader) == expected
                cur.execute(
                    "SELECT count(*) FROM pg_prepared_statements WHERE name LIKE 'tm_cvrf_audit_%'"
                )
                assert cur.fetchone() == (1,)
                if fail:
                    raise RuntimeError("synthetic cancellation")
        except RuntimeError:
            assert fail
        cur.execute(
            "SELECT count(*) FROM pg_prepared_statements WHERE name LIKE 'tm_cvrf_audit_%'"
        )
        assert cur.fetchone() == (0,)


def test_prepared_reader_is_lazy(db):  # noqa: F811
    with db.cursor() as cur, ReceiptRowsReader(cur) as reader:
        assert not reader.prepared
        cur.execute(
            "SELECT count(*) FROM pg_prepared_statements WHERE name LIKE 'tm_cvrf_audit_%'"
        )
        assert cur.fetchone() == (0,)
