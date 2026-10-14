"""Attribution checks reject changed advisory data and foreign-key relationships."""

import json
from uuid import uuid4
import pytest
from .test_csaf_store import ready as ready_fixture
from .test_store import db as database_fixture
from standalone.evidence_pipeline.persistence.public_store import persist_public
from standalone.evidence_pipeline.persistence.csaf_attribution import (
    verify_advisory_receipt,
)

ready = ready_fixture
db = database_fixture


def context(cursor, execution):
    cursor.execute(
        "SELECT to_jsonb(c),to_jsonb(v),to_jsonb(r),p.claim FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id JOIN evidence.source_connections c ON c.id=v.connection_id JOIN evidence_pipeline.public_claims p ON p.source_revision_id=v.id WHERE r.collection_attempt_id=%s",
        (execution,),
    )
    return cursor.fetchone()


def test_roundtrip_reconstructs_every_relationship(db, ready):
    persist_public(db, ready)
    with db.cursor() as cursor:
        cursor.execute("RESET SESSION AUTHORIZATION")
        result = verify_advisory_receipt(cursor, *context(cursor, ready.execution_id))
        assert len(result) == 7 and all(len(ids) == 1 for ids in result.values())


@pytest.mark.parametrize(
    "damage",
    [
        "patch",
        "recommendation",
        "missing-link",
        "extra-link",
        "claim",
        "recipe",
        "receipt",
    ],
)
def test_advisory_damage_is_rejected(db, ready, damage):
    persist_public(db, ready)
    with db.cursor() as cursor:
        cursor.execute("RESET SESSION AUTHORIZATION")
        source, revision, receipt, claim = context(cursor, ready.execution_id)
        if damage == "patch":
            cursor.execute(
                "UPDATE evidence.patches SET product_names=ARRAY['wrong'] WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "recommendation":
            cursor.execute(
                "UPDATE evidence.recommendations SET recommended_version='invented' WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "missing-link":
            cursor.execute(
                "DELETE FROM evidence.recommendation_patches WHERE receipt_id=%s",
                (receipt["id"],),
            )
        elif damage == "extra-link":
            # An extra recommendation is a fabricated claim even if its columns are valid.
            cursor.execute(
                "INSERT INTO evidence.recommendations(id,source_recommendation_id,title,receipt_id) VALUES(%s,'invented','invented',%s)",
                (str(uuid4()), receipt["id"]),
            )
        elif damage == "claim":
            claim += " "
        elif damage == "recipe":
            from standalone.evidence_pipeline.parsing.public_records import canonical
            from standalone.evidence_pipeline.parsing.devices import stable_id
            import hashlib

            document = json.loads(claim)
            document["projection"][0][1][1][1] = "invented"
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
        with pytest.raises(AssertionError, match="Advisory|advisory"):
            verify_advisory_receipt(cursor, source, revision, receipt, claim)
