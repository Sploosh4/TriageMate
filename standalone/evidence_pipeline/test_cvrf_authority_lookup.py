"""Receipt-local authority reuse preserves existing CVRF enforcement contracts."""

from backend.database import schema as database_schema

import pytest
from . import test_cvrf_store as contracts
from .test_store import db as database_fixture

db = database_fixture


@pytest.fixture(autouse=True)
def candidate(monkeypatch):
    original = contracts.prepare

    def prepare(connection):
        value = original(connection)
        with connection.cursor() as cur:
            cur.execute("RESET SESSION AUTHORIZATION")

            database_schema.verify(cur)
            cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        return value

    monkeypatch.setattr(contracts, "prepare", prepare)


@pytest.mark.parametrize("streamed", [False, True])
def test_relationship_roundtrip_and_empty_replacement(db, tmp_path, streamed):
    contracts.test_restricted_update_relationship_roundtrip(db, tmp_path, streamed)


@pytest.mark.parametrize("mutation", ["field", "omit", "cross_product"])
@pytest.mark.parametrize("streamed", [False, True])
def test_exact_claim_tampering_rolls_back(
    db, monkeypatch, mutation, tmp_path, streamed
):
    contracts.test_projection_tampering_rolls_back_entire_attempt(
        db, monkeypatch, mutation, tmp_path, streamed
    )


def test_unmapped_extra_rows_and_mutation_denied(db):
    contracts.test_extra_rows_and_writer_mutation_are_rejected(db)


def test_non_cvrf_scope_cannot_use_product_uniqueness(db):
    contracts.test_product_scope_cannot_relax_legacy_patch_uniqueness(db)


@pytest.mark.parametrize("target", ["batch", "projection"])
def test_existing_non_cvrf_receipt_cannot_mint_cached_authority(db, target):
    import psycopg2
    from uuid import uuid4
    from .test_devices import make
    from standalone.evidence_pipeline.persistence.store import persist_devices, atomic
    from standalone.evidence_pipeline.persistence.authority import authorize_connection

    contracts.prepare(db)
    device = make("Entra", [dict(id=str(uuid4()), deviceId=str(uuid4()))])
    with db.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        authorize_connection(cur, device)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
    persist_devices(db, device)
    with db.cursor() as cur:
        cur.execute(
            "SELECT id FROM evidence.observation_receipts WHERE collection_attempt_id=%s",
            (device.execution_id,),
        )
        receipt = cur.fetchone()[0]
        with pytest.raises(
            psycopg2.errors.InsufficientPrivilege, match="row-level security"
        ):
            with atomic(cur):
                if target == "batch":
                    cur.execute(
                        "INSERT INTO evidence_pipeline.cvrf_batches VALUES(%s,1)",
                        (receipt,),
                    )
                else:
                    cur.execute(
                        "INSERT INTO evidence_pipeline.cvrf_projection VALUES(%s,0,'patches',%s)",
                        (receipt, str(uuid4())),
                    )


def test_upgrade_preserves_prior_verifier_and_detects_authority_drift(db):

    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute(
            "GRANT UPDATE ON evidence_pipeline.cvrf_batches TO tm_pipeline_writer"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cur)
