"""Architecture extensions preserve legacy verification and replay identity."""

from backend.database import schema as database_schema

from .test_store import db as database_fixture

from .test_exposure_migration import (
    test_original_schema_verifier_accepts_only_recognized_upgrade as check_original,
)
from .test_devices import make
from .test_completeness import put
from standalone.evidence_pipeline.persistence.store import persist_devices

db = database_fixture


def test_original_verifier_checks_architecture_extension(db):
    with db.cursor() as cur:
        database_schema.verify(cur)
    check_original(db)


def test_old_and_new_snapshots_replay_with_original_identity(db):
    old = make("Defender", [{"id": "synthetic-architecture-history"}])
    put(db, old)
    with db.cursor() as cur:
        cur.execute("RESET ROLE")
        cur.execute(
            "SELECT r.id,r.source_revision_id,v.content_hash FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id WHERE r.collection_attempt_id=%s",
            (old.execution_id,),
        )
        before = cur.fetchall()
        database_schema.verify(cur)
        cur.execute("SET LOCAL ROLE tm_pipeline_writer")
    assert persist_devices(db, old)["replayed"]
    new = make(
        "Defender",
        [
            {
                "id": "synthetic-architecture-history",
                "osArchitecture": "64-bit",
                "osProcessor": "x64",
            }
        ],
    )
    put(db, new)
    assert persist_devices(db, new)["replayed"]
    with db.cursor() as cur:
        cur.execute(
            "SELECT r.id,r.source_revision_id,v.content_hash FROM evidence.observation_receipts r JOIN evidence.source_revisions v ON v.id=r.source_revision_id WHERE r.collection_attempt_id=%s",
            (old.execution_id,),
        )
        assert cur.fetchall() == before
