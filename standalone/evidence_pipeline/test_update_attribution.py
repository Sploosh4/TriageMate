"""Retained update fields must match their source revision, not just row counts."""

from copy import deepcopy
from psycopg2 import sql
import pytest

from .test_store import db, snapshot  # noqa: F401
from .test_update_schema import update_bound  # noqa: F401
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.persistence.update_attribution import verify_updates


def test_source_status_attribution_detects_changed_fields(db, update_bound):  # noqa: F811
    device, child, provider, _ = update_bound
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:

        def fetch(table, condition, value):
            cur.execute(
                sql.SQL("SELECT to_jsonb(t) FROM evidence.{} t WHERE ").format(
                    sql.Identifier(table)
                )
                + sql.SQL(condition),
                (value,),
            )
            return [row[0] for row in cur.fetchall()]

        sources = {
            row["id"]: row
            for row in fetch("source_connections", "id=%s", child.scope.connection_id)
        }
        revisions = {
            row["id"]: row
            for row in fetch(
                "source_revisions", "connection_id=%s", child.scope.connection_id
            )
        }
        receipts = {
            row["id"]: row
            for row in fetch(
                "observation_receipts", "collection_attempt_id=%s", child.execution_id
            )
        }
        attempts = {
            row["id"]: row
            for row in fetch("collection_attempts", "id=%s", child.execution_id)
        }
        providers = {
            row["id"]: row for row in fetch("provider_devices", "id=%s", provider)
        }
        received = next(iter(receipts))
        extras = {
            table: fetch(table, "receipt_id=%s", received)
            for table in (
                "patches",
                "device_missing_patches",
                "update_policy_observations",
            )
        }

    def verify(values):
        explained = {table: set() for table in extras}

        def verify_receipt(receipt_id, source_id, content_hash, kind):
            revision = revisions[receipts[receipt_id]["source_revision_id"]]
            assert kind == "exposure"
            assert source_id == revision["source_record_id"]
            assert content_hash == revision["content_hash"]

        verify_updates(
            values,
            sources,
            revisions,
            receipts,
            attempts,
            providers,
            explained,
            verify_receipt,
        )
        return explained

    explained = verify(extras)
    unrelated = deepcopy(extras)
    unrelated["patches"].append({"id": "synthetic-unrelated-public-patch"})
    assert verify(unrelated) == explained
    assert sum(map(len, explained.values())) == (
        2 if child.scope.source == "Defender" else 1
    )
    if child.scope.source == "Defender":
        missing = deepcopy(extras)
        missing["patches"] = []
        with pytest.raises(
            AssertionError, match="Missing patch source receipt differs"
        ):
            verify(missing)
        migrated = deepcopy(extras)
        migrated["patches"][0]["source_product_id"] = None
        assert verify(migrated) == explained
        migrated["patches"][0]["source_product_id"] = "invented-product"
        with pytest.raises(AssertionError, match="projection changed"):
            verify(migrated)
    changed = deepcopy(extras)
    if child.scope.source == "Defender":
        changed["device_missing_patches"][0]["reported_cve_count"] += 1
    else:
        changed["update_policy_observations"][0]["current_status"] = "changed"
    with pytest.raises(AssertionError):
        verify(changed)


def test_unrelated_patch_volume_does_not_accumulate_in_memory():
    import tracemalloc

    peaks = []
    for count in (100, 10_000):
        extras = {
            "patches": (
                {"id": str(n), "title": "Synthetic " * 1000} for n in range(count)
            ),
            "device_missing_patches": [],
            "update_policy_observations": [],
        }
        tracemalloc.start()
        try:
            verify_updates(extras, {}, {}, {}, {}, {}, {}, lambda *args: None)
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
    assert max(peaks) < 1024 * 1024


@pytest.mark.parametrize("update_bound", ["Defender"], indirect=True)
def test_new_status_rows_preserve_original_fixture_verification(
    db,  # noqa: F811
    update_bound,  # noqa: F811
    monkeypatch,
):
    import importlib.util
    from pathlib import Path

    device, child, _, _ = update_bound
    path = Path(__file__).resolve().parents[2] / "ui-engine/postgres/epss/baseline.py"
    monkeypatch.syspath_prepend(str(path.parent.parent))
    spec = importlib.util.spec_from_file_location("update_baseline", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with db.cursor() as cur:
        before = module.verify(cur)
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        result = module.verify(cur)
        assert (
            result["device_missing_patches"]
            == before.get("device_missing_patches", 0) + 1
        )
