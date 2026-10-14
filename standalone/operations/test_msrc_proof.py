"""Failed proofs promptly close discovery and CVRF iterators, even when retained."""

from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4
import pytest

from . import msrc_proof as module
from standalone.evidence_pipeline.test_msrc_publication_selection import publication


@pytest.mark.parametrize("failure", ["snapshot", "attempt", "receipts", "interrupted"])
def test_failed_proof_closes_borrowed_iterators(tmp_path, monkeypatch, failure):
    item = publication("2099-Jan")
    scope = module.source_scope("synthetic", item)
    closed = []

    def items():
        try:
            yield item
        finally:
            closed.append("index")

    def records():
        try:
            for number in range(300):
                yield SimpleNamespace(
                    source_record_id=f"synthetic-{number}", content_hash="a" * 64
                )
        finally:
            closed.append("records")

    held_items, held_records = items(), records()
    snapshot = SimpleNamespace(
        complete=failure != "snapshot", input_fingerprint="b" * 64, feed=lambda: None
    )
    monkeypatch.setattr(module, "prepare", lambda *a, **k: snapshot)
    monkeypatch.setattr(module, "normalize_public", lambda feed: held_records)
    cursor = Mock()
    cursor.fetchall.return_value = (
        []
        if failure == "attempt"
        else [(scope.connection_id, snapshot.input_fingerprint, item.url, "synthetic")]
    )

    def rejected(*args):
        if failure == "interrupted":
            raise KeyboardInterrupt("synthetic interrupted proof")
        return False

    monkeypatch.setattr(module.MsrcProof, "_receipts", staticmethod(rejected))
    proof = module.MsrcProof(None, frozenset())
    if failure == "interrupted":
        with pytest.raises(KeyboardInterrupt):
            proof.imports_committed(
                cursor, tmp_path, "synthetic", str(uuid4()), held_items
            )
    else:
        assert not proof.imports_committed(
            cursor, tmp_path, "synthetic", str(uuid4()), held_items
        )
    assert "index" in closed
    if failure in {"receipts", "interrupted"}:
        assert closed == ["records", "index"]
    assert held_items.gi_frame is None


@pytest.mark.parametrize("receipt_count", [0, 1])
def test_empty_publication_proof_requires_zero_database_receipts(
    tmp_path, monkeypatch, receipt_count
):
    item = publication("2099-Jan")
    scope = module.source_scope("synthetic", item)
    snapshot = SimpleNamespace(
        complete=True, input_fingerprint="b" * 64, feed=lambda: None
    )
    monkeypatch.setattr(module, "prepare", lambda *a, **k: snapshot)
    monkeypatch.setattr(module, "normalize_public", lambda feed: (x for x in ()))
    cursor = Mock()
    cursor.fetchall.return_value = [
        (scope.connection_id, snapshot.input_fingerprint, item.url, "synthetic")
    ]
    cursor.fetchone.return_value = (receipt_count,)
    proof = module.MsrcProof(None, frozenset())
    assert proof.imports_committed(
        cursor, tmp_path, "synthetic", str(uuid4()), (x for x in [item])
    ) is (receipt_count == 0)
