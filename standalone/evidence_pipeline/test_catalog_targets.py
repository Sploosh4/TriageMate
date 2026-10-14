"""Pinned missing-patch evidence selects identities, never applicability."""

from dataclasses import replace
import json
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.collection.catalog_targets import select_targets
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from .test_store import db, snapshot  # noqa: F401
from .test_update_schema import update_bound  # noqa: F401


@pytest.mark.parametrize("update_bound", ["Defender"], indirect=True)
@pytest.mark.parametrize(
    "reference",
    [
        "KB9999991",
        "KB-synthetic",
        "9999991",
        "999",
        "99999999999",
        " 9999991",
        "９９９９９９１",
        "9999991 OR 1=1",
    ],
)
def test_pinned_targets_and_unresolved_references(db, update_bound, reference):  # noqa: F811
    device, child, _, _ = update_bound
    raw = child.records()[0]
    raw["id"] = reference
    child = replace(child, payload=json.dumps([raw]).encode())
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        selected = select_targets(
            cur, {child.scope.connection_id: child.execution_id}, origin="synthetic"
        )
        assert selected.snapshots == ((child.scope.connection_id, child.execution_id),)
        assert selected.kbs == (
            ("KB9999991",) if reference in ("KB9999991", "9999991") else ()
        )
        assert selected.complete == (reference in ("KB9999991", "9999991"))
        assert selected.unresolved_references == (0 if selected.complete else 1)
        cur.execute(
            "SELECT source_patch_id FROM evidence_pipeline.current_missing_patches WHERE connection_id=%s",
            (child.scope.connection_id,),
        )
        assert cur.fetchall() == [(reference,)]
        with pytest.raises(ValueError, match="snapshot"):
            select_targets(
                cur, {child.scope.connection_id: str(uuid4())}, origin="synthetic"
            )
        with pytest.raises(ValueError, match="snapshot"):
            select_targets(
                cur, {child.scope.connection_id: child.execution_id}, origin="lab"
            )


@pytest.mark.parametrize("update_bound", ["Defender"], indirect=True)
@pytest.mark.parametrize(
    "references", [[], ["KB9999991", "KB9999992"], ["9999991", "KB9999991"]]
)
def test_empty_selection_and_request_budget(db, update_bound, references):  # noqa: F811
    device, child, _, _ = update_bound
    original = child.records()[0]
    child = replace(
        child, payload=json.dumps([dict(original, id=kb) for kb in references]).encode()
    )
    persist_exposure(db, child, device.execution_id)
    with db.cursor() as cur:
        cur.execute("SET CONSTRAINTS ALL IMMEDIATE")
        cur.execute("SET LOCAL ROLE tm_mock_reader")
        selection = select_targets(
            cur, {child.scope.connection_id: child.execution_id}, origin="synthetic"
        )
        expected = tuple(
            sorted({r if r.startswith("KB") else "KB" + r for r in references})
        )
        assert selection.kbs == expected and selection.complete
        if len(expected) > 1:
            with pytest.raises(ValueError, match="budget exceeded"):
                select_targets(
                    cur,
                    {child.scope.connection_id: child.execution_id},
                    origin="synthetic",
                    maximum=1,
                )
        with pytest.raises(ValueError, match="snapshot"):
            select_targets(
                cur,
                {device.scope.connection_id: device.execution_id},
                origin="synthetic",
            )
