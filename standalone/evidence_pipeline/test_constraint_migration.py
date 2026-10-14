"""Explicit migration and inherited exposure behavior, all rolled back."""

from backend.database import schema as database_schema

import pytest

from . import test_exposure_store as exposure_tests
from .test_store import db as database_fixture, snapshot as snapshot_fixture
from .test_exposure_store import bound as bound_fixture

db = database_fixture
snapshot = snapshot_fixture
bound = bound_fixture


def test_upgrade_repeatability_and_schema_drift(db):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "ALTER FUNCTION evidence.check_provenance() SET search_path=public"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)


@pytest.mark.parametrize(
    "case",
    [
        "test_inventory_persists_zero_cve_software_and_zero_link_apps",
        "test_same_content_new_receipts_and_failed_or_empty_snapshots",
        "test_invalid_associations_roll_back_attempt_and_preserve_existing",
        "test_unrelated_or_failed_device_attempt_rejected",
        "test_restricted_runtime_can_ingest_but_cannot_change_binding",
    ],
)
def test_exposure_contracts_after_optimization(db, bound, case):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    getattr(exposure_tests, case)(db, bound)


@pytest.mark.parametrize("bound", ["Defender"], indirect=True)
def test_defender_findings_after_optimization(db, bound):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    exposure_tests.test_findings_preserve_source_fix_reference_without_fabricating_patch(
        db, bound
    )
