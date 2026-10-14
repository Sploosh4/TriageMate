"""Query materialization retains scoped, pinned and unknown NVD evaluations."""

from backend.database import schema as database_schema

import pytest

from .test_store import db as db

from .test_windows_nvd_sql import (
    test_reader_preserves_pinned_facts_unknowns_and_separate_source_assertions as exercise_reader,
)


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("match", ["matched"]),
        ("excluded", ["excluded"]),
        ("prerequisite", ["unknown"]),
        ("missing", ["unknown"]),
        ("no_conditions", ["unknown"]),
        ("rejected", ["unknown"]),
        ("conflicting_scopes", ["excluded", "matched"]),
        ("lab_isolation", ["unknown"]),
        ("lab_public", ["matched"]),
    ],
)
def test_materialized_source_set_preserves_reader_results(db, mode, expected):
    with db.cursor() as cursor:
        database_schema.verify(cursor)
    exercise_reader(db, mode, expected)


def test_upgrade_is_idempotent_and_rejects_changed_authority(db):

    with db.cursor() as cursor:
        database_schema.verify(cursor)
        cursor.execute(
            "GRANT SELECT ON evidence_pipeline.current_windows_nvd_evaluations TO PUBLIC"
        )
        with pytest.raises(ValueError, match="schema/authority differs"):
            database_schema.verify(cursor)
