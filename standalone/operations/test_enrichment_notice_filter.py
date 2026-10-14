"""Internal batch declarations cannot become notifications or mask an episode."""

import json
from uuid import uuid4
from standalone.evidence_pipeline.runtime import local_database
from .notifications import SQL
from .dispatch import Dispatcher
from .store import save
from .test_dispatch import at


def test_refresh_and_initial_journals_are_not_notification_events():
    conn = local_database().connect()
    key = "synthetic-journal-filter-" + uuid4().hex
    input_id = str(uuid4())
    try:
        with conn.cursor() as cur:
            save(cur, key, 0, Dispatcher([], now=at(0)))
            for kind in ["enrichment_batch", "enrichment_refresh_batch"]:
                cur.execute(
                    "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) VALUES(%s,1,%s,%s::jsonb)",
                    (
                        key,
                        at(0),
                        json.dumps(
                            dict(kind=kind, input_id=input_id, run_id=str(uuid4()))
                        ),
                    ),
                )
            cur.execute(SQL, (key,))
            assert cur.fetchall() == []
    finally:
        conn.rollback()
        conn.close()


import pytest  # noqa: E402
from .repository_failures import validate  # noqa: E402


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "unapproved"),
        ("origin", "lab"),
        ("kind", "unknown_failure"),
        ("worker_contract", "changed"),
        ("failure_count", 0),
    ],
)
def test_enrichment_failure_rejects_changed_authority(field, value):
    event = dict(
        kind="enrichment_failure",
        input_id=str(uuid4()),
        worker_contract="a" * 64,
        source="CVE",
        origin="public",
        episode_id=str(uuid4()),
        first_failed_at=at(0).isoformat(),
        last_failed_at=at(0).isoformat(),
        failure_count=1,
        failed_run_id=str(uuid4()),
        recovery_run_id=None,
        status="unresolved",
        at=at(0).isoformat(),
    )
    validate(event)
    event[field] = value
    with pytest.raises(ValueError):
        validate(event)
