from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.notifications import (
    CollectionAttempt,
    collection_notifications,
)


def attempt(connection, hour, success=False):
    stamp = datetime(2026, 9, 12, tzinfo=timezone.utc) + timedelta(hours=hour)
    return CollectionAttempt(
        str(uuid4()),
        connection,
        stamp,
        stamp,
        success,
        "success" if success else "failure",
    )


def test_failures_coalesce_and_only_same_input_success_resolves():
    connection = str(uuid4())
    first, second = attempt(connection, 1), attempt(connection, 2)
    unrelated = attempt(str(uuid4()), 3, True)
    (notice,) = collection_notifications([unrelated, second, first])
    assert notice.status == "unresolved" and notice.failure_ids == (first.id, second.id)
    recovery = attempt(connection, 4, True)
    (resolved,) = collection_notifications([recovery, unrelated, second, first])
    assert resolved.id == notice.id and resolved.status == "resolved"
    assert (
        resolved.failure_ids == notice.failure_ids
        and resolved.recovery_attempt_id == recovery.id
    )
    assert first.outcome == "failure"


def test_failure_after_recovery_creates_distinct_episode():
    connection = str(uuid4())
    entries = [
        attempt(connection, 1),
        attempt(connection, 2, True),
        attempt(connection, 3),
    ]
    newer, older = collection_notifications(entries)
    assert newer.status == "unresolved" and older.status == "resolved"
    assert newer.id != older.id


def test_no_failed_attempt_means_no_notification():
    assert collection_notifications([]) == ()
    assert collection_notifications([attempt(str(uuid4()), 1, True)]) == ()


def test_duplicate_input_is_rejected_instead_of_inflating_failure_count():
    one = attempt(str(uuid4()), 1)
    with pytest.raises(ValueError):
        collection_notifications([one, one])


def test_projection_preserves_status_and_hostile_source_as_plain_data():
    from app.notifications import project_collection_rows

    (notice,) = collection_notifications([attempt(str(uuid4()), 1)])
    source = "bad\n```sql\nSELECT pg_sleep(20)\n```\n[link](https://example.invalid)"
    row = (
        notice.id,
        notice.connection_id,
        notice.first_failure_id,
        notice.latest_failure_id,
        notice.episode_started_at.isoformat(),
        notice.status,
        None,
        None,
        source,
        "devices",
        "Synthetic scope",
        "evidence-pipeline-v1:synthetic:test",
        notice.page,
        1,
        notice.first_failure_id,
        "microsoft_request_timeout",
        "critical",
        notice.episode_started_at.isoformat(),
    )
    (record,) = project_collection_rows([row])
    assert record["status"] == "unresolved" and record["source"] == source
    assert record["input"] == "devices" and record["scope"] == "Synthetic scope"
    assert notice.page.startswith("System/TriageMate/Notifiations/collection-")
