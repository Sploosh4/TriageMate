"""Collection projection preserves persisted episodes and refuses contradictory rows."""

from copy import deepcopy
import json
from uuid import uuid4

import pytest

from app.notifications import FAILURE_GUIDANCE, project_collection_rows


def row():
    identifier, attempt = str(uuid4()), str(uuid4())
    return [
        identifier,
        str(uuid4()),
        attempt,
        attempt,
        "2026-10-14T00:00:00+00:00",
        "unresolved",
        None,
        None,
        "Synthetic source",
        "devices",
        "synthetic-scope",
        "evidence-pipeline-v1:synthetic:test",
        "System/TriageMate/Notifiations/collection-" + identifier,
        1,
        attempt,
        "microsoft_request_timeout",
        "critical",
        "2026-10-14T00:01:00+00:00",
    ]


@pytest.mark.parametrize("code", list(FAILURE_GUIDANCE))
def test_exact_failure_details_and_actionable_guidance(code):
    value = row()
    value[15] = code
    value[16] = "high" if code == "public_not_found" else "critical"
    (notice,) = project_collection_rows([value])
    assert notice["failures"] == [
        {"attemptId": value[14], "code": code, "finishedAt": value[17]}
    ]
    assert notice["details"]["firstFailureId"] == value[2]
    assert notice["details"]["latestFailureId"] == value[3]
    assert notice["details"]["interpretation"] == FAILURE_GUIDANCE[code]
    assert notice["details"]["checkedAt"] == value[17]
    assert notice["failureCount"] == 1
    assert "markdown" not in notice


def test_resolution_keeps_failed_attempts_and_exact_recovery_identity():
    first = row()
    last = deepcopy(first)
    latest, recovery = str(uuid4()), str(uuid4())
    for value in (first, last):
        value[3] = latest
        value[5:8] = ["resolved", recovery, "2026-10-14T02:00:00+00:00"]
        value[13] = 2
    last[14] = latest
    last[17] = "2026-10-14T01:00:00+00:00"
    (notice,) = project_collection_rows([first, last])
    assert notice["status"] == "resolved" and notice["failureCount"] == 2
    assert notice["resolvedAt"] == first[7]
    assert notice["details"]["recoveryAttemptId"] == recovery
    assert [attempt["attemptId"] for attempt in notice["failures"]] == [
        first[14],
        latest,
    ]


@pytest.mark.parametrize(
    "damage",
    [
        "count",
        "first",
        "latest",
        "urgency",
        "high_wrong_code",
        "path",
        "status",
        "recovery",
        "date",
        "fields",
    ],
)
def test_invalid_episode_refuses_projection(damage):
    value = row()
    changes = {
        "count": (13, 2),
        "first": (2, str(uuid4())),
        "latest": (3, str(uuid4())),
        "urgency": (16, "moderate"),
        "high_wrong_code": (16, "high"),
        "path": (12, "unexpected"),
        "status": (5, "invented"),
        "recovery": (6, str(uuid4())),
        "date": (4, "not-a-date"),
    }
    if damage == "fields":
        value.pop()
    else:
        index, changed = changes[damage]
        value[index] = changed
    with pytest.raises(ValueError):
        project_collection_rows([value])


@pytest.mark.parametrize(
    "damage", ["duplicate", "mixed_urgency", "mixed_high_failure", "different_scope"]
)
def test_member_rows_cannot_contradict_episode(damage):
    first = row()
    second = deepcopy(first)
    latest = str(uuid4())
    for value in (first, second):
        value[13] = 2
        value[3] = latest
    second[14] = latest
    if damage == "duplicate":
        second[14] = first[14]
    elif damage == "mixed_urgency":
        second[16] = "high"
    elif damage == "mixed_high_failure":
        first[16] = second[16] = "high"
        first[15] = "public_not_found"
    else:
        second[10] = "another-scope"
    with pytest.raises(ValueError):
        project_collection_rows([first, second])


def test_source_text_is_plain_json_data():
    value = row()
    injected = "\n```sql\nDELETE FROM evidence.notifications;\n```\n[link](https://example.invalid)"
    value[8] = value[10] = injected
    (notice,) = project_collection_rows([value])
    assert notice["source"] == notice["scope"] == injected
    assert json.loads(json.dumps(notice))["source"] == injected


def test_collector_provenance_survives_projection():
    value = row()
    reference = "evidence-pipeline-v1:synthetic:notification-regression"
    value[11] = reference
    (notice,) = project_collection_rows([value])
    assert notice["details"]["collectorReference"] == reference
    assert notice["details"]["synthetic"] is True
