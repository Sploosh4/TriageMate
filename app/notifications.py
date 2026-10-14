"""Validated structured projection of persisted collection-failure episodes."""

from datetime import datetime
import json
from uuid import uuid4

from standalone.evidence_pipeline.notifications import CollectionNotification

QUERY = """
SELECT n.id::text,n.connection_id::text,n.first_failure_id::text,n.latest_failure_id::text,
       n.episode_started_at::text,n.status,n.recovery_attempt_id::text,n.resolved_at::text,
       c.source_name,c.input_kind,c.scope_reference,c.collector_reference,n.page_path,
       n.failure_count,x.collection_attempt_id::text,a.error_code,n.urgency,a.finished_at::text
FROM evidence.notifications n
JOIN evidence.source_connections c ON c.id=n.connection_id
JOIN evidence.notification_attempts x ON x.notification_id=n.id
JOIN evidence.collection_attempts a ON a.id=x.collection_attempt_id
WHERE n.category='collection-failure'
ORDER BY n.episode_started_at DESC,n.id,a.finished_at,a.started_at,a.id
"""

FAILURE_GUIDANCE = {
    "microsoft_token_request_timeout": "The Microsoft token request timed out. Check connectivity to the configured sign-in service before retrying. This does not establish credential expiry.",
    "microsoft_token_transport_failed": "The Microsoft token request could not complete over its HTTP connection. Check connectivity and TLS configuration; the underlying cause is not established.",
    "microsoft_request_timeout": "The Microsoft data request timed out. Any previously collected complete evidence is retained. Check service availability and the configured timeout before retrying.",
    "microsoft_request_transport_failed": "The Microsoft data request exhausted its connection retries. Check connectivity and TLS configuration; the underlying cause is not established.",
    "microsoft_request_throttled": "Microsoft throttled the request (HTTP 429). Retry later and check collection frequency if this recurs.",
    "microsoft_service_unavailable": "Microsoft returned a server error (HTTP 5xx). Retry later and check service health if this recurs.",
    "microsoft_token_request_rejected": "Microsoft rejected the token request. Check the configured application, resource and credential. This response does not establish credential expiry.",
    "microsoft_authentication_rejected": "Microsoft rejected authentication for the resource request (HTTP 401). This response does not establish certificate expiry or its cause.",
    "microsoft_access_forbidden": "Microsoft forbade the resource request (HTTP 403). Check the configured resource access and policy; this response does not identify which permission or policy caused the refusal.",
    "public_not_found": "The source returned no record for the requested input. Missing evidence remains missing.",
}


def project_collection_rows(rows):
    """Preserve exact episode membership and reject inconsistent persisted facts."""
    groups = {}
    for row in rows:
        if len(row) != 18:
            raise ValueError("Unexpected collection notification fields")
        groups.setdefault(row[0], []).append(row)
    output = []
    for group in groups.values():
        row = group[0]
        failures = tuple(item[14] for item in group)
        if len(failures) != row[13] or len(set(failures)) != len(failures):
            raise ValueError("Notification membership differs from its recorded count")
        if row[2] not in failures or row[3] not in failures:
            raise ValueError(
                "Notification first/latest failure is missing from membership"
            )
        if row[16] not in {"high", "critical"} or any(
            item[16] != row[16] for item in group
        ):
            raise ValueError("Invalid collection notification urgency")
        if row[16] == "high" and any(item[15] != "public_not_found" for item in group):
            raise ValueError("High source-absence alert contains another failure")
        if any(item[:14] != row[:14] for item in group):
            raise ValueError("Notification episode facts differ between members")
        if row[5] not in {"resolved", "unresolved"} or (
            (row[6] is not None or row[7] is not None)
            if row[5] == "unresolved"
            else (row[6] is None or row[7] is None or row[6] in failures)
        ):
            raise ValueError(
                "Notification resolution differs from its recovery evidence"
            )
        notice = CollectionNotification(
            row[0],
            row[1],
            row[2],
            row[3],
            failures,
            datetime.fromisoformat(row[4]),
            row[5],
            row[6],
            datetime.fromisoformat(row[7]) if row[7] else None,
            row[16],
        )
        if row[12] != notice.page:
            raise ValueError("Unexpected generated notification path")
        latest = next(item for item in group if item[14] == notice.latest_failure_id)
        output.append(
            {
                "id": notice.id,
                "source": row[8],
                "input": row[9],
                "scope": row[10],
                "status": notice.status,
                "urgency": notice.urgency,
                "startedAt": row[4],
                "resolvedAt": row[7],
                "failureCount": row[13],
                "message": (
                    f"{row[8]} returned no record ({row[10]})"
                    if notice.urgency == "high"
                    else f"{row[8]} {row[9]} collection failed ({row[10]})"
                ),
                "failures": [
                    {"attemptId": item[14], "code": item[15], "finishedAt": item[17]}
                    for item in group
                ],
                "details": {
                    "collectorReference": row[11],
                    "synthetic": row[11].startswith("evidence-pipeline-v1:synthetic:"),
                    "connectionId": notice.connection_id,
                    "firstFailureId": notice.first_failure_id,
                    "latestFailureId": notice.latest_failure_id,
                    "recoveryAttemptId": notice.recovery_attempt_id,
                    "checkedAt": latest[17],
                    "interpretation": FAILURE_GUIDANCE.get(
                        latest[15],
                        "Check collection status and source availability. Previously committed complete evidence remains available.",
                    ),
                },
            }
        )
    return output


def load_collection_notifications(queries):
    result = json.loads(queries.execute({"requestId": str(uuid4()), "sql": QUERY}))
    return project_collection_rows(result["rows"])


def exact_json_values(value):
    """Preserve measured integers beyond JavaScript's exact JSON number range."""
    if type(value) is int and abs(value) > 2**53 - 1:
        return str(value)
    if isinstance(value, dict):
        return {key: exact_json_values(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [exact_json_values(item) for item in value]
    return value
