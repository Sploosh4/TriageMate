"""Project measured storage-pressure episodes after validating their evidence."""

import hashlib
import re
from uuid import UUID

from .checkpoint import keys, integer, timestamp
from standalone.evidence_pipeline.contracts import identifier


def project(key, event):
    keys(
        event,
        [
            "kind",
            "input_id",
            "episode_id",
            "at",
            "condition",
            "database_bytes",
            "filesystem_bytes",
            "known_bytes",
            "incomplete_reasons",
            "maximum_bytes",
            "directories_count",
            "policy_fingerprint",
        ],
    )
    if (
        event["kind"] not in {"storage_opened", "storage_updated", "storage_resolved"}
        or event["input_id"] != "storage"
    ):
        raise ValueError("Invalid storage notification")
    episode = identifier(event["episode_id"])
    timestamp(event["at"])
    maximum = integer(event["maximum_bytes"])
    files = integer(event["filesystem_bytes"])
    database = (
        None if event["database_bytes"] is None else integer(event["database_bytes"])
    )
    reasons = event["incomplete_reasons"]
    allowed = {
        "entry_budget",
        "time_budget",
        "allocation_unavailable",
        "depth_budget",
        "concurrent_change",
        "special_file",
        "unreadable_entry",
        "unreadable_directory",
        "unreadable_root",
        "database_unavailable",
    }
    if (
        not isinstance(reasons, list)
        or any(not isinstance(value, str) or value not in allowed for value in reasons)
        or len(set(reasons)) != len(reasons)
        or not 1 <= maximum <= 2**63 - 1
        or not 1 <= integer(event["directories_count"]) <= 32
        or not isinstance(event["policy_fingerprint"], str)
        or not re.fullmatch("[0-9a-f]{64}", event["policy_fingerprint"])
        or (database is None) != ("database_unavailable" in reasons)
    ):
        raise ValueError("Invalid storage measurement evidence")
    known = files + (database or 0)
    condition = (
        "over_limit" if known >= maximum else "unknown" if reasons else "below_limit"
    )
    resolved = event["kind"] == "storage_resolved"
    if (
        integer(event["known_bytes"]) != known
        or event["condition"] != condition
        or resolved != (condition == "below_limit")
    ):
        raise ValueError("Storage notification disagrees with measured evidence")
    notice_id = str(
        UUID(
            hashlib.sha256(
                ("triagemate-storage-v1\0" + key + "\0" + episode).encode()
            ).hexdigest()[:32]
        )
    )
    label = {
        "over_limit": "Monitored storage reached its configured allowance",
        "unknown": "Monitored storage could not be measured completely",
        "below_limit": "Monitored storage is below its configured allowance",
    }[condition]
    status = "resolved" if resolved else "unresolved"
    record = dict(
        id=notice_id,
        category="storage-pressure",
        parameters={"api": "TriageMate", "organisation": "Local storage"},
        message=label,
        urgency="moderate",
        synthetic=False,
        status=status,
        placeholder=False,
        page="System/TriageMate/Notifiations/operation-" + notice_id,
    )
    return {
        **record,
        "details": {
            **event,
            "interpretation": "This sample covers the connected database and configured product directories. Shared WAL, server logs and backups are excluded unless separately configured outside the database directory. Nothing was deleted and no collection was cancelled. This episode sample is not a live counter.",
        },
    }
