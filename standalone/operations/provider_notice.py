"""Project provider-age episodes after validating their clock evidence."""

import hashlib
from uuid import UUID

from standalone.evidence_pipeline.contracts import identifier
from .checkpoint import keys, timestamp
from .provider_age import SUPPORTED, COLLECTION_HEALTH_INPUTS, classify, clock_basis
from .repository_age import SOURCES as REPOSITORY_SOURCES, HEALTH_BASIS


def project(key, event):
    collection_health = "health_time" in event or "health_basis" in event
    keys(
        event,
        [
            "kind",
            "input_id",
            "episode_id",
            "at",
            "source",
            "input_kind",
            "scope_reference",
            "origin",
            "max_age_seconds",
            "condition",
            "attempt_id",
            "collected_at",
            "provider_time",
            "basis",
            "precision",
        ]
        + (["health_time", "health_basis"] if collection_health else []),
    )
    if (
        event["kind"]
        not in {"provider_age_opened", "provider_age_updated", "provider_age_resolved"}
        or (event["source"], event["input_kind"])
        not in SUPPORTED
        | {(source, "repository") for source in REPOSITORY_SOURCES}
        | {
            ("Microsoft Update Catalog", "catalog_search"),
            ("Microsoft Update Catalog", "catalog_targets"),
            ("MSRC", "repository"),
        }
        or event["origin"]
        not in (
            {"synthetic", "lab"}
            if event["input_kind"] == "catalog_targets"
            else {"synthetic", "public"}
        )
    ):
        raise ValueError("Invalid provider-age notification")
    input_id, episode = identifier(event["input_id"]), identifier(event["episode_id"])
    at = timestamp(event["at"])
    clock = (
        None if event["provider_time"] is None else timestamp(event["provider_time"])
    )
    health_clock = clock
    if collection_health:
        expected_basis = {
            **{(source, "repository"): HEALTH_BASIS for source in REPOSITORY_SOURCES},
            ("MSRC", "repository"): "sealed_collection_journal",
            **dict.fromkeys(COLLECTION_HEALTH_INPUTS, "successful_collection"),
            ("Microsoft Update Catalog", "catalog_search"): "sealed_collection_journal",
            (
                "Microsoft Update Catalog",
                "catalog_targets",
            ): "sealed_collection_journal",
        }.get((event["source"], event["input_kind"]))
        if expected_basis is None or event["health_basis"] != expected_basis:
            raise ValueError("Invalid collection-health clock meaning")
        health_clock = (
            None if event["health_time"] is None else timestamp(event["health_time"])
        )
        if health_clock is not None and (
            event["attempt_id"] is None or event["health_time"] != event["collected_at"]
        ):
            raise ValueError("Collection health requires its verified seal identity")
    condition = classify(health_clock, at, max_age_seconds=event["max_age_seconds"])
    resolved = event["kind"] == "provider_age_resolved"
    if condition != event["condition"] or resolved != (condition == "healthy"):
        raise ValueError("Provider-age event disagrees with its clock evidence")
    if (event["attempt_id"] is None) != (event["collected_at"] is None):
        raise ValueError("Incomplete provider collection identity")
    if event["attempt_id"] is not None:
        identifier(event["attempt_id"])
        timestamp(event["collected_at"])
    if clock is None:
        if event["basis"] is not None or event["precision"] is not None:
            raise ValueError("Unknown provider clock cannot claim timestamp precision")
    elif event["basis"] != clock_basis(event["source"], event["input_kind"]) or event[
        "precision"
    ] not in (
        {"date", "timestamp"}
        if event["source"] == "FIRST"
        else {"date"}
        if event["source"] == "Microsoft Update Catalog"
        else {"timestamp"}
    ):
        raise ValueError("Invalid provider clock meaning")
    if (
        not isinstance(event["scope_reference"], str)
        or not 1 <= len(event["scope_reference"]) <= 4096
    ):
        raise ValueError("Invalid provider scope")
    notice_id = str(
        UUID(
            hashlib.sha256(
                (
                    "triagemate-provider-age-v1\0"
                    + key
                    + "\0"
                    + input_id
                    + "\0"
                    + episode
                ).encode()
            ).hexdigest()[:32]
        )
    )
    label = {
        "stale": "provider timestamp exceeds the configured age",
        "future": "provider timestamp is in the future",
        "unknown": "provider timestamp could not be verified",
        "healthy": "provider timestamp is within the configured age",
    }[condition]
    if collection_health:
        label = {
            "stale": "verified collection exceeds the configured age",
            "future": "verified collection journal time is in the future",
            "unknown": "complete collection could not be verified",
            "healthy": "verified collection is within the configured age",
        }[condition]
    status = "resolved" if resolved else "unresolved"
    record = dict(
        id=notice_id,
        category="provider-data-age",
        parameters={"api": event["source"], "organisation": event["scope_reference"]},
        message=event["source"] + ": " + label,
        urgency="moderate",
        synthetic=event["origin"] == "synthetic",
        status=status,
        placeholder=False,
        page="System/TriageMate/Notifiations/operation-" + notice_id,
    )
    return {
        **record,
        "details": {
            **event,
            "interpretation": "Publication age is shown separately and does not make a freshly collected historical archive stale. An unknown publication clock remains unknown."
            if collection_health
            else "Historical publications can be old after a fresh collection; an unknown document clock makes the aggregate unknown. Collection timing and provider publication age are separate.",
        },
    }
