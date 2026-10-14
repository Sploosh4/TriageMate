"""Provider-age notifications cannot claim a state unsupported by their clocks."""

from uuid import uuid4

import pytest

from .notifications import project


@pytest.mark.parametrize(
    "damage", [None, "condition", "basis", "precision", "threshold", "origin"]
)
@pytest.mark.parametrize(
    "source,input_kind,basis,precision",
    [
        ("FIRST", "epss", "score_date", "date"),
        ("Microsoft Update Catalog", "updates", "record_last_modified", "date"),
        ("Microsoft Update Catalog", "catalog_search", "record_last_modified", "date"),
        ("Microsoft Update Catalog", "catalog_targets", "record_last_modified", "date"),
        ("MSRC", "security_updates", "document_release", "timestamp"),
        ("MSRC", "repository", "oldest_document_release", "timestamp"),
        ("MITRE ATT&CK", "enterprise_definitions", "collection_modified", "timestamp"),
    ],
)
@pytest.mark.parametrize("origin", ["synthetic", "lab", "public"])
def test_notification_clock_validation(
    damage, source, input_kind, basis, precision, origin
):
    event = dict(
        kind="provider_age_opened",
        input_id=str(uuid4()),
        episode_id=str(uuid4()),
        at="2026-09-15T00:00:00+00:00",
        source=source,
        input_kind=input_kind,
        scope_reference="https://example.invalid/synthetic",
        origin=origin,
        max_age_seconds=172800,
        condition="stale",
        attempt_id=str(uuid4()),
        collected_at="2026-09-14T23:59:00+00:00",
        provider_time="2026-09-12T00:00:00+00:00",
        basis=basis,
        precision=precision,
    )
    if damage == "threshold":
        event["max_age_seconds"] = True
    elif damage is not None:
        event[damage] = "invalid"
    allowed_origin = origin in (
        {"synthetic", "lab"}
        if input_kind == "catalog_targets"
        else {"synthetic", "public"}
    )
    if damage or not allowed_origin:
        with pytest.raises(ValueError):
            project("synthetic-service", event, None, None, None, None)
    else:
        record = project("synthetic-service", event, None, None, None, None)
        assert record["synthetic"] is (origin == "synthetic")
        assert record["status"] == "unresolved"
        assert (
            record["details"]["basis"] == basis
            and record["details"]["precision"] == precision
        )


@pytest.mark.parametrize(
    "source,input_kind",
    [
        ("MSRC", "advisories"),
        ("CVE", "records"),
        ("CISA", "vulnrichment"),
        ("WA SOC", "advisories"),
        ("Microsoft Update Catalog", "updates"),
        ("Microsoft Update Catalog", "catalog_search"),
        ("Microsoft Update Catalog", "catalog_targets"),
    ],
)
@pytest.mark.parametrize("damage", [None, "basis", "time", "identity"])
def test_record_health_notice_preserves_old_publication(source, input_kind, damage):
    event = dict(
        kind="provider_age_resolved",
        input_id=str(uuid4()),
        episode_id=str(uuid4()),
        at="2026-09-18T12:00:00+00:00",
        source=source,
        input_kind=input_kind,
        scope_reference="https://example.invalid/synthetic",
        origin="synthetic",
        max_age_seconds=86400,
        condition="healthy",
        attempt_id=str(uuid4()),
        collected_at="2026-09-18T11:00:00+00:00",
        health_time="2026-09-18T11:00:00+00:00",
        health_basis="sealed_collection_journal"
        if input_kind in {"catalog_search", "catalog_targets"}
        else "successful_collection",
        provider_time="2010-01-01T00:00:00+00:00",
        basis="record_last_modified",
        precision="date" if source == "Microsoft Update Catalog" else "timestamp",
    )
    if damage == "basis":
        event["health_basis"] = "publisher_date"
    elif damage == "time":
        event["health_time"] = "2026-09-18T10:00:00+00:00"
    elif damage == "identity":
        event["attempt_id"] = None
    if damage:
        with pytest.raises(ValueError):
            project("synthetic-service", event, None, None, None, None)
    else:
        record = project("synthetic-service", event, None, None, None, None)
        assert record["status"] == "resolved"
        assert record["details"]["health_basis"] == event["health_basis"]
        assert (
            record["details"]["provider_time"].startswith("2010-01-01")
            and "Publication age is shown separately"
            in record["details"]["interpretation"]
        )
