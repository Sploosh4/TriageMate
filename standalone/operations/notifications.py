"""Validate committed operational episodes for structured notification screens."""

from contextlib import closing
import hashlib
from uuid import UUID

from standalone.evidence_pipeline.runtime import connect
from .checkpoint import keys, timestamp, integer
from .dispatch import identity
from .store import service_key


SQL = """
SELECT latest.event,c.source_name,c.input_kind,c.scope_reference,c.collector_reference
FROM (
 SELECT DISTINCT ON (event->>'input_id',coalesce(event->>'original_run_id',event->>'episode_id')) id,event
 FROM evidence_pipeline.operation_events WHERE service_key=%s
 AND event->>'kind' NOT IN ('enrichment_batch','enrichment_refresh_batch','redhat_index','catalog_search','catalog_targets','cisco_rss','msrc_index')
 ORDER BY event->>'input_id',coalesce(event->>'original_run_id',event->>'episode_id'),id DESC
) latest
LEFT JOIN evidence.source_connections c ON c.id::text=latest.event->>'input_id'
ORDER BY latest.id DESC LIMIT 1001
"""


def project(key, event, source, kind, scope, collector):
    key = service_key(key)
    original = dict(event) if isinstance(event, dict) else event
    if isinstance(event, dict) and event.get("kind") in {
        "repository_failure",
        "enrichment_failure",
    }:
        from .repository_failures import project as repository_failure

        return repository_failure(key, event)
    if isinstance(event, dict) and event.get("kind") in {
        "storage_opened",
        "storage_updated",
        "storage_resolved",
    }:
        from .storage_notice import project as project_storage

        return project_storage(key, event)
    if isinstance(event, dict) and event.get("kind") in {
        "provider_age_opened",
        "provider_age_updated",
        "provider_age_resolved",
    }:
        from .provider_notice import project as project_provider

        return project_provider(key, event)
    if isinstance(event, dict) and "enrichment_scope" in event:
        from standalone.evidence_pipeline.persistence.enrichment_store import SOURCES

        event = dict(event)
        enrichment = event.pop("enrichment_scope")
        keys(enrichment, ["source", "origin"])
        if (
            enrichment["source"] not in SOURCES
            or enrichment["origin"] not in {"synthetic", "public"}
            or "repository_scope" in event
            or event.get("kind")
            not in {
                "overlap_opened",
                "overlap_updated",
                "overlap_resolved",
                "overdue_opened",
                "overdue_resolved",
            }
        ):
            raise ValueError("Invalid enrichment notification scope")
        source, kind = enrichment["source"], "enrichment"
        scope = "triagemate:enrichment/" + source
        collector = "evidence-pipeline-v1:" + enrichment["origin"] + ":enrichment"
    if isinstance(event, dict) and "repository_scope" in event:
        from .repository_recipe import source_reference

        event = dict(event)
        repository = event.pop("repository_scope")
        scope = source_reference(repository)
        if event.get("kind") not in {
            "overlap_opened",
            "overlap_updated",
            "overlap_resolved",
            "overdue_opened",
            "overdue_resolved",
        }:
            raise ValueError("Invalid repository notification scope")
        source = repository["source"]
        kind = (
            "catalog_targets"
            if repository.get("mode") == "targets"
            else "catalog_search"
            if source == "Microsoft Update Catalog"
            else "repository"
        )
        collector = "evidence-pipeline-v1:" + repository["origin"] + ":repository"
    if isinstance(event, dict) and event.get("kind") in (
        "credential_opened",
        "credential_updated",
        "credential_resolved",
    ):
        return project_certificate(key, event)
    if isinstance(event, dict) and event.get("kind") in (
        "overdue_opened",
        "overdue_resolved",
    ):
        record = project_overdue(key, event, source, kind, scope, collector)
        record["details"].update(original)
        return record
    keys(event, ["kind", "input_id", "original_run_id", "skipped_count", "at"])
    if event["kind"] not in ("overlap_opened", "overlap_updated", "overlap_resolved"):
        raise ValueError("Unsupported operational notification event")
    count = integer(event["skipped_count"])
    if count < 2:
        raise ValueError("An overlap episode requires two skipped scheduled runs")
    input_id, run_id = identity(event["input_id"]), identity(event["original_run_id"])
    timestamp(event["at"])
    # A deleted/retired input does not erase its committed operational episode.
    source, kind, scope = source or "Input", kind or input_id, scope or input_id
    raw = "triagemate-overlap-v1\0" + key + "\0" + input_id + "\0" + run_id
    notice_id = str(UUID(hashlib.sha256(raw.encode()).hexdigest()[:32]))
    status = "resolved" if event["kind"] == "overlap_resolved" else "unresolved"
    record = dict(
        id=notice_id,
        category="collection-overlap",
        parameters={"api": source, "organisation": scope},
        message=f"{source} {kind}: {count} scheduled collections skipped during an active run",
        urgency="moderate",
        synthetic=bool(
            collector and collector.startswith("evidence-pipeline-v1:synthetic:")
        ),
        status=status,
        placeholder=False,
        page="System/TriageMate/Notifiations/operation-" + notice_id,
    )
    return {
        **record,
        "details": {
            **original,
            "interpretation": "Skips follow the configured interval; they are not assumed to be hourly. A subsequent scheduled collection completed successfully. The skipped runs remain recorded."
            if status == "resolved"
            else "Skips follow the configured interval; they are not assumed to be hourly. Finishing the original slow run does not resolve this episode; a subsequent scheduled collection must succeed.",
        },
    }


def project_overdue(key, event, source, kind, scope, collector):
    keys(
        event,
        ["kind", "input_id", "episode_id", "reference_at", "threshold_seconds", "at"],
    )
    input_id, episode = identity(event["input_id"]), identity(event["episode_id"])
    reference, updated = timestamp(event["reference_at"]), timestamp(event["at"])
    threshold = integer(event["threshold_seconds"])
    if (
        threshold < 1
        or reference > updated
        or (
            event["kind"] == "overdue_opened"
            and (updated - reference).total_seconds() < threshold
        )
    ):
        raise ValueError("Invalid overdue collection episode")
    raw = "triagemate-overdue-v1\0" + key + "\0" + input_id + "\0" + episode
    notice_id = str(UUID(hashlib.sha256(raw.encode()).hexdigest()[:32]))
    status = "resolved" if event["kind"] == "overdue_resolved" else "unresolved"
    source, kind, scope = source or "Input", kind or input_id, scope or input_id
    record = dict(
        id=notice_id,
        category="collection-overdue",
        parameters={"api": source, "organisation": scope},
        message=f"{source} {kind}: scheduled collection overdue",
        urgency="moderate",
        synthetic=bool(
            collector and collector.startswith("evidence-pipeline-v1:synthetic:")
        ),
        status=status,
        placeholder=False,
        page="System/TriageMate/Notifiations/operation-" + notice_id,
    )
    return {
        **record,
        "details": {
            **event,
            "interpretation": "This measures collection timeliness, not the publisher's data age. Existing usable evidence remains available.",
        },
    }


def project_certificate(key, event):
    keys(
        event,
        [
            "kind",
            "input_id",
            "episode_id",
            "at",
            "label",
            "origin",
            "provenance",
            "warn_before_seconds",
            "condition",
            "fingerprint",
            "not_before",
            "expires_at",
        ]
        + (["metadata_type"] if "metadata_type" in event else []),
    )
    reference, episode = identity(event["input_id"]), identity(event["episode_id"])
    label = identity(event["label"])
    timestamp(event["at"])
    descriptions = {
        "expiring": "certificate expires soon",
        "expired": "certificate has expired",
        "not_yet_valid": "certificate is not yet valid",
        "unavailable": "certificate validity is unavailable",
        "healthy": "certificate validity is confirmed",
    }
    declared = "metadata_type" in event
    if declared:
        if event["metadata_type"] not in {
            "declared",
            "client_secret",
            "api_key",
            "certificate",
        }:
            raise ValueError("Invalid credential metadata type")
        descriptions = {
            "expiring": "declared credential expiry is approaching",
            "expired": "declared credential expiry has passed",
            "not_yet_valid": "declared credential validity has not begun",
            "unavailable": "credential expiry metadata is unavailable",
            "healthy": "declared credential expiry is outside the warning window",
        }
    condition = event["condition"]
    if (
        condition not in descriptions
        or event["origin"] not in ("synthetic", "public", "lab")
        or integer(event["warn_before_seconds"]) < 1
    ):
        raise ValueError("Invalid credential notification")
    if (
        not isinstance(event["provenance"], str)
        or not 1 <= len(event["provenance"]) <= 4096
    ):
        raise ValueError("Invalid certificate provenance")
    resolved = event["kind"] == "credential_resolved"
    if resolved != (condition == "healthy"):
        raise ValueError("Credential resolution does not match observed validity")
    if condition == "unavailable":
        if any(
            event[name] is not None
            for name in ("fingerprint", "not_before", "expires_at")
        ):
            raise ValueError("Unavailable certificate cannot assert validity metadata")
    else:
        fingerprint = event["fingerprint"]
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in fingerprint)
        ):
            raise ValueError("Invalid certificate fingerprint")
        expiry = timestamp(event["expires_at"])
        before = (
            None
            if declared and event["not_before"] is None
            else timestamp(event["not_before"])
        )
        if before is not None and before >= expiry:
            raise ValueError("Invalid certificate validity period")
    raw = "triagemate-certificate-v1\0" + key + "\0" + reference + "\0" + episode
    notice_id = str(UUID(hashlib.sha256(raw.encode()).hexdigest()[:32]))
    status = "resolved" if resolved else "unresolved"
    urgency = "moderate" if condition in ("expiring", "healthy") else "critical"
    record = dict(
        id=notice_id,
        category="credential-expiry",
        parameters={"api": label, "organisation": key},
        message=label + ": " + descriptions[condition],
        urgency=urgency,
        synthetic=event["origin"] == "synthetic",
        status=status,
        placeholder=False,
        page="System/TriageMate/Notifiations/operation-" + notice_id,
    )
    return {
        **record,
        "details": {
            **event,
            "interpretation": "Expiry comes from an explicit metadata declaration, not a live provider check. Revocation and provider acceptance remain unknown. No credential value is read, renewed or changed."
            if declared
            else "This checks certificate validity metadata only. It does not prove provider acceptance, permissions or collection authentication. No private key is parsed and provider access is not changed.",
        },
    }


def load(key, connector=connect):
    key = service_key(key)
    with closing(connector()) as conn, conn, conn.cursor() as cur:
        cur.execute(SQL, (key,))
        rows = cur.fetchall()
    if len(rows) > 1000:
        raise ValueError("Operational notification history exceeds the response bound")
    return [project(key, *row) for row in rows]
