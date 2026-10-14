"""Critical repository-run episodes committed with the completion checkpoint."""

import hashlib
import json
import re
from uuid import UUID

from standalone.evidence_pipeline.contracts import identifier
from .checkpoint import keys, timestamp
from .repository_recipe import SOURCE_URLS, source_reference
from standalone.evidence_pipeline.persistence.enrichment_store import (
    SOURCES as ENRICHMENT_SOURCES,
)


def record(cursor, key, revision, previous, current, sources, *, enrichment=False):
    if previous is None:
        return
    for input_id, source in sources.items():
        before, after = previous.inputs.get(input_id), current.inputs.get(input_id)
        if (
            before is None
            or before.active is None
            or after is None
            or after.active is not None
        ):
            continue
        job = before.active
        if not after.latest_success and previous.control.desired.value != "running":
            continue  # Planned shutdown is not an unexpected collection failure.
        contract = current.definitions[input_id].worker_contract
        event_kind = "enrichment_failure" if enrichment else "repository_failure"
        cursor.execute(
            "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
            "AND event->>'kind'=%s AND event->>'input_id'=%s "
            "AND event->>'worker_contract'=%s ORDER BY id DESC LIMIT 1",
            (key, event_kind, input_id, contract),
        )
        row = cursor.fetchone()
        last = row[0] if row else None
        if last is not None:
            validate(last)
        open_episode = last is not None and last["status"] == "unresolved"
        if after.latest_success and not open_episode:
            continue
        at = current.clock.isoformat()
        event = dict(
            kind=event_kind,
            input_id=input_id,
            worker_contract=contract,
            source=source["source"],
            origin=source["origin"],
            episode_id=last["episode_id"] if open_episode else job.run_id,
            first_failed_at=last["first_failed_at"] if open_episode else at,
            last_failed_at=last["last_failed_at"] if after.latest_success else at,
            failure_count=last["failure_count"] + (not after.latest_success)
            if open_episode
            else 1,
            failed_run_id=last["failed_run_id"] if after.latest_success else job.run_id,
            recovery_run_id=job.run_id if after.latest_success else None,
            status="resolved" if after.latest_success else "unresolved",
            at=at,
            **(
                (
                    {"mode": "targets"}
                    if source.get("mode") == "targets"
                    else {"kb": source["kb"]}
                )
                if source["source"] == "Microsoft Update Catalog"
                else {}
            ),
        )
        validate(event)
        cursor.execute(
            "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) "
            "VALUES(%s,%s,%s,%s::jsonb)",
            (key, revision, current.clock, json.dumps(event)),
        )


def failure_scope(event):
    if event.get("kind") == "enrichment_failure":
        if event.get("source") not in ENRICHMENT_SOURCES or event.get("origin") not in {
            "synthetic",
            "public",
        }:
            raise ValueError("Invalid enrichment failure scope")
        return "triagemate:enrichment/" + event["source"]
    return source_reference(
        {key: event[key] for key in ("source", "origin", "kb", "mode") if key in event}
    )


def validate(event):
    keys(
        event,
        [
            "kind",
            "input_id",
            "worker_contract",
            "source",
            "origin",
            "episode_id",
            "first_failed_at",
            "last_failed_at",
            "failure_count",
            "failed_run_id",
            "recovery_run_id",
            "status",
            "at",
        ]
        + (
            ["mode" if "mode" in event else "kb"]
            if event.get("source") == "Microsoft Update Catalog"
            else []
        ),
    )
    failure_scope(event)
    for name in ("input_id", "episode_id", "failed_run_id"):
        identifier(event[name])
    first, last, at = (
        timestamp(event[name]) for name in ("first_failed_at", "last_failed_at", "at")
    )
    if (
        event["kind"] not in {"repository_failure", "enrichment_failure"}
        or event["source"]
        not in (
            ENRICHMENT_SOURCES if event["kind"] == "enrichment_failure" else SOURCE_URLS
        )
        or event["origin"] not in {"synthetic", "public"}
        or not isinstance(event["worker_contract"], str)
        or re.fullmatch(r"[a-f0-9]{64}", event["worker_contract"]) is None
        or type(event["failure_count"]) is not int
        or event["failure_count"] < 1
        or not first <= last <= at
        or event["status"] not in {"resolved", "unresolved"}
    ):
        raise ValueError("Invalid repository failure episode")
    if event["status"] == "resolved":
        identifier(event["recovery_run_id"])
        if event["recovery_run_id"] == event["failed_run_id"]:
            raise ValueError("Recovery requires a later complete run")
    elif event["recovery_run_id"] is not None:
        raise ValueError("Unresolved repository failure cannot contain recovery")


def project(key, event):
    validate(event)
    notice_id = str(
        UUID(
            hashlib.sha256(
                (
                    (
                        "triagemate-enrichment-failure-v1\0"
                        if event["kind"] == "enrichment_failure"
                        else "triagemate-repository-failure-v1\0"
                    )
                    + key
                    + "\0"
                    + event["input_id"]
                    + "\0"
                    + event["episode_id"]
                ).encode()
            ).hexdigest()[:32]
        )
    )
    source, status = event["source"], event["status"]
    scope = failure_scope(event)
    notice = dict(
        id=notice_id,
        category="collection-failure",
        parameters=dict(api=source, organisation=scope),
        message=source
        + (
            " enrichment collection failed"
            if event["kind"] == "enrichment_failure"
            else " search collection failed"
            if source == "Microsoft Update Catalog"
            else " RSS collection failed"
            if source == "Cisco"
            else " repository collection failed"
        ),
        urgency="critical",
        synthetic=event["origin"] == "synthetic",
        status=status,
        placeholder=False,
        page="System/TriageMate/Notifiations/operation-" + notice_id,
    )
    return {
        **notice,
        "details": {
            **event,
            "interpretation": "The collection run did not establish complete committed evidence. Previously committed records remain available. Failed runs remain failed in history; only a later complete collection resolves this notification.",
        },
    }
