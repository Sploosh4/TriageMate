"""Deterministic receipt-bound antivirus observations; no overall health verdict."""

from dataclasses import asdict
import json

from standalone.evidence_pipeline.parsing.antivirus import AntivirusHealth
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id


def source_record_id(item):
    if not isinstance(item, AntivirusHealth):
        raise ValueError("Unsupported antivirus observation")
    return json.dumps(
        ["antivirus", item.source_record_id], ensure_ascii=False, separators=(",", ":")
    )


def content(item):
    source_record_id(item)
    return asdict(item)


def rows(item, receipt_id, provider_device_id, observed_at):
    source_record_id(item)
    receipt_id = identifier(receipt_id)
    provider_device_id = identifier(provider_device_id)
    observation = item.observation()
    group = observation["source_rbac_group_id"]
    # The established schema stores source group IDs as text, without interpretation.
    observation["source_rbac_group_id"] = str(group) if group is not None else None
    return (
        (
            "antivirus_observations",
            {
                "id": stable_id("antivirus-observation", receipt_id),
                "provider_device_id": provider_device_id,
                "receipt_id": receipt_id,
                **observation,
            },
        ),
    )
