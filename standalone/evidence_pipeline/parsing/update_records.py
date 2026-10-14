"""Receipt-bound rows for missing-patch and policy observations.

These recipes do not execute SQL or infer remediation, applicability or CVEs.
The writer must first establish the source scope and pinned device snapshot.
"""

from dataclasses import asdict
import json

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.update_status import (
    MissingPatch,
    UpdatePolicyStatus,
)


def source_record_id(item):
    if isinstance(item, MissingPatch):
        parts = ["missing-patch", item.native_device_id, item.source_patch_id]
    elif isinstance(item, UpdatePolicyStatus):
        parts = ["update-policy", item.native_device_id, item.policy_id]
    else:
        raise ValueError("Unsupported update observation")
    return json.dumps(parts, ensure_ascii=False, separators=(",", ":"))


def content(item):
    source_record_id(item)  # Reject unsupported record types before projection.
    return asdict(item)


def rows(item, receipt_id, provider_device_id, observed_at):
    """Project validated records using caller-proven receipt and provider keys."""
    source_record_id(item)
    receipt_id = identifier(receipt_id)
    provider_device_id = identifier(provider_device_id)
    if isinstance(item, MissingPatch):
        patch_id = stable_id("missing-patch", receipt_id)
        return (
            (
                "patches",
                {
                    "id": patch_id,
                    "source_patch_id": item.source_patch_id,
                    "receipt_id": receipt_id,
                    # The source ID is a display fallback, not a fabricated title.
                    "title": item.title
                    if item.title is not None
                    else item.source_patch_id,
                    "url": item.url,
                    "published_at": None,
                    "product_names": list(item.product_labels)
                    if item.product_labels is not None
                    else None,
                },
            ),
            (
                "device_missing_patches",
                {
                    "id": stable_id("device-missing-patch", receipt_id),
                    "provider_device_id": provider_device_id,
                    "patch_id": patch_id,
                    "receipt_id": receipt_id,
                    "observed_at": observed_at,
                    "reported_machine_count": item.reported_machine_count,
                    "reported_cve_count": item.reported_cve_count,
                },
            ),
        )
    return (
        (
            "update_policy_observations",
            {
                "id": stable_id("update-policy-observation", receipt_id),
                "provider_device_id": provider_device_id,
                "receipt_id": receipt_id,
                **item.observation(),
            },
        ),
    )
