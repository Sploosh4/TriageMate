"""Explain source-status rows by their immutable revision fingerprints."""

from dataclasses import replace

from standalone.evidence_pipeline.parsing.update_status import (
    MissingPatch,
    UpdatePolicyStatus,
)
from standalone.evidence_pipeline.parsing.update_records import (
    content,
    rows,
    source_record_id,
)
from standalone.evidence_pipeline.parsing.devices import timestamp


def verify_updates(
    extras, sources, revisions, receipts, attempts, providers, explained, verify_receipt
):
    from standalone.evidence_pipeline.persistence.attribution import require, digest

    # This verifier needs only device-reported missing patches. Public MSRC
    # patches are reconstructed by their own verifier; loading all of them here
    # materializes millions of unrelated rows without adding an integrity check.
    needed_patches = {row["patch_id"] for row in extras["device_missing_patches"]}
    patches = {
        row["id"]: row for row in extras["patches"] if row["id"] in needed_patches
    }
    for table, expected_kind in [
        ("device_missing_patches", "missing_patches"),
        ("update_policy_observations", "update_status"),
    ]:
        for observation in extras[table]:
            received = receipts.get(observation["receipt_id"])
            if received is None:
                continue
            revision = revisions[received["source_revision_id"]]
            source = sources[revision["connection_id"]]
            require(
                source["input_kind"] == expected_kind,
                "Update observation has the wrong source kind",
            )
            provider = providers.get(observation["provider_device_id"])
            require(
                provider is not None, "Update observation has an unexplained device"
            )
            if table == "device_missing_patches":
                patch = patches.get(observation["patch_id"])
                require(
                    patch is not None
                    and patch["receipt_id"] == observation["receipt_id"],
                    "Missing patch source receipt differs",
                )
                labels = patch["product_names"]
                item = MissingPatch(
                    provider["native_device_id"],
                    patch["source_patch_id"],
                    patch["title"],
                    tuple(labels) if labels is not None else None,
                    patch["url"],
                    observation["reported_machine_count"],
                    observation["reported_cve_count"],
                )
                # Source-ID display fallback must reproduce a source-null fingerprint.
                if (
                    digest(content(item)) != revision["content_hash"]
                    and patch["title"] == patch["source_patch_id"]
                ):
                    item = replace(item, title=None)
            else:
                observation = dict(observation)
                # PostgreSQL JSON trims fractional zeros; reproduce the adapter's
                # canonical timestamp text before checking its content hash.
                for field in ("event_time", "last_wu_scan_at"):
                    observation[field] = timestamp(observation[field], field)
                fields = tuple(
                    sorted(
                        (key, value)
                        for key, value in observation.items()
                        if key not in {"id", "provider_device_id", "receipt_id"}
                    )
                )
                item = UpdatePolicyStatus(
                    provider["native_device_id"], observation["policy_id"], fields
                )
            verify_receipt(
                observation["receipt_id"],
                source_record_id(item),
                digest(content(item)),
                "exposure",
            )
            projected = rows(
                item,
                observation["receipt_id"],
                provider["id"],
                attempts[received["collection_attempt_id"]]["finished_at"],
            )
            for target, expected in projected:
                actual = patches[expected["id"]] if target == "patches" else observation
                if target == "patches" and "source_product_id" in actual:
                    # v17 adds explicit CVRF product IDs. Legacy missing-KB
                    # evidence has no such identifier; only NULL is attributable.
                    expected = {**expected, "source_product_id": None}
                require(actual == expected, "Update observation projection changed")
                explained[target].add(expected["id"])
