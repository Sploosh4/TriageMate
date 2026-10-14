"""Check persisted antivirus observations against their source fingerprints."""

from standalone.evidence_pipeline.parsing.antivirus import AntivirusHealth, TIME_FIELDS
from standalone.evidence_pipeline.parsing.antivirus_records import (
    content,
    rows,
    source_record_id,
)
from standalone.evidence_pipeline.parsing.devices import timestamp


def verify_antivirus(
    extras, sources, revisions, receipts, attempts, providers, explained, verify_receipt
):
    from standalone.evidence_pipeline.persistence.attribution import require, digest

    for original in extras["antivirus_observations"]:
        received = receipts.get(original["receipt_id"])
        if received is None:
            continue
        revision = revisions[received["source_revision_id"]]
        source = sources[revision["connection_id"]]
        require(
            (source["source_name"], source["input_kind"]) == ("Defender", "antivirus"),
            "Antivirus observation has the wrong source",
        )
        provider = providers.get(original["provider_device_id"])
        require(provider is not None, "Antivirus observation has an unexplained device")
        observation = dict(original)
        for field in TIME_FIELDS:
            observation[field] = timestamp(observation[field], field)
        fields = {
            key: value
            for key, value in observation.items()
            if key not in {"id", "provider_device_id", "receipt_id"}
        }
        group = fields["source_rbac_group_id"]
        if group is not None:
            require(
                isinstance(group, str) and group.isascii() and group.isdecimal(),
                "Antivirus group ID changed",
            )
            fields["source_rbac_group_id"] = int(group)
        item = AntivirusHealth(
            fields["source_record_id"],
            provider["native_device_id"],
            tuple(sorted(fields.items())),
        )
        verify_receipt(
            original["receipt_id"],
            source_record_id(item),
            digest(content(item)),
            "exposure",
        )
        ((table, expected),) = rows(
            item,
            original["receipt_id"],
            provider["id"],
            attempts[received["collection_attempt_id"]]["finished_at"],
        )
        require(observation == expected, "Antivirus observation projection changed")
        explained[table].add(expected["id"])
