"""Source-preserving projections for exploit metadata and ATT&CK references."""

from dataclasses import dataclass
from standalone.evidence_pipeline.text_bytes import utf8_sha256

from standalone.evidence_pipeline.parsing.advisory_feeds import AdvisoryFeed
from standalone.evidence_pipeline.parsing.redhat_advisories import RedHatFeed
from standalone.evidence_pipeline.parsing.attack_definitions import AttackFeed
from standalone.evidence_pipeline.parsing.ctid_mappings import CtidFeed
from standalone.evidence_pipeline.parsing.exploit_db import ExploitFeed
from standalone.evidence_pipeline.parsing.cve_records import source_json
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_records import canonical


@dataclass(frozen=True)
class ReferenceRecord:
    source_record_id: str
    cve_ids: tuple[str, ...]
    reference_kind: str
    source_fields: str
    claim: str
    content_hash: str

    def evidence_rows(self, receipt_id):
        yield (
            "public_reference_observations",
            dict(
                id=stable_id("public-reference-observation", receipt_id),
                receipt_id=receipt_id,
                native_id=self.source_record_id,
                reference_kind=self.reference_kind,
                cve_ids=list(self.cve_ids),
                source_fields=self.source_fields,
            ),
        )


def normalize_references(feed):
    if isinstance(feed, RedHatFeed):
        encoded = source_json(
            dict(
                document=feed.source_document,
                products=list(feed.product_definitions),
                relationships=list(feed.product_relationships),
            )
        )
        cves = tuple(record.cve_id for record in feed.records)
        claim = canonical(
            dict(
                adapter="public-reference-v1",
                native_id=feed.advisory_id,
                reference_kind="vendor_csaf",
                cve_ids=cves,
                source_fields=encoded,
            )
        )
        yield ReferenceRecord(
            feed.advisory_id,
            cves,
            "vendor_csaf",
            encoded,
            claim,
            utf8_sha256(claim),
        )
        return
    if not isinstance(feed, (ExploitFeed, CtidFeed, AttackFeed, AdvisoryFeed)):
        raise ValueError("Parsed public reference feed required")
    for record in feed.records:
        if isinstance(feed, AdvisoryFeed):
            kind = "vendor_advisory_data"
            fields = record.fields
        elif isinstance(feed, ExploitFeed):
            kind = "exploit_metadata"
            fields = dict(
                raw_rows=record.raw_rows,
                verified=record.verified,
                reference_url=record.reference_url,
            )
        elif isinstance(feed, CtidFeed):
            kind = "cve_attack_mapping"
            fields = dict(
                raw_rows=record.raw_rows,
                mappings=record.mappings,
                unresolved_mappings=record.unresolved_mappings,
            )
        else:
            kind = "attack_definition"
            fields = dict(
                object=record.raw,
                collection_metadata=feed.metadata,
                technique_ids=record.technique_ids,
            )
        encoded = source_json(fields)
        claim = canonical(
            dict(
                adapter="public-reference-v1",
                native_id=record.source_record_id,
                reference_kind=kind,
                cve_ids=record.cve_ids,
                source_fields=encoded,
            )
        )
        yield ReferenceRecord(
            record.source_record_id,
            record.cve_ids,
            kind,
            encoded,
            claim,
            utf8_sha256(claim),
        )
