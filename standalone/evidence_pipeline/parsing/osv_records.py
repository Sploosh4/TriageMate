"""Native OSV advisory projections; CVE aliases never replace advisory identity."""

from dataclasses import dataclass
import hashlib

from standalone.evidence_pipeline.parsing.cve_records import source_json
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.osv import OsvFeed
from standalone.evidence_pipeline.parsing.public_records import canonical


@dataclass(frozen=True)
class OsvPublicRecord:
    source_record_id: str
    cve_ids: tuple[str, ...]
    claim: str
    content_hash: str
    rows: tuple

    def evidence_rows(self, receipt_id):
        for index, (table, fields) in enumerate(self.rows):
            values = dict(fields)
            values.update(
                id=stable_id("public-observation", receipt_id, table, str(index)),
                receipt_id=receipt_id,
                advisory_id=self.source_record_id,
            )
            yield table, values


def normalize_osv(feed):
    if not isinstance(feed, OsvFeed):
        raise ValueError("A parsed OSV feed is required")
    for record in feed.records:
        rows = [
            (
                "osv_advisory_observations",
                dict(
                    modified_text=record.modified,
                    withdrawn_text=record.withdrawn,
                    source_fields=source_json(record.raw),
                ),
            )
        ]
        for index, alias in enumerate(record.aliases):
            rows.append(("osv_aliases", dict(alias_index=index, alias_id=alias)))
        for index, affected in enumerate(record.raw.get("affected") or []):
            package = affected.get("package", {})
            rows.append(
                (
                    "osv_affected_packages",
                    dict(
                        package_index=index,
                        package_name=package.get("name"),
                        ecosystem=package.get("ecosystem"),
                        purl=package.get("purl"),
                        source_fields=source_json(affected),
                    ),
                )
            )
        claim = canonical(
            dict(
                adapter="osv-record-v1",
                advisory_id=record.advisory_id,
                source_document=source_json(record.raw),
                projection=rows,
            )
        )
        yield OsvPublicRecord(
            record.advisory_id,
            record.cve_ids,
            claim,
            hashlib.sha256(claim.encode()).hexdigest(),
            tuple((table, tuple(fields.items())) for table, fields in rows),
        )
