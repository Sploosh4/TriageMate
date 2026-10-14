"""CVE record/contributor projections without collapsing publisher ownership.

JSON fields retain exact source numbers. The claim also retains the full source
document, including extensions outside the contributor containers, for independent
reconstruction. These projections require their explicit storage migration.
"""

import hashlib

from standalone.evidence_pipeline.source_json import encode_source_text

from standalone.evidence_pipeline.parsing.cve_program import CveProgramFeed
from standalone.evidence_pipeline.parsing.public_inputs import _json
from standalone.evidence_pipeline.parsing.public_records import PublicRecord, canonical


def source_json(value):
    return encode_source_text(value, sort_keys=True)


def normalize_cve_record(feed):
    if not isinstance(feed, CveProgramFeed):
        raise ValueError("A parsed CVE record is required")
    raw = _json(feed.raw_payload.decode("utf-8-sig"))
    for record in feed.records:
        rows = [
            (
                "cve_record_observations",
                dict(
                    record_state=record.state,
                    data_version=record.data_version,
                    source_metadata=source_json(record.metadata),
                ),
            )
        ]
        for contribution in record.contributions:
            rows.append(
                (
                    "cve_contributions",
                    dict(
                        contributor_kind=contribution.kind,
                        contributor_index=contribution.index,
                        organization_id=contribution.organization_id,
                        provider_name=contribution.provider_name,
                        source_fields=source_json(contribution.raw),
                    ),
                )
            )
        claim = canonical(
            dict(
                adapter="cve-record-v1",
                cve_id=record.cve_id,
                source_document=source_json(raw),
                projection=rows,
            )
        )
        yield PublicRecord(
            record.cve_id,
            claim,
            hashlib.sha256(claim.encode()).hexdigest(),
            tuple((table, tuple(fields.items())) for table, fields in rows),
        )
