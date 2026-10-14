"""Map validated public feeds to the existing relational evidence vocabulary.

Each source record retains a complete structured claim alongside its projected
rows. Persistence must store that claim with its revision; projections alone do
not preserve languages, reference tags or supplemental publisher metrics.
"""

from dataclasses import asdict, dataclass
from datetime import date, datetime
from decimal import Decimal
import hashlib
import json

from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_inputs import (
    EpssFeed,
    KevFeed,
    NvdFeed,
)


def canonical(value):
    """Lossless deterministic source-claim serialization, never binary floats."""

    def encode(item):
        if isinstance(item, Decimal):
            return {"decimal": str(item)}
        if isinstance(item, (date, datetime)):
            return {"iso": item.isoformat()}
        raise TypeError("Unsupported claim value")

    return json.dumps(
        value, default=encode, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )


class CveIdentity:
    """Public record identity for formats whose source record is one CVE."""

    @property
    def source_record_id(self):
        return self.cve_id

    @property
    def cve_ids(self):
        return (self.cve_id,)


@dataclass(frozen=True)
class PublicRecord(CveIdentity):
    cve_id: str
    claim: str
    content_hash: str
    # Tuples prevent callers accidentally mutating a previously hashed row set.
    rows: tuple[tuple[str, tuple[tuple[str, object], ...]], ...]

    def evidence_rows(self, receipt_id):
        for index, (table, fields) in enumerate(self.rows):
            values = dict(fields)
            values.update(cve_id=self.cve_id, receipt_id=receipt_id)
            values["id"] = stable_id(
                "public-observation", receipt_id, table, str(index)
            )
            yield table, values


def normalize_public(feed):
    from standalone.evidence_pipeline.parsing.cvrf_stream import (
        StreamedCvrfUpdates,
        normalize_streamed_cvrf,
    )

    if isinstance(feed, StreamedCvrfUpdates):
        yield from normalize_streamed_cvrf(feed)
        return
    from standalone.evidence_pipeline.parsing.redhat_advisories import RedHatFeed
    from standalone.evidence_pipeline.parsing.advisory_feeds import AdvisoryFeed

    if isinstance(feed, (RedHatFeed, AdvisoryFeed)):
        from standalone.evidence_pipeline.parsing.reference_records import (
            normalize_references,
        )

        yield from normalize_references(feed)
        return

    """Yield independent facts; no preferred CVSS, negative KEV or patch inference.

    Feed validation is the parser's responsibility. A caller must not construct a
    feed manually from untrusted rows and treat this mapping as validation.
    """
    from standalone.evidence_pipeline.parsing.attack_definitions import AttackFeed
    from standalone.evidence_pipeline.parsing.ctid_mappings import CtidFeed
    from standalone.evidence_pipeline.parsing.exploit_db import ExploitFeed

    if isinstance(feed, (AttackFeed, CtidFeed, ExploitFeed)):
        from standalone.evidence_pipeline.parsing.reference_records import (
            normalize_references,
        )

        yield from normalize_references(feed)
        return
    from standalone.evidence_pipeline.parsing.osv import OsvFeed

    if isinstance(feed, OsvFeed):
        from standalone.evidence_pipeline.parsing.osv_records import normalize_osv

        yield from normalize_osv(feed)
        return
    from standalone.evidence_pipeline.parsing.cve_program import CveProgramFeed

    if isinstance(feed, CveProgramFeed):
        from standalone.evidence_pipeline.parsing.cve_records import (
            normalize_cve_record,
        )

        yield from normalize_cve_record(feed)
        return
    from standalone.evidence_pipeline.parsing.cvrf_updates import CvrfUpdates

    if isinstance(feed, CvrfUpdates):
        from standalone.evidence_pipeline.parsing.cvrf_records import (
            normalize_cvrf_updates,
        )

        yield from normalize_cvrf_updates(feed)
        return
    from standalone.evidence_pipeline.parsing.csaf import CsafFeed

    if isinstance(feed, CsafFeed):
        from standalone.evidence_pipeline.parsing.csaf_records import normalize_csaf

        yield from normalize_csaf(feed)
        return
    try:
        yield from _normalize_common(feed)
    finally:
        close = getattr(getattr(feed, "records", None), "close", None)
        if close is not None:
            close()


def _normalize_common(feed):
    if not isinstance(feed, (EpssFeed, KevFeed, NvdFeed)):
        raise ValueError("A parsed public feed is required")
    raw_records = {}
    if isinstance(feed, NvdFeed):
        document = json.loads(feed.raw_payload, parse_float=Decimal)
        raw_records = {
            item["cve"]["id"]: item["cve"] for item in document["vulnerabilities"]
        }
    elif isinstance(feed, KevFeed):
        document = json.loads(feed.raw_payload, parse_float=Decimal)
        raw_records = {item["cveID"]: item for item in document["vulnerabilities"]}
    for record in feed.records:
        rows = []
        claim = {"record": asdict(record)}
        if isinstance(feed, EpssFeed):
            claim.update(
                score_date=feed.score_date,
                model_version=feed.model_version,
                score_timestamp=feed.score_timestamp,
            )
            rows.append(
                (
                    "epss_observations",
                    dict(
                        probability=record.probability,
                        percentile=record.percentile,
                        score_date=feed.score_date,
                        model_version=feed.model_version,
                    ),
                )
            )
        elif isinstance(feed, KevFeed):
            claim.update(
                raw=raw_records[record.cve_id],
                catalog_version=feed.catalog_version,
                date_released=feed.date_released,
            )
            rows.append(
                (
                    "kev_observations",
                    dict(
                        membership=True,
                        date_added=record.date_added,
                        required_action=record.required_action,
                        source_due_date=record.due_date,
                    ),
                )
            )
            rows.append(
                (
                    "vulnerability_details",
                    dict(
                        title=record.vulnerability_name,
                        description=record.short_description,
                    ),
                )
            )
        else:
            claim["raw"] = raw_records[record.cve_id]
            for description in record.descriptions:
                rows.append(
                    (
                        "vulnerability_details",
                        dict(
                            description=description.value,
                            published_at=record.published,
                            updated_at=record.last_modified,
                        ),
                    )
                )
            for assessment in record.assessments:
                rows.append(
                    (
                        "cvss_observations",
                        dict(
                            publisher=assessment.source,
                            version=assessment.version,
                            score=assessment.score,
                            vector=assessment.vector,
                        ),
                    )
                )
            seen_urls = set()
            for reference in record.references:
                if reference.url in seen_urls:
                    continue
                seen_urls.add(reference.url)
                rows.append(
                    ("vulnerability_references", dict(url=reference.url, label=None))
                )
        claim["projection"] = rows
        serialized = canonical(claim)
        yield PublicRecord(
            record.cve_id,
            serialized,
            hashlib.sha256(serialized.encode()).hexdigest(),
            tuple((table, tuple(fields.items())) for table, fields in rows),
        )
