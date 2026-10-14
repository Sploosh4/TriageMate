"""Relational CSAF projection recipes with receipt-bound foreign keys.

No database writes. Product names are publisher labels, not applicability matches.
"""

from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
from decimal import Decimal

from standalone.evidence_pipeline.parsing.csaf import CsafFeed
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_records import canonical, CveIdentity

ID_TABLES = {"advisories", "recommendations", "patches", "patch_vulnerabilities"}


@dataclass(frozen=True)
class RowReference:
    index: int


@dataclass(frozen=True)
class AdvisoryRecord(CveIdentity):
    cve_id: str
    claim: str
    content_hash: str
    rows: tuple

    def evidence_rows(self, receipt_id):
        for index, (table, fields) in enumerate(self.rows):
            values = {}
            for key, value in fields:
                if isinstance(value, RowReference):
                    target = value.index
                    if type(target) is not int or not 0 <= target < index:
                        raise ValueError("Invalid advisory projection relationship")
                    target_table = self.rows[target][0]
                    if target_table not in ID_TABLES:
                        raise ValueError("Invalid advisory projection relationship")
                    value = stable_id(
                        "public-observation", receipt_id, target_table, str(target)
                    )
                values[key] = list(value) if key == "product_names" else value
            values["receipt_id"] = receipt_id
            if table in ID_TABLES:
                values["id"] = stable_id(
                    "public-observation", receipt_id, table, str(index)
                )
            yield table, values


def normalize_csaf(feed):
    if not isinstance(feed, CsafFeed):
        raise ValueError("A parsed CSAF feed is required")
    raw = json.loads(feed.raw_payload, parse_float=Decimal)
    raw_records = {record["cve"]: record for record in raw.get("vulnerabilities", [])}
    names = {product.product_id: product.name for product in feed.products}
    for record in feed.records:
        rows = []

        def add(table, **values):
            index = len(rows)
            rows.append((table, tuple(values.items())))
            return RowReference(index)

        advisory = add(
            "advisories",
            source_advisory_id=feed.advisory_id,
            title=feed.title,
            publisher=feed.publisher,
            url=feed.scope.scope_reference,
            published_at=feed.published_at,
            updated_at=feed.updated_at,
            content_or_reference=canonical(
                {
                    "document": raw["document"],
                    "vulnerability": raw_records[record.cve_id],
                }
            ),
        )
        add("advisory_cves", advisory_id=advisory, cve_id=record.cve_id)
        by_kb = defaultdict(list)
        for remedy in record.remediations:
            if remedy.patch_id:
                by_kb[remedy.patch_id].append(remedy)
        patches = {}
        for kb, remedies in sorted(by_kb.items()):
            urls = {r.url for r in remedies}
            dates = {r.date for r in remedies}
            patches[kb] = add(
                "patches",
                source_patch_id=kb,
                title=kb,
                url=next(iter(urls)) if len(urls) == 1 else None,
                published_at=next(iter(dates)) if len(dates) == 1 else None,
                product_names=tuple(
                    sorted({names[p] for r in remedies for p in r.product_ids})
                ),
            )
            add("patch_vulnerabilities", patch_id=patches[kb], cve_id=record.cve_id)
        for index, remedy in enumerate(record.remediations):
            for product in remedy.product_ids:
                recommendation = add(
                    "recommendations",
                    source_recommendation_id=f"{record.cve_id}/remediations/{index}/products/{product}",
                    advisory_id=advisory,
                    title=remedy.category,
                    recommendation_text=remedy.details,
                    product_name=names[product],
                    category=remedy.category,
                    remediation_type=remedy.category,
                )
                add(
                    "recommendation_cves",
                    recommendation_id=recommendation,
                    cve_id=record.cve_id,
                )
                if remedy.patch_id:
                    add(
                        "recommendation_patches",
                        recommendation_id=recommendation,
                        patch_id=patches[remedy.patch_id],
                    )
        claim = canonical(
            {
                "adapter": "msrc-csaf-v1",
                "record": asdict(record),
                "source_document": {
                    key: value for key, value in raw.items() if key != "vulnerabilities"
                },
                "source_vulnerability": raw_records[record.cve_id],
                "projection": [
                    (
                        table,
                        [
                            (
                                key,
                                {"row_reference": value.index}
                                if isinstance(value, RowReference)
                                else value,
                            )
                            for key, value in fields
                        ],
                    )
                    for table, fields in rows
                ],
            }
        )
        yield AdvisoryRecord(
            record.cve_id,
            claim,
            hashlib.sha256(claim.encode()).hexdigest(),
            tuple(rows),
        )
