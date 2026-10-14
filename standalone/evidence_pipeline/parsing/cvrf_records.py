"""Receipt-scoped CVRF update relationships with no device applicability inference."""

from collections import defaultdict
from dataclasses import dataclass, fields as dataclass_fields
from decimal import Decimal
import json

from standalone.evidence_pipeline.parsing.csaf_records import RowReference
from standalone.evidence_pipeline.parsing.cvrf_updates import CvrfUpdates
from standalone.evidence_pipeline.parsing.cvrf_identity import native_identity
from standalone.evidence_pipeline.parsing.cvrf_variants import variants
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_records import canonical, CveIdentity
from standalone.evidence_pipeline.text_bytes import utf8_sha256


@dataclass(frozen=True)
class UpdateRecord(CveIdentity):
    cve_id: str | None
    claim: str
    content_hash: str
    rows: tuple

    def evidence_rows(self, receipt_id):
        # Reuse identities already derived in this receipt, never persisted rows
        # or verification results. The cache dies with this one record iterator.
        patch_ids = {}
        for index, (table, fields) in enumerate(self.rows):
            values = dict(fields)
            for key, value in values.items():
                if isinstance(value, RowReference):
                    if (
                        type(value.index) is not int
                        or not 0 <= value.index < index
                        or self.rows[value.index][0] != "patches"
                    ):
                        raise ValueError("Invalid CVRF patch relationship")
                    values[key] = patch_ids[value.index]
                elif key == "product_names":
                    values[key] = list(value)
            values.update(
                id=stable_id("public-observation", receipt_id, table, str(index)),
                receipt_id=receipt_id,
            )
            if table == "patches":
                patch_ids[index] = values["id"]
            yield table, values


@dataclass(frozen=True)
class AdvisoryUpdateRecord(UpdateRecord):
    native_id: str

    @property
    def source_record_id(self):
        return self.native_id

    @property
    def cve_ids(self):
        return ()


def normalize_cvrf_updates(feed):
    if not isinstance(feed, CvrfUpdates):
        raise ValueError("A parsed CVRF update feed is required")
    root = json.loads(feed.raw_payload, parse_float=Decimal)
    yield from normalize_cvrf_document(root, feed.records)


def normalize_cvrf_document(root, records):
    raw_groups = {
        identity: (common, originals)
        for identity, common, originals in variants(root.get("Vulnerability", []))
    }
    raw_cves = {identity: group[0] for identity, group in raw_groups.items()}
    grouped = defaultdict(list)
    for record in records:
        grouped[record.source_record_id].append(record)
    for cve in sorted(raw_cves):
        # A publisher record with no structured fix is still evidence, not an
        # absent CVE. Preserve the full claim without inventing patch rows.
        records = grouped[cve]
        _, actual_cve = native_identity(cve)
        rows, patches, applicability, replacements, vulnerability_links = (
            [],
            {},
            set(),
            set(),
            set(),
        )

        def add(table, **values):
            ref = RowReference(len(rows))
            rows.append((table, tuple(values.items())))
            return ref

        def patch(record, reference):
            key = (record.product_id, reference)
            if key not in patches:
                patches[key] = add(
                    "patches",
                    source_patch_id=reference,
                    source_product_id=record.product_id,
                    title=reference,
                    url=None,
                    published_at=None,
                    product_names=(record.product_name,),
                )
            return patches[key]

        for record in records:
            if record.patch_kb is None:
                continue
            fix = patch(record, record.patch_kb)
            key = (record.product_id, record.patch_kb)
            if actual_cve is not None and key not in vulnerability_links:
                add("patch_vulnerabilities", patch_id=fix, cve_id=cve)
                vulnerability_links.add(key)
            if key not in applicability:
                # Explicit product targeting is retained. FixedBuild does not
                # establish a generic vulnerable-version range or device match.
                add(
                    "patch_applicability",
                    patch_id=fix,
                    software_product=record.product_name,
                    publisher=None,
                    platform=None,
                    version_expression=None,
                    architecture=None,
                )
                applicability.add(key)
            if record.superseded_kb is not None:
                old = patch(record, record.superseded_kb)
                relation = (record.product_id, record.patch_kb, record.superseded_kb)
                if relation not in replacements:
                    add("patch_replacements", patch_id=fix, superseded_patch_id=old)
                    replacements.add(relation)
        source_document = {
            key: value
            for key, value in root.items()
            if key not in ("Vulnerability", "ProductTree")
        }
        # Preserve each product's exact publisher definition; unrelated products
        # do not multiply the size of every individual CVE receipt.
        # Status/remediation references can include products without a Type2 fix.
        referenced = {
            p
            for entry in raw_cves[cve].get("ProductStatuses", [])
            for p in entry.get("ProductID", [])
        }
        referenced.update(
            p
            for entry in raw_cves[cve].get("Remediations", [])
            for p in entry.get("ProductID", [])
        )
        source_document["ProductTree"] = {
            "FullProductName": [
                item
                for item in root["ProductTree"]["FullProductName"]
                if item["ProductID"] in referenced
            ]
        }
        claim = update_claim(
            cve, records, rows, source_document, raw_cves[cve], raw_groups[cve][1]
        )
        if actual_cve is None:
            yield AdvisoryUpdateRecord(
                None, claim, utf8_sha256(claim), tuple(rows), cve
            )
        else:
            yield UpdateRecord(cve, claim, utf8_sha256(claim), tuple(rows))


def update_claim(
    cve, records, rows, source_document, source_vulnerability, source_variants=None
):
    """Keep canonical v1 bytes without copying every update and projection first.

    The final claim remains a string for the existing persistence contract. This
    removes intermediate deep copies; it does not bound a single claim's memory.
    Keys below follow canonical's sorted order and are checked against the legacy
    complete-object encoding by regression tests.
    """

    _, actual_cve = native_identity(cve)

    def parts():
        adapter = (
            "msrc-cvrf-updates-v1"
            if actual_cve is not None
            else "msrc-cvrf-advisory-v1"
        )
        yield '{"adapter":' + canonical(adapter) + ',"projection":['
        for index, (table, values) in enumerate(rows):
            if index:
                yield ","
            yield canonical(
                (
                    table,
                    [
                        (
                            key,
                            {"row_reference": value.index}
                            if isinstance(value, RowReference)
                            else value,
                        )
                        for key, value in values
                    ],
                )
            )
        yield (
            '],"record":{'
            + canonical("cve_id" if actual_cve is not None else "native_id")
            + ":"
        )
        yield canonical(cve)
        yield ',"updates":['
        for index, record in enumerate(records):
            if index:
                yield ","
            # No mutation occurs during serialization. Nested source values can
            # be encoded directly without dataclasses.asdict's recursive copy.
            yield canonical(
                {
                    field.name: getattr(record, field.name)
                    for field in dataclass_fields(record)
                }
            )
        yield ']},"source_document":'
        yield canonical(source_document)
        if source_variants is not None:
            yield ',"source_variants":'
            yield canonical(source_variants)
        yield ',"source_vulnerability":'
        yield canonical(source_vulnerability)
        yield "}"

    return "".join(parts())
