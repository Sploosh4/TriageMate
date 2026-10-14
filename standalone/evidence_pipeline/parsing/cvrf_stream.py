"""File-backed CVRF validation and normalization, one vulnerability at a time."""

from dataclasses import dataclass
from io import BytesIO

from standalone.evidence_pipeline.temporary_index import temporary_index
from standalone.evidence_pipeline.verification_spool import VerificationSpool

from standalone.evidence_pipeline.parsing.cvrf_updates import (
    _document_products,
    _parse_product_records,
    validate_scope,
)
from standalone.evidence_pipeline.parsing.cvrf_identity import native_identity
from standalone.evidence_pipeline.file_payload import FilePayload
from standalone.evidence_pipeline.json_stream import document_array
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    MAX_PUBLIC_RECORDS,
)


def document_metadata(payload):
    if not isinstance(payload, (FilePayload, bytes)):
        raise ValueError("CVRF metadata requires source bytes or a verified file")
    # Product definitions can legally follow the vulnerability array. A first
    # pass validates the entire JSON and retains only document-level metadata.
    metadata = {}
    with (
        payload.open() if isinstance(payload, FilePayload) else BytesIO(payload)
    ) as stream:
        for kind, name, value in document_array(
            stream, "Vulnerability", materialize_items=False, required=False
        ):
            if kind == "member":
                metadata[name] = value
    return metadata


def documents(payload, scope):
    validate_scope(scope)
    if not isinstance(payload, FilePayload):
        raise ValueError("Streamed CVRF requires a verified file payload")
    # Stage parsed values in private disposable storage: metadata can appear
    # after Vulnerability, but the source need only be tokenized once. The spool
    # serializes our validated Python values, never accepts external pickle data.
    metadata = {}
    array_present = False
    with VerificationSpool() as spool, temporary_index() as seen:
        seen.execute(
            "CREATE TABLE cves (identity TEXT NOT NULL, position INTEGER PRIMARY KEY)"
        )
        seen.execute("CREATE INDEX cve_identity ON cves(identity)")
        with payload.open() as stream:

            def values():
                nonlocal array_present
                position = 0
                for kind, name, value in document_array(
                    stream, "Vulnerability", required=False
                ):
                    if kind == "member":
                        metadata[name] = value
                    elif kind == "array":
                        array_present = True
                    elif kind == "item":
                        identity, _ = native_identity(
                            value.get("CVE") if isinstance(value, dict) else None
                        )
                        seen.execute(
                            "INSERT INTO cves VALUES (?,?)", (identity, position)
                        )
                        position += 1
                        yield value

            staged = spool.rows(values())
        # Full JSON structure and the payload fingerprint have validated before
        # any record is yielded. Product/reference and cycle checks still run.
        products = _document_products(
            dict(metadata, Vulnerability=[]) if array_present else metadata,
            scope=scope,
        )
        total = 0
        for (identity,) in seen.execute(
            "SELECT identity FROM cves GROUP BY identity ORDER BY min(position)"
        ):
            entries = [
                staged[position]
                for (position,) in seen.execute(
                    "SELECT position FROM cves WHERE identity=? ORDER BY position",
                    (identity,),
                )
            ]
            document = dict(metadata, Vulnerability=entries)
            records = _parse_product_records(document, products)
            total += len(records)
            if total > MAX_PUBLIC_RECORDS:
                raise ValueError("CVRF normalized relationship bound exceeded")
            yield document, records


@dataclass(frozen=True)
class StreamedCvrfUpdates(PublicFeed):
    @property
    def records(self):
        for _, records in documents(self.raw_payload, self.scope):
            yield from records


def normalize_streamed_cvrf(feed):
    from standalone.evidence_pipeline.parsing.cvrf_records import (
        normalize_cvrf_document,
    )

    for document, records in documents(feed.raw_payload, feed.scope):
        yield from normalize_cvrf_document(document, records)
