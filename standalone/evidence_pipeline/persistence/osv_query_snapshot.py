"""Reconstruct query evidence from its manifest and wire before persistence."""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib

from standalone.evidence_pipeline.contracts import Snapshot, utc
from standalone.evidence_pipeline.parsing.cve_records import source_json
from standalone.evidence_pipeline.parsing.osv import OsvFeed
from standalone.evidence_pipeline.parsing.osv_query import (
    MAX_PAGES,
    URL,
    parse_pages,
    query_bytes,
    validate_scope,
)
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.contracts import PublicDownload


@dataclass(frozen=True)
class QuerySnapshot(PublicSnapshot):
    responses: tuple[PublicDownload, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        if not self.complete:
            self.reconstruct()

    def reconstruct(self):
        validate_scope(self.scope, synthetic=True)
        documents = Snapshot.records(self)
        if len(documents) != 1:
            raise ValueError("Query attempt requires one manifest")
        m = documents[0]
        if (
            m.get("format") != "triagemate-osv-query-v1"
            or m.get("scope") != asdict(self.scope)
            or m.get("execution_id") != self.execution_id
            or utc(datetime.fromisoformat(m["started_at"])) != self.started_at
            or utc(datetime.fromisoformat(m["finished_at"])) != self.finished_at
            or m.get("error_code") != self.error_code
            or self.complete != (self.error_code is None)
        ):
            raise ValueError("Query manifest disagrees with its attempt")
        query_bytes(m["query"])
        if (
            not isinstance(self.responses, tuple)
            or not isinstance(m.get("pages"), list)
            or len(m["pages"]) != len(self.responses)
            or len(self.responses) > MAX_PAGES
        ):
            raise ValueError("Query manifest page list differs")

        previous = self.started_at
        for metadata, response in zip(m["pages"], self.responses):
            if (
                not isinstance(metadata, dict)
                or not isinstance(response, PublicDownload)
                or response.url != URL
                or not isinstance(response.wire, bytes)
                or response.wire != response.payload
                or hashlib.sha256(response.wire).hexdigest()
                != metadata.get("fingerprint")
                or utc(datetime.fromisoformat(metadata["started_at"]))
                != utc(response.started_at)
                or utc(datetime.fromisoformat(metadata["finished_at"]))
                != utc(response.finished_at)
                or response.started_at < previous
                or response.finished_at < response.started_at
                or response.finished_at > self.finished_at
            ):
                raise ValueError("Query response differs from its manifest")

            previous = response.finished_at
        return (
            parse_pages(scope=self.scope, query=m["query"], responses=self.responses)
            if self.complete
            else None
        )

    def feed(self):
        result = self.reconstruct()
        if result is None:
            raise ValueError("Failed query has no complete advisory feed")
        records = {}
        for page in result.pages:
            for record in page.records:
                existing = records.get(record.advisory_id)
                if existing is not None and source_json(existing.raw) != source_json(
                    record.raw
                ):
                    raise ValueError(
                        "OSV query contains conflicting revisions of one advisory"
                    )
                records[record.advisory_id] = record
        return OsvFeed(self.scope, self.payload, tuple(records.values()))


def from_collection(collection):
    value = collection.snapshot
    result = QuerySnapshot(
        value.scope,
        value.execution_id,
        value.started_at,
        value.finished_at,
        value.outcome,
        value.complete,
        value.payload,
        value.error_code,
        collection.responses,
    )
    return result
