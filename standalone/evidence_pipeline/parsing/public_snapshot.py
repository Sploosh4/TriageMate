"""Public full-response attempts using the common immutable collection contract."""

from standalone.evidence_pipeline.contracts import Snapshot, SourceScope
from standalone.evidence_pipeline.file_payload import FilePayload
from standalone.evidence_pipeline.parsing.public_inputs import (
    parse_epss_csv,
    parse_kev_json,
    parse_nvd_json,
)

from standalone.evidence_pipeline.parsing.csaf import parse_csaf
from standalone.evidence_pipeline.parsing.cvrf_updates import parse_cvrf_updates
from standalone.evidence_pipeline.parsing.cve_program import parse_cve_record
from standalone.evidence_pipeline.parsing.osv import parse_osv
from standalone.evidence_pipeline.parsing.github_advisories import parse_github_advisory

from standalone.evidence_pipeline.parsing.attack_definitions import parse_attack
from standalone.evidence_pipeline.parsing.ctid_mappings import parse_ctid
from standalone.evidence_pipeline.parsing.exploit_db import parse_exploit_db

from standalone.evidence_pipeline.parsing.ubuntu_advisories import parse_ubuntu

from standalone.evidence_pipeline.parsing.redhat_advisories import parse_redhat

from standalone.evidence_pipeline.parsing.advisory_feeds import (
    SOURCES as ADVISORY_SOURCES,
    parse_advisory,
    validate_scope,
)

PARSERS = {
    **dict.fromkeys(ADVISORY_SOURCES, parse_advisory),
    ("Red Hat", "advisories"): parse_redhat,
    ("Ubuntu", "advisories"): parse_ubuntu,
    ("MITRE ATT&CK", "enterprise_definitions"): parse_attack,
    ("CTID", "cve_mappings"): parse_ctid,
    ("Exploit-DB", "metadata"): parse_exploit_db,
    ("GitHub", "advisories"): parse_github_advisory,
    ("OSV", "advisories"): parse_osv,
    ("CVE", "records"): parse_cve_record,
    ("CISA", "vulnrichment"): parse_cve_record,
    ("MSRC", "advisories"): parse_csaf,
    ("MSRC", "security_updates"): parse_cvrf_updates,
    ("FIRST", "epss"): parse_epss_csv,
    ("CISA", "kev"): parse_kev_json,
    ("NVD", "vulnerabilities"): parse_nvd_json,
}


class PublicSnapshot(Snapshot):
    """Payload is the decoded source wire, not a re-serialized record array.

    NVD completeness applies to the configured query, not to all known CVEs.
    Transport compressed-byte provenance must remain separate from this hash.
    Failure attempts can retain the fingerprint of an invalid bounded response.
    """

    def __post_init__(self):
        if (
            not isinstance(self.scope, SourceScope)
            or (self.scope.source, self.scope.input_kind) not in PARSERS
            or self.scope.tenant_id is not None
        ):
            raise ValueError("Public attempts require a supported non-tenant source")
        if self.scope.origin not in ("synthetic", "public"):
            raise ValueError("Public attempt origin must be synthetic or public")
        if (self.scope.source, self.scope.input_kind) in ADVISORY_SOURCES:
            validate_scope(self.scope)
        if isinstance(self.payload, FilePayload):
            if (self.scope.source, self.scope.input_kind) not in {
                ("Debian", "tracker"),
                ("MSRC", "security_updates"),
                ("FIRST", "epss"),
            }:
                raise ValueError("Source does not yet support streamed saved payloads")
            envelope = Snapshot(
                self.scope,
                self.execution_id,
                self.started_at,
                self.finished_at,
                self.outcome,
                self.complete,
                b"[]",
                self.error_code,
            )
            for name in ("execution_id", "started_at", "finished_at"):
                object.__setattr__(self, name, getattr(envelope, name))
            if self.complete:
                for _ in self.records():
                    pass
            else:
                self.payload.verify()
        else:
            super().__post_init__()

    @property
    def input_fingerprint(self):
        if isinstance(self.payload, FilePayload):
            return self.payload.fingerprint
        return super().input_fingerprint

    def verify_payload(self):
        if isinstance(self.payload, FilePayload):
            self.payload.verify()

    def feed(self):
        if not self.complete:
            raise ValueError("Failed collection has no complete public feed")
        if isinstance(self.payload, FilePayload):
            if self.scope.source == "FIRST":
                from standalone.evidence_pipeline.parsing.epss_stream import (
                    parse_epss_file,
                )

                return parse_epss_file(self.payload, scope=self.scope)
            if self.scope.source == "MSRC":
                from standalone.evidence_pipeline.parsing.cvrf_stream import (
                    StreamedCvrfUpdates,
                )

                return StreamedCvrfUpdates(self.scope, self.payload)
            from standalone.evidence_pipeline.parsing.debian_tracker import iter_debian
            from standalone.evidence_pipeline.parsing.advisory_feeds import (
                AdvisoryFeed,
                AdvisoryRecord,
            )

            def records():
                with self.payload.open() as stream:
                    for record in iter_debian(stream, scope=self.scope):
                        yield AdvisoryRecord(
                            record.source_record_id,
                            record.cve_ids,
                            dict(document={record.source_record_id: record.issues}),
                        )

            return AdvisoryFeed(self.scope, self.payload, records())
        return PARSERS[self.scope.source, self.scope.input_kind](
            self.payload, scope=self.scope
        )

    def records(self):
        return self.feed().records
