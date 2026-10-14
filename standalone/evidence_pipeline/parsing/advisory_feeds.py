"""Fixed vendor advisory routes with native source claims and attribution."""

from dataclasses import asdict, dataclass
from decimal import Decimal
import json

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.cve_records import source_json
from standalone.evidence_pipeline.parsing.debian_tracker import (
    parse_debian,
    URL as DEBIAN_URL,
)
from standalone.evidence_pipeline.parsing.httpd_advisories import (
    parse_httpd,
    BASE as HTTPD_BASE,
)
from standalone.evidence_pipeline.parsing.public_inputs import PublicFeed, CVE_PATTERN
from standalone.evidence_pipeline.parsing.samba_advisories import (
    parse_samba,
    BASE as SAMBA_BASE,
)
from standalone.evidence_pipeline.parsing.tomcat_advisories import (
    parse_tomcat,
    BASE as TOMCAT_BASE,
)
from standalone.evidence_pipeline.parsing.cisco_advisories import parse_cisco
from standalone.evidence_pipeline.parsing.cisco_discovery import (
    BASE as CISCO_BASE,
    advisory_file as cisco_file,
)

SOURCES = frozenset(
    {
        ("Debian", "tracker"),
        ("Apache HTTP Server", "advisories"),
        ("Apache Tomcat", "advisories"),
        ("Samba", "advisories"),
        ("Cisco", "advisories"),
        ("WA SOC", "advisories"),
        ("Palo Alto Networks", "advisories"),
        ("Microsoft Update Catalog", "updates"),
    }
)


@dataclass(frozen=True)
class AdvisoryRecord:
    source_record_id: str
    cve_ids: tuple[str, ...]
    fields: dict


@dataclass(frozen=True)
class AdvisoryFeed(PublicFeed):
    records: tuple[AdvisoryRecord, ...]


def validate_scope(scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) not in SOURCES
        or scope.origin not in {"synthetic", "public"}
        or scope.tenant_id is not None
    ):
        raise ValueError(
            "Vendor advisory requires an enabled public or synthetic non-tenant scope"
        )
    reference = scope.scope_reference
    if scope.source == "WA SOC":
        from standalone.evidence_pipeline.parsing.wasoc_advisories import (
            validate_scope as validate_wasoc_scope,
        )

        validate_wasoc_scope(scope)
        return
    if scope.source == "Microsoft Update Catalog":
        from standalone.evidence_pipeline.parsing.update_catalog import BASE, endpoint

        valid = reference.startswith(BASE) and reference == endpoint(
            reference[len(BASE) :]
        )
    elif scope.source == "Palo Alto Networks":
        base = "https://security.paloaltonetworks.com/json/"
        valid = reference.startswith(base) and bool(
            CVE_PATTERN.fullmatch(reference[len(base) :])
        )
    elif scope.source == "Cisco":
        if reference.startswith(CISCO_BASE) and scope.origin == "synthetic":
            cisco_file(reference[len(CISCO_BASE) :])
        else:
            from standalone.evidence_pipeline.parsing.cisco_rss import (
                validate_scope as validate_cisco_scope,
            )

            validate_cisco_scope(scope)
        valid = True
    elif scope.source == "Debian":
        valid = reference == DEBIAN_URL
    elif scope.source == "Apache Tomcat":
        valid = reference in {
            TOMCAT_BASE + f"security-{series}.xml" for series in (9, 10, 11)
        }
    else:
        base, suffix = (
            (HTTPD_BASE, ".json")
            if scope.source == "Apache HTTP Server"
            else (SAMBA_BASE, ".html")
        )
        native = reference.removeprefix(base).removesuffix(suffix)
        valid = (
            bool(CVE_PATTERN.fullmatch(native)) and reference == base + native + suffix
        )
    if not valid:
        raise ValueError("Unsupported vendor advisory source reference")


def parse_advisory(payload, *, scope):
    validate_scope(scope)
    if scope.source == "WA SOC":
        from standalone.evidence_pipeline.parsing.wasoc_advisories import (
            parse_wasoc,
            source_heading,
        )

        notice = parse_wasoc(payload, scope=scope)
        fields = asdict(notice)
        del fields["raw_payload"]
        _, heading_id = source_heading(payload)
        if heading_id != notice.advisory_id:
            fields["source_heading_advisory_id"] = heading_id
            fields["identity_status"] = (
                "unknown_heading_identity"
                if heading_id is None
                else "conflicting_heading_identity"
            )
        records = (
            AdvisoryRecord(
                notice.advisory_id,
                notice.referenced_cves,
                dict(wire_text=payload.decode("utf-8-sig"), notice=fields),
            ),
        )
    elif scope.source == "Microsoft Update Catalog":
        from standalone.evidence_pipeline.parsing.update_catalog import (
            BASE,
            parse_detail,
        )

        native = scope.scope_reference[len(BASE) :]
        notice = parse_detail(payload, identity=native)
        records = (
            AdvisoryRecord(
                native, (), dict(wire_text=payload.decode("utf-8-sig"), notice=notice)
            ),
        )
    elif scope.source == "Palo Alto Networks":
        from standalone.evidence_pipeline.parsing.cve_program import parse_cve_record

        feed = parse_cve_record(payload, scope=scope)
        document = json.loads(payload)
        native = document["cveMetadata"]["cveId"]
        if (
            scope.scope_reference
            != "https://security.paloaltonetworks.com/json/" + native
        ):
            raise ValueError(
                "Palo Alto advisory identity differs from requested record"
            )
        records = (AdvisoryRecord(native, (native,), dict(document=document)),)
    elif scope.source == "Cisco":
        feed = parse_cisco(payload, scope=scope)
        records = (
            AdvisoryRecord(
                feed.advisory_id,
                tuple(record.cve_id for record in feed.records),
                dict(document=json.loads(feed.raw_payload, parse_float=Decimal)),
            ),
        )
    elif scope.source == "Debian":
        feed = parse_debian(payload, scope=scope)
        records = tuple(
            AdvisoryRecord(
                record.source_record_id,
                record.cve_ids,
                dict(document={record.source_record_id: record.issues}),
            )
            for record in feed.records
        )
    elif scope.source == "Apache HTTP Server":
        feed = parse_httpd(payload, scope=scope)
        records = tuple(
            AdvisoryRecord(
                record.source_record_id, record.cve_ids, dict(document=record.raw)
            )
            for record in feed.records
        )
    elif scope.source == "Apache Tomcat":
        series = scope.scope_reference.removeprefix(
            TOMCAT_BASE + "security-"
        ).removesuffix(".xml")
        notices = parse_tomcat(payload, series=series)
        records = (
            AdvisoryRecord(
                "security-" + series,
                tuple(dict.fromkeys(notice.cve_id for notice in notices)),
                dict(
                    wire_text=payload.decode("utf-8-sig"),
                    notices=[asdict(notice) for notice in notices],
                ),
            ),
        )
    else:
        native = scope.scope_reference.removeprefix(SAMBA_BASE).removesuffix(".html")
        notice = parse_samba(payload, cve_id=native)
        fields = asdict(notice)
        del fields["raw_payload"]
        records = (
            AdvisoryRecord(
                native,
                (native,),
                dict(wire_text=payload.decode("utf-8-sig"), notice=fields),
            ),
        )
    return AdvisoryFeed(scope, payload, records)


def reconstruct_payload(fields):
    if "wire_text" in fields:
        return fields["wire_text"].encode()
    return source_json(fields["document"]).encode()
