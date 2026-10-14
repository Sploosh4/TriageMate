"""Bounded CVE JSON 5 records with separate CNA and ADP contributions.

This validates the fields used by TriageMate, not every optional schema extension.
Original metadata, affected ranges, metrics and contributor containers remain
intact. No version-range matching, CVSS arbitration or SSVC decision is inferred.
"""

from dataclasses import dataclass
from datetime import datetime
import re
from uuid import UUID

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    _array,
    _cve,
    _json,
    _object,
    _text,
)

VERSIONS = {"5.0", "5.1", "5.1.1", "5.2", "5.2.0"}
STATUS = {"affected", "unaffected", "unknown"}


@dataclass(frozen=True)
class Contribution:
    kind: str
    index: int
    organization_id: str
    provider_name: str | None
    raw: dict


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    state: str
    data_version: str
    metadata: dict
    contributions: tuple[Contribution, ...]


@dataclass(frozen=True)
class CveProgramFeed(PublicFeed):
    records: tuple[CveRecord, ...]


def organization(value):
    text = _text(value)
    parsed = UUID(text)
    if parsed.version != 4:
        raise ValueError("CVE organization identity must be a UUID v4")
    return text


def source_time(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?",
        value,
    ):
        raise ValueError("Invalid CVE source timestamp")
    # Validate calendar/time values; retain the original precision and offset.
    # The CVE schema explicitly defines absent offsets as GMT, unlike arbitrary
    # source timestamps. This parser does not replace any raw timestamp text.
    datetime.fromisoformat(value.replace("Z", "+00:00"))


def nonempty_array(value):
    result = _array(value)
    if not result:
        raise ValueError("Expected nonempty CVE field")
    return result


def descriptions(value):
    for item in nonempty_array(value):
        item = _object(item)
        _text(item.get("lang"))
        _text(item.get("value"))


def affected(value):
    for item in nonempty_array(value):
        item = _object(item)
        if not (
            {"vendor", "product"} <= item.keys()
            or {"collectionURL", "packageName"} <= item.keys()
        ):
            raise ValueError("CVE affected product identity is missing")
        for name in ("vendor", "product", "collectionURL", "packageName", "packageURL"):
            if name in item:
                _text(item[name])
        if "defaultStatus" in item and _text(item["defaultStatus"]) not in STATUS:
            raise ValueError("Unknown CVE affected status")
        if "versions" not in item and "defaultStatus" not in item:
            raise ValueError("CVE product has no version or default status")
        for version in nonempty_array(item["versions"]) if "versions" in item else []:
            version = _object(version)
            _text(version.get("version"))
            if _text(version.get("status")) not in STATUS:
                raise ValueError("Unknown CVE version status")
            if "lessThan" in version and "lessThanOrEqual" in version:
                raise ValueError("Ambiguous CVE version upper bound")
            for name in ("versionType", "lessThan", "lessThanOrEqual"):
                if name in version:
                    _text(version[name])
            if (
                "lessThan" in version or "lessThanOrEqual" in version
            ) and "versionType" not in version:
                raise ValueError("CVE version range requires its comparison type")
            for change in _array(version.get("changes", [])):
                change = _object(change)
                _text(change.get("at"))
                if _text(change.get("status")) not in STATUS:
                    raise ValueError("Unknown CVE version-change status")


def contributor(raw, kind, index, state):
    raw = _object(raw)
    provider = _object(raw.get("providerMetadata"))
    org = organization(provider.get("orgId"))
    name = _text(provider.get("shortName"), optional=True)
    if "dateUpdated" in provider:
        source_time(provider["dateUpdated"])
    if kind == "cna" and state == "PUBLISHED":
        for key in ("descriptions", "affected", "references"):
            if key not in raw:
                raise ValueError("Published CNA lacks required evidence")
    if kind == "cna" and state == "REJECTED":
        descriptions(raw.get("rejectedReasons"))
        for replacement in _array(raw.get("replacedBy", [])):
            _cve(replacement)
    if "descriptions" in raw:
        descriptions(raw["descriptions"])
    if "affected" in raw:
        affected(raw["affected"])
    if "references" in raw:
        for reference in nonempty_array(raw["references"]):
            _text(_object(reference).get("url"))
    for key in ("dateAssigned", "datePublic"):
        if key in raw:
            source_time(raw[key])
    for tag in _array(raw.get("tags", [])):
        _text(tag)
    for metric in _array(raw.get("metrics", [])):
        _object(metric)
    return Contribution(kind, index, org, name, dict(raw))


def parse_cve_record(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind)
        not in {
            ("CVE", "records"),
            ("CISA", "vulnrichment"),
            ("Palo Alto Networks", "advisories"),
        }
        or scope.tenant_id is not None
        or scope.origin not in ("synthetic", "public")
    ):
        raise ValueError("CVE records require a supported non-tenant public source")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("CVE input requires bounded immutable bytes")
    root = _json(payload.decode("utf-8-sig"))
    if (
        root.get("dataType") != "CVE_RECORD"
        or _text(root.get("dataVersion")) not in VERSIONS
    ):
        raise ValueError("Unsupported CVE record format")
    metadata = _object(root.get("cveMetadata"))
    cve = _cve(metadata.get("cveId"))
    organization(metadata.get("assignerOrgId"))
    state = _text(metadata.get("state"))
    if state not in {"PUBLISHED", "REJECTED"}:
        raise ValueError("CVE record has no supported public state")
    for key in ("dateReserved", "datePublished", "dateUpdated", "dateRejected"):
        if key in metadata:
            source_time(metadata[key])
    containers = _object(root.get("containers"))
    contributions = [contributor(containers.get("cna"), "cna", 0, state)]
    if state == "REJECTED" and "adp" in containers:
        raise ValueError("Rejected CVE record cannot contain active ADP claims")
    contributions.extend(
        contributor(raw, "adp", index, state)
        for index, raw in enumerate(_array(containers.get("adp", [])))
    )
    return CveProgramFeed(
        scope,
        payload,
        (
            CveRecord(
                cve, state, root["dataVersion"], dict(metadata), tuple(contributions)
            ),
        ),
    )
