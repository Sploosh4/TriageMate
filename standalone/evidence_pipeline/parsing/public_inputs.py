"""Pure, bounded public wire parsers; no fetching, scoring policy or persistence.

Provenance and exact wire bytes accompany every parsed feed. Unknown fields remain
in raw_payload, and unknown/absent facts never become invented negative evidence.
NVD results describe only the requested query, whereas KEV is a full catalogue.
Source/input_kind pairs are FIRST/epss, CISA/kev and NVD/vulnerabilities.
Wire references: https://www.first.org/epss/data,
https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json,
https://nvd.nist.gov/developers/vulnerabilities.
"""

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import csv
import hashlib
import io
import json
import re
from urllib.parse import urlsplit

from standalone.evidence_pipeline.contracts import SourceScope

# Daily EPSS includes more CVEs than a bounded Microsoft device snapshot.
MAX_PUBLIC_RECORDS = 1_000_000
MAX_TEXT = 100_000
MAX_DEPTH = 64
_INVALID_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]")
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")
INPUT_KINDS = {
    "FIRST": "epss",
    "CISA": "kev",
    "NVD": "vulnerabilities",
    "MSRC": "advisories",
}
VERSIONS = {
    "cvssMetricV2": "2.0",
    "cvssMetricV30": "3.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV40": "4.0",
}


@dataclass(frozen=True)
class PublicFeed:
    scope: SourceScope
    raw_payload: bytes

    @property
    def input_fingerprint(self) -> str:
        from standalone.evidence_pipeline.file_payload import FilePayload

        if isinstance(self.raw_payload, FilePayload):
            return self.raw_payload.fingerprint
        return hashlib.sha256(self.raw_payload).hexdigest()


@dataclass(frozen=True)
class EpssRecord:
    cve_id: str
    probability: Decimal
    percentile: Decimal


@dataclass(frozen=True)
class EpssFeed(PublicFeed):
    score_date: date
    model_version: str | None
    records: tuple[EpssRecord, ...]
    score_timestamp: datetime | None = None


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    short_description: str
    required_action: str
    date_added: date
    due_date: date
    known_ransomware_campaign_use: str | None
    notes: str | None
    cwes: tuple[str, ...] | None
    is_member: bool = True


@dataclass(frozen=True)
class KevFeed(PublicFeed):
    catalog_version: str
    date_released: datetime
    records: tuple[KevRecord, ...]
    # Syntax/count validation is not proof of transport completeness/authenticity.
    # Callers must validate transport and provenance before using absence.
    coverage: str = "catalogue"


@dataclass(frozen=True)
class CvssAssessment:
    source: str
    version: str
    score: Decimal
    vector: str
    severity: str | None
    assessment_type: str | None


@dataclass(frozen=True)
class NvdDescription:
    language: str
    value: str


@dataclass(frozen=True)
class NvdReference:
    url: str
    source: str | None
    tags: tuple[str, ...] | None


@dataclass(frozen=True)
class NvdRecord:
    cve_id: str
    source_identifier: str | None
    published: datetime | None
    last_modified: datetime | None
    vulnerability_status: str | None
    descriptions: tuple[NvdDescription, ...]
    references: tuple[NvdReference, ...]
    assessments: tuple[CvssAssessment, ...]
    supplemental_metric_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class NvdFeed(PublicFeed):
    timestamp: datetime
    records: tuple[NvdRecord, ...]
    coverage: str = "query"


def _wire(payload: bytes, scope: SourceScope, source: str) -> str:
    if (
        not isinstance(scope, SourceScope)
        or scope.source != source
        or scope.input_kind != INPUT_KINDS[source]
    ):
        raise ValueError("Source scope does not match the parser")
    if scope.origin not in ("public", "synthetic") or scope.tenant_id is not None:
        raise ValueError("Public parsers require public or synthetic non-tenant inputs")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Public payload must be bounded immutable bytes")
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ValueError("Invalid public payload encoding") from exc
    if "\x00" in text:
        raise ValueError("NUL is not valid public input text")
    return text


def _text(value, *, optional=False, empty=False) -> str | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, str)
        or len(value) > MAX_TEXT
        or (not empty and not value.strip())
        or _INVALID_TEXT.search(value) is not None
    ):
        raise ValueError("Expected bounded text")
    return value


def _cve(value) -> str:
    value = _text(value)
    if not CVE_PATTERN.fullmatch(value):
        raise ValueError("Invalid CVE identifier")
    return value


def _date(value) -> date:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value
    ):
        raise ValueError("Expected YYYY-MM-DD date")
    return date.fromisoformat(value)


def _timestamp(value, *, nvd=False, optional=False) -> datetime | None:
    if value is None and optional:
        return None
    value = _text(value)
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])?",
        value,
    ):
        raise ValueError("Expected ISO source timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD API timestamps omit the timezone and document UTC semantics.
    if parsed.tzinfo is None:
        if not nvd:
            raise ValueError("Explicit source timezone required")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _number(value, maximum: int, *, csv_value=False) -> Decimal:
    if csv_value:
        if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,6})?", value
        ):
            raise ValueError("Expected decimal CSV number")
    elif type(value) not in (int, Decimal):
        raise ValueError("Expected JSON number")
    try:
        result = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Invalid decimal") from exc
    if not result.is_finite() or not 0 <= result <= maximum:
        raise ValueError("Number outside published range")
    return result


def _object(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    return value


def _array(value) -> list:
    if not isinstance(value, list) or len(value) > MAX_PUBLIC_RECORDS:
        raise ValueError("Expected bounded JSON array")
    return value


def _integer(value) -> int:
    if type(value) is not int or not 0 <= value <= MAX_PUBLIC_RECORDS:
        raise ValueError("Expected bounded nonnegative integer")
    return value


def _json(text: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError("Nonfinite JSON number")

    def validate(value, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(value, dict):
            for key, child in value.items():
                _text(key, empty=True)
                validate(child, depth + 1)
        elif isinstance(value, list):
            for child in _array(value):
                validate(child, depth + 1)
        elif isinstance(value, str):
            _text(value, empty=True)
        elif isinstance(value, Decimal) and not value.is_finite():
            raise ValueError("Nonfinite JSON number")

    try:
        result = _object(
            json.loads(
                text,
                parse_float=Decimal,
                parse_constant=reject_constant,
                object_pairs_hook=unique,
            )
        )
        validate(result)
        return result
    except (RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid public JSON") from exc


def _unique(value, seen: set):
    if value in seen:
        raise ValueError("Duplicate source record")
    seen.add(value)


def parse_epss_csv(
    payload: bytes, *, scope: SourceScope, score_date: date | None = None
) -> EpssFeed:
    """Parse an uncompressed daily FIRST CSV, preserving exact decimal values.

    Historical v1 files require an explicit score_date because they lack metadata.
    A supplied date must agree with any header date; missing model stays unknown.
    """
    from standalone.evidence_pipeline.epss_route import scope_score_date

    requested_date = scope_score_date(scope.scope_reference)
    if requested_date is not None:
        if score_date is not None and score_date != requested_date:
            raise ValueError("EPSS explicit date differs from its archive scope")
        score_date = requested_date
    text = _wire(payload, scope, "FIRST")
    stream = io.StringIO(text, newline="")
    first = stream.readline()
    metadata = {}
    if first.startswith("#"):
        for item in first[1:].strip().split(","):
            if ":" not in item:
                raise ValueError("Malformed EPSS metadata")
            key, value = (part.strip() for part in item.split(":", 1))
            _unique(key, set(metadata))
            metadata[_text(key)] = _text(value)
        if "score_date" not in metadata:
            raise ValueError("EPSS metadata must include score_date")
    else:
        stream.seek(0)
    raw_date = metadata.get("score_date")
    # FIRST's dated archives use a basic UTC offset (+0000). Normalise only
    # this EPSS wire spelling; the retained payload preserves the original.
    if raw_date and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{4}",
        raw_date,
    ):
        raw_date = raw_date[:-2] + ":" + raw_date[-2:]
    score_timestamp = _timestamp(raw_date) if raw_date and "T" in raw_date else None
    header_date = (
        score_timestamp.date()
        if score_timestamp
        else (_date(raw_date) if raw_date else None)
    )
    if score_date is not None and type(score_date) is not date:
        raise ValueError("score_date must be a date")
    if header_date and score_date and score_date != header_date:
        raise ValueError("Conflicting EPSS score dates")
    effective_date = header_date or score_date
    if effective_date is None or effective_date < date(2021, 4, 14):
        raise ValueError("An available EPSS score date is required")
    records = []
    seen = set()
    try:
        reader = csv.reader(stream, strict=True)
        if next(reader, None) != ["cve", "epss", "percentile"]:
            raise ValueError("Unexpected EPSS CSV columns")
        for row in reader:
            if len(row) != 3 or len(records) >= MAX_PUBLIC_RECORDS:
                raise ValueError("Invalid EPSS row shape or count")
            cve = _cve(row[0])
            _unique(cve, seen)
            records.append(
                EpssRecord(
                    cve,
                    _number(row[1], 1, csv_value=True),
                    _number(row[2], 1, csv_value=True),
                )
            )
    except csv.Error as exc:
        raise ValueError("Malformed EPSS CSV") from exc
    return EpssFeed(
        scope,
        payload,
        effective_date,
        metadata.get("model_version"),
        tuple(records),
        score_timestamp,
    )


def parse_kev_json(payload: bytes, *, scope: SourceScope) -> KevFeed:
    """Parse a complete CISA catalogue; entries assert membership only.

    due_date/required_action remain CISA facts, not an instruction to any agency.
    """
    document = _json(_wire(payload, scope, "CISA"))
    rows = _array(document.get("vulnerabilities"))
    if _integer(document.get("count")) != len(rows):
        raise ValueError("KEV catalogue count mismatch")
    version = _text(document.get("catalogVersion"))
    released = _timestamp(document.get("dateReleased"))
    records = []
    seen = set()
    for row in rows:
        row = _object(row)
        cve = _cve(row.get("cveID"))
        _unique(cve, seen)
        cwes = row.get("cwes")
        if cwes is not None:
            cwes = tuple(_text(item) for item in _array(cwes))
            if any(not re.fullmatch(r"CWE-[0-9]+", item) for item in cwes):
                raise ValueError("Invalid CWE identifier")
        records.append(
            KevRecord(
                cve,
                _text(row.get("vendorProject")),
                _text(row.get("product")),
                _text(row.get("vulnerabilityName")),
                _text(row.get("shortDescription")),
                _text(row.get("requiredAction")),
                _date(row.get("dateAdded")),
                _date(row.get("dueDate")),
                _text(row.get("knownRansomwareCampaignUse"), optional=True),
                _text(row.get("notes"), optional=True, empty=True),
                cwes,
            )
        )
    return KevFeed(scope, payload, version, released, tuple(records))


def _assessments(metrics) -> tuple[CvssAssessment, ...]:
    result = []
    seen = set()
    for key, rows in _object(metrics).items():
        if key == "ssvcV203":
            # SSVC is not CVSS. Retain its presence and full wire claim without
            # interpreting it as a severity or inventing a prioritisation rule.
            _array(rows)
            continue
        if key not in VERSIONS:
            # Never silently drop a future published CVSS version.
            raise ValueError("Unsupported NVD metric family")
        for row in _array(rows):
            row = _object(row)
            data = _object(row.get("cvssData"))
            version = _text(data.get("version"))
            if version != VERSIONS[key]:
                raise ValueError("CVSS version disagrees with metric family")
            vector = _text(data.get("vectorString"))
            if version != "2.0" and not vector.startswith(f"CVSS:{version}/"):
                raise ValueError("CVSS vector version mismatch")
            assessment = CvssAssessment(
                _text(row.get("source")),
                version,
                _number(data.get("baseScore"), 10),
                vector,
                _text(data.get("baseSeverity", row.get("baseSeverity")), optional=True),
                _text(row.get("type"), optional=True),
            )
            # Identical duplicates are ambiguous; differing published assessments
            # from the same publisher/version remain separate, without arbitration.
            _unique(assessment, seen)
            result.append(assessment)
    return tuple(result)


def parse_nvd_json(payload: bytes, *, scope: SourceScope) -> NvdFeed:
    """Parse a complete bounded NVD API 2.0 query result, never a global inventory.

    A truncated page is rejected. Zero results and CVEs without metrics are valid,
    and imply neither remediation, missing global CVEs nor a zero CVSS score.
    """
    document = _json(_wire(payload, scope, "NVD"))
    if document.get("format") != "NVD_CVE" or document.get("version") != "2.0":
        raise ValueError("Expected NVD CVE API 2.0")
    rows = _array(document.get("vulnerabilities"))
    if (
        _integer(document.get("startIndex")) != 0
        or _integer(document.get("totalResults")) != len(rows)
        or _integer(document.get("resultsPerPage")) < len(rows)
    ):
        raise ValueError("NVD query must be complete; pagination is transport-owned")
    timestamp = _timestamp(document.get("timestamp"), nvd=True)
    records = []
    seen = set()
    for wrapper in rows:
        row = _object(_object(wrapper).get("cve"))
        cve = _cve(row.get("id"))
        _unique(cve, seen)
        descriptions = []
        for item in _array(row.get("descriptions", [])):
            item = _object(item)
            descriptions.append(
                NvdDescription(_text(item.get("lang")), _text(item.get("value")))
            )
        references = []
        for item in _array(row.get("references", [])):
            item = _object(item)
            url = _text(item.get("url"))
            parsed = urlsplit(url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("Invalid NVD reference URL")
            tags = item.get("tags")
            references.append(
                NvdReference(
                    url,
                    _text(item.get("source"), optional=True),
                    None if tags is None else tuple(_text(tag) for tag in _array(tags)),
                )
            )
        records.append(
            NvdRecord(
                cve,
                _text(row.get("sourceIdentifier"), optional=True),
                _timestamp(row.get("published"), nvd=True, optional=True),
                _timestamp(row.get("lastModified"), nvd=True, optional=True),
                _text(row.get("vulnStatus"), optional=True),
                tuple(descriptions),
                tuple(references),
                _assessments(row.get("metrics", {})),
                tuple(key for key in row.get("metrics", {}) if key == "ssvcV203"),
            )
        )
    return NvdFeed(scope, payload, timestamp, tuple(records))
