"""Bounded OSV records preserving native IDs and ecosystem-specific source claims.

Validates the fields consumed here, not the complete evolving OSV JSON schema.
No alias merging, version matching or interpretation of arbitrary source URLs.
"""

from dataclasses import dataclass
from datetime import datetime
import re

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    _array,
    _json,
    _object,
    _text,
    CVE_PATTERN,
)


@dataclass(frozen=True)
class OsvRecord:
    advisory_id: str
    modified: str
    withdrawn: str | None
    aliases: tuple[str, ...]
    raw: dict

    @property
    def cve_ids(self):
        return tuple(alias for alias in self.aliases if CVE_PATTERN.fullmatch(alias))


@dataclass(frozen=True)
class OsvFeed(PublicFeed):
    records: tuple[OsvRecord, ...]


def timestamp(value):
    value = _text(value)
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", value
    ):
        raise ValueError("OSV timestamp requires an explicit UTC time")
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def nullable_array(value):
    return [] if value is None else _array(value)


def severity(value):
    for entry in nullable_array(value):
        entry = _object(entry)
        _text(entry.get("type"))
        _text(entry.get("score"))
        if "source" in entry:
            _text(entry["source"])


def affected(value):
    for entry in nullable_array(value):
        entry = _object(entry)
        if "package" in entry:
            package = _object(entry["package"])
            _text(package.get("name"))
            _text(package.get("ecosystem"))
            if "purl" in package:
                _text(package["purl"])
        severity(entry.get("severity"))
        for version in _array(entry.get("versions", [])):
            _text(version)
        for item in _array(entry.get("ranges", [])):
            item = _object(item)
            kind = _text(item.get("type"))
            if kind not in {"GIT", "SEMVER", "ECOSYSTEM"}:
                raise ValueError("Unsupported OSV range type")
            if kind == "GIT" or "repo" in item:
                _text(item.get("repo"))
            events = _array(item.get("events"))
            kinds = set()
            for event in events:
                event = _object(event)
                selected = set(event) & {
                    "introduced",
                    "fixed",
                    "last_affected",
                    "limit",
                }
                if len(selected) != 1:
                    raise ValueError("OSV event requires one range boundary")
                name = next(iter(selected))
                boundary = _text(event[name])
                special = (name == "introduced" and boundary == "0") or (
                    name == "limit" and boundary == "*"
                )
                if (
                    kind == "GIT"
                    and not special
                    and not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", boundary)
                ):
                    raise ValueError("OSV Git range requires full commit identities")
                kinds.add(name)
            if "introduced" not in kinds or {"fixed", "last_affected"} <= kinds:
                raise ValueError("Invalid OSV range boundaries")
            if "database_specific" in item:
                _object(item["database_specific"])
        for key in ("ecosystem_specific", "database_specific"):
            if key in entry:
                _object(entry[key])


def parse_osv(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind)
        not in {
            ("OSV", "advisories"),
            ("GitHub", "advisories"),
            ("Ubuntu", "advisories"),
        }
        or scope.tenant_id is not None
        or scope.origin not in {"synthetic", "public"}
    ):
        raise ValueError("OSV requires an authorized non-tenant public source")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("OSV requires bounded immutable bytes")
    raw = _json(payload.decode("utf-8-sig"))
    identity = _text(raw.get("id"))
    if len(identity) > 256 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9:._+\-]*", identity
    ):
        raise ValueError("Invalid OSV advisory identity")
    if "schema_version" in raw and not re.fullmatch(
        r"1\.[0-9]+\.[0-9]+", _text(raw["schema_version"])
    ):
        raise ValueError("Unsupported OSV schema version")
    modified = timestamp(raw.get("modified"))
    for name in ("published", "withdrawn"):
        if name in raw:
            timestamp(raw[name])
    for name in ("summary", "details"):
        if name in raw:
            _text(raw[name], optional=True)
    aliases = tuple(_text(item) for item in nullable_array(raw.get("aliases")))
    for name in ("related", "upstream"):
        for item in _array(raw.get(name, [])):
            _text(item)
    affected(raw.get("affected"))
    severity(raw.get("severity"))
    if "severity" in raw and any(
        entry.get("severity") is not None
        for entry in nullable_array(raw.get("affected"))
    ):
        raise ValueError("OSV severity cannot be both record and package scoped")
    for reference in nullable_array(raw.get("references")):
        reference = _object(reference)
        _text(reference.get("type"))
        _text(reference.get("url"))
    if "database_specific" in raw:
        _object(raw["database_specific"])
    return OsvFeed(
        scope,
        payload,
        (OsvRecord(identity, modified, raw.get("withdrawn"), aliases, raw),),
    )
