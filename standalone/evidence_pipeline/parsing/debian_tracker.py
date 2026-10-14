"""Bounded public or synthetic Debian tracker contract.

Source structure follows Debian's security_db.calculateJson, not DSA notices.
No Debian version ordering, binary-package matching or inferred patch state.
"""

from dataclasses import dataclass
import re

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_inputs import (
    PublicFeed,
    CVE_PATTERN,
    _json,
    _object,
    _text,
)

URL = "https://security-tracker.debian.org/tracker/data/json"
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+\Z")
MAX_PACKAGE_ISSUES = 100_000


@dataclass(frozen=True)
class TrackerPackage:
    source_record_id: str
    issues: dict

    @property
    def cve_ids(self):
        return tuple(
            identity for identity in self.issues if CVE_PATTERN.fullmatch(identity)
        )


@dataclass(frozen=True)
class DebianFeed(PublicFeed):
    records: tuple[TrackerPackage, ...]


def optional_text(record, key):
    if key in record and record[key] is not None:
        _text(record[key], empty=True)


def validate_scope(scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("Debian", "tracker")
        or scope.tenant_id is not None
        or scope.origin not in {"synthetic", "public"}
        or scope.scope_reference != URL
    ):
        raise ValueError(
            "Debian tracker currently requires its fixed public or synthetic scope"
        )


def packages(pairs):
    total = 0
    for package, issues in pairs:
        if not PACKAGE.fullmatch(package) or len(package) > 256:
            raise ValueError("Invalid Debian source-package name")
        issues = _object(issues)
        total += len(issues)
        if total > MAX_PACKAGE_ISSUES:
            raise ValueError("Debian package/issue limit exceeded")
        for identity, issue in issues.items():
            _text(identity)
            if identity.startswith("CVE-") and not CVE_PATTERN.fullmatch(identity):
                raise ValueError("Malformed Debian CVE identifier")
            issue = _object(issue)
            for key in ("description", "scope"):
                optional_text(issue, key)
            if "debianbug" in issue and (
                type(issue["debianbug"]) is not int or issue["debianbug"] < 0
            ):
                raise ValueError("Invalid Debian bug identifier")
            for release, state in _object(issue.get("releases")).items():
                _text(release)
                state = _object(state)
                # Unknown future statuses remain explicit source values, never a fix.
                _text(state.get("status"))
                for key in ("fixed_version", "urgency", "nodsa", "nodsa_reason"):
                    optional_text(state, key)
                if (
                    "next_point_update" in state
                    and type(state["next_point_update"]) is not bool
                ):
                    raise ValueError("Invalid Debian point-update flag")
                for repository, version in _object(state.get("repositories")).items():
                    _text(repository)
                    _text(version)
        yield TrackerPackage(package, issues)


def iter_debian(stream, *, scope, cancelled=lambda: False):
    """Validate one package at a time; callers must consume through EOF."""
    from standalone.evidence_pipeline.json_stream import object_members

    validate_scope(scope)
    yield from packages(object_members(stream, cancelled=cancelled))


def parse_debian(payload, *, scope):
    validate_scope(scope)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Debian tracker payload must be bounded immutable bytes")
    root = _json(payload.decode("utf-8-sig"))
    return DebianFeed(scope, payload, tuple(packages(root.items())))
