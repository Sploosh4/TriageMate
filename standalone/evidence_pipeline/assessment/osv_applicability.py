"""Evaluate explicit OSV package/version claims, never infer a device/package link.

SemVer ordering: https://semver.org/
Range semantics: https://ossf.github.io/osv-schema/#evaluation
Ecosystem and Git ordering require their own engines and remain unknown here.
"""

import re
import json

from standalone.evidence_pipeline.parsing.osv import OsvRecord

SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def semver_key(value):
    if not isinstance(value, str) or len(value) > 4096:
        return None
    match = SEMVER.fullmatch(value)
    if match is None:
        return None
    major, minor, patch, prerelease, _ = match.groups()
    identifiers = []
    for part in prerelease.split(".") if prerelease is not None else ():
        numeric = part.isascii() and part.isdigit()
        if numeric and len(part) > 1 and part.startswith("0"):
            return None
        identifiers.append((0, int(part)) if numeric else (1, part))
    return (int(major), int(minor), int(patch)), prerelease is None, tuple(identifiers)


def range_contains(specification, version):
    """Return True/False for supported ranges, None for unresolved ordering."""
    if specification.get("type") != "SEMVER":
        return None
    candidate = semver_key(version)
    if candidate is None:
        return None
    ordered, limits = {}, []
    for event in specification.get("events", []):
        boundary = [
            (kind, event[kind])
            for kind in ("introduced", "fixed", "last_affected", "limit")
            if kind in event
        ]
        if len(boundary) != 1:
            return None
        kind, value = boundary[0]
        if kind == "limit" and value == "*":
            limits.append(None)
            continue
        key = (-1, -1, -1), False, ()
        if not (kind == "introduced" and value == "0"):
            key = semver_key(value)
            if key is None:
                return None
        if kind == "limit":
            limits.append(key)
        else:
            if key in ordered and ordered[key] != kind:
                return None
            ordered[key] = kind
    if "introduced" not in ordered.values():
        return None
    if limits and not any(bound is None or candidate < bound for bound in limits):
        return False
    affected = False
    for boundary, kind in sorted(ordered.items()):
        if kind == "introduced" and candidate >= boundary:
            affected = True
        elif kind == "fixed" and candidate >= boundary:
            affected = False
        elif kind == "last_affected" and candidate > boundary:
            affected = False
    return affected


def _evaluate(record, *, name, ecosystem, version):
    """Evaluate one named package; the result does not establish patch installation.

    Identity is exact and case-sensitive. Inputs must already have a package
    ecosystem identity; Microsoft display names alone do not supply that mapping.
    """
    if not isinstance(record, OsvRecord):
        raise ValueError("A parsed OSV record is required")
    if any(
        not isinstance(value, str) or not value.strip() or len(value) > 4096
        for value in (name, ecosystem, version)
    ):
        raise ValueError(
            "An explicit bounded package identity and version are required"
        )
    if record.withdrawn is not None:
        return dict(state="unknown", reason="withdrawn_advisory", fixed_versions=[])
    selected, unknown_identity = [], False
    for entry in record.raw.get("affected", []) or []:
        package = entry.get("package")
        if package is None:
            unknown_identity = True
        elif package.get("name") == name and package.get("ecosystem") == ecosystem:
            selected.append(entry)
    if not selected:
        return dict(
            state="unknown" if unknown_identity else "unaffected",
            reason="package_identity_unresolved"
            if unknown_identity
            else "different_package",
            fixed_versions=[],
        )
    states, fixes = [], set()
    for entry in selected:
        versions = entry.get("versions", [])
        ranges = entry.get("ranges", [])
        if version in versions:
            states.append(True)
        if not versions and not ranges:
            states.append(None)
        for specification in ranges:
            matched = range_contains(specification, version)
            states.append(matched)
            if matched is True:
                key = semver_key(version)
                for event in specification["events"]:
                    fixed = event.get("fixed")
                    if (
                        fixed is not None
                        and semver_key(fixed) is not None
                        and semver_key(fixed) > key
                    ):
                        fixes.add(fixed)
    state = (
        "affected"
        if True in states
        else "unknown"
        if unknown_identity or None in states
        else "unaffected"
    )
    return dict(
        state=state,
        reason="source_version_claim"
        if state != "unknown"
        else "unsupported_or_incomplete_range",
        fixed_versions=sorted(fixes, key=semver_key),
    )


def evaluate(record, *, name, ecosystem, version):
    """Keep fixes only when all matching source ranges support that version.

    A fixed event from one range cannot override a second affected range or an
    unresolved ordering contract for the same package. This does not establish
    installation eligibility, compatibility, or a device/package association.
    """
    result = _evaluate(record, name=name, ecosystem=ecosystem, version=version)
    result["fixed_versions"] = [
        candidate
        for candidate in result["fixed_versions"]
        if _evaluate(record, name=name, ecosystem=ecosystem, version=candidate)["state"]
        == "unaffected"
    ]
    return result


def evaluate_query(result):
    """Report source-range results alongside a retained query, never as device facts."""
    from standalone.evidence_pipeline.parsing.osv_query import QueryResult

    if not isinstance(result, QueryResult):
        raise ValueError("A complete parsed OSV query result is required")
    query = json.loads(result.query)
    package = query["package"]
    supported = "name" in package and "ecosystem" in package and "version" in query
    assessments = []
    for page_index, page in enumerate(result.pages):
        for record_index, record in enumerate(page.records):
            assessed = (
                evaluate(
                    record,
                    name=package["name"],
                    ecosystem=package["ecosystem"],
                    version=query["version"],
                )
                if supported
                else dict(
                    state="unknown",
                    reason="explicit_package_and_version_required",
                    fixed_versions=[],
                )
            )
            assessments.append(
                dict(
                    advisory_id=record.advisory_id,
                    page_index=page_index,
                    record_index=record_index,
                    **assessed,
                )
            )
    return dict(query=query, assessments=assessments)
