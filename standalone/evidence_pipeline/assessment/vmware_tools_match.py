"""Evaluate VMware CNA version statements against pinned Defender Tools facts.

This does not establish environmental prerequisites, exploitability or patch
installation. Broadcom VMSA-2025-0015.1 explicitly uses both three- and
four-component Tools versions; only a missing final zero is normalized here.
"""

import re

_NUMBER = r"(?:0|[1-9][0-9]{0,8})"
_VERSION = re.compile(rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}(?:\.{_NUMBER})?")
_WINDOWS = {
    "Windows10",
    "Windows11",
    "WindowsServer2012",
    "WindowsServer2012R2",
    "WindowsServer2016",
    "WindowsServer2019",
    "WindowsServer2022",
    "WindowsServer2025",
}
_STATUSES = {"affected", "unaffected", "unknown"}


def version_key(value):
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        return None
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) if len(parts) == 3 else parts


def _version_match(item, candidate):
    if not isinstance(item, dict) or set(item) - {
        "version",
        "status",
        "versionType",
        "lessThan",
        "lessThanOrEqual",
    }:
        return None
    if item.get("status") not in tuple(_STATUSES) or item.get(
        "versionType", "custom"
    ) not in (
        "custom",
        "commercial",
    ):
        return None
    raw = item.get("version")
    start = version_key(raw)
    prefix = None
    if start is None:
        if not isinstance(raw, str):
            return None
        parts = raw.split(".")
        if len(parts) not in (3, 4) or "x" not in parts:
            return None
        split = parts.index("x")
        if (
            split == 0
            or any(p != "x" for p in parts[split:])
            or any(re.fullmatch(_NUMBER, p) is None for p in parts[:split])
        ):
            return None
        prefix = tuple(map(int, parts[:split]))
        start = prefix + (0,) * (4 - len(prefix))
    bounds = [k for k in ("lessThan", "lessThanOrEqual") if k in item]
    if len(bounds) > 1:
        return None
    if not bounds:
        return (
            candidate[: len(prefix)] == prefix
            if prefix is not None
            else candidate == start
        )
    bound = bounds[0]
    end = version_key(item[bound])
    if end is None or end < start or (end == start and bound == "lessThan"):
        return None
    return (
        candidate >= start
        and (prefix is None or candidate[: len(prefix)] == prefix)
        and (candidate < end if bound == "lessThan" else candidate <= end)
    )


def evaluate_tools(
    affected, *, provider, product, publisher, version, operating_system
):
    """Return a source-specific product/version statement, never CVE remediation."""

    def result(state, reason, entries=()):
        return dict(
            state=state,
            reason=reason,
            entries=list(entries),
            interpretation="publisher_product_version_statement_not_full_applicability",
        )

    candidate = version_key(version)
    if (
        provider != "vmware"
        or publisher != "vmware"
        or product != "tools"
        or candidate is None
    ):
        return result("unknown", "unsupported_or_missing_pinned_tools_identity")
    if not isinstance(affected, list) or not affected:
        return result("unknown", "missing_affected_entries")
    evaluations = []
    for index, entry in enumerate(affected):
        if not isinstance(entry, dict):
            return result("unknown", "invalid_affected_entry")
        if entry.get("vendor") != "VMware" or entry.get("product") not in (
            "Tools",
            "VMware tools",
            "VMware Tools",
        ):
            continue
        if set(entry) - {"vendor", "product", "versions", "defaultStatus", "platforms"}:
            return result("unknown", "unsupported_product_selectors")
        if "platforms" in entry and (
            entry["platforms"] != ["Windows"] or operating_system not in tuple(_WINDOWS)
        ):
            return result("unknown", "missing_or_unsupported_platform_evidence")
        default = entry.get("defaultStatus", "unknown")
        versions = entry.get("versions")
        if (
            default not in tuple(_STATUSES)
            or not isinstance(versions, list)
            or not versions
        ):
            return result("unknown", "missing_version_status")
        matches = []
        for position, item in enumerate(versions):
            matched = _version_match(item, candidate)
            if matched is None:
                return result("unknown", "unsupported_or_conflicting_version_rules")
            if matched:
                matches.append(dict(index=position, status=item["status"]))
        states = {match["status"] for match in matches} or {default}
        if len(states) != 1:
            return result("unknown", "conflicting_version_statuses")
        evaluations.append(dict(index=index, state=next(iter(states)), matches=matches))
    if not evaluations:
        return result("unknown", "no_supported_tools_entry")
    states = {entry["state"] for entry in evaluations}
    if len(states) != 1:
        return result("unknown", "conflicting_product_entries", evaluations)
    return result(
        next(iter(states)), "explicit_tools_product_version_statement", evaluations
    )
