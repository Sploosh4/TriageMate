"""Conservative Intune Windows Edge identity and Microsoft CNA version claims.

Only the exact desktop product/publisher pair and four-component Chromium
versions are supported. Store aliases, legacy Edge, channels, architecture and
environmental requirements are not inferred. An unmentioned version is unknown.
"""

import re

_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){3}")
_STATES = ("affected", "unaffected", "unknown")
_WINDOWS = (
    "Windows",
    "Windows10",
    "Windows11",
    "WindowsServer2012",
    "WindowsServer2012R2",
    "WindowsServer2016",
    "WindowsServer2019",
    "WindowsServer2022",
    "WindowsServer2025",
)


def version_key(value):
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        return None
    return tuple(map(int, value.split(".")))


def version_match(rule, candidate):
    """None means unsupported/invalid; False is a valid range non-match."""
    if not isinstance(rule, dict) or set(rule) - {
        "version",
        "status",
        "versionType",
        "lessThan",
        "lessThanOrEqual",
    }:
        return None
    if (
        rule.get("status") not in _STATES
        or rule.get("versionType", "custom") != "custom"
    ):
        return None
    lower = version_key(rule.get("version"))
    if lower is None:
        return None
    bounds = [key for key in ("lessThan", "lessThanOrEqual") if key in rule]
    if len(bounds) > 1:
        return None
    if not bounds:
        return candidate == lower
    bound = bounds[0]
    upper = version_key(rule[bound])
    if upper is None or upper < lower or (upper == lower and bound == "lessThan"):
        return None
    return lower <= candidate and (
        candidate < upper if bound == "lessThan" else candidate <= upper
    )


def evaluate_edge(source_fields, *, provider, facts):
    product = _evaluate_products(source_fields, provider=provider, facts=facts)
    if (
        not isinstance(source_fields, dict)
        or "cpeApplicability" not in source_fields
        or "configurations" in source_fields
        or product["mapping_profile"] is None
    ):
        return product
    from standalone.evidence_pipeline.assessment.edge_cpe_match import (
        evaluate_configurations,
    )

    cpe = evaluate_configurations(
        source_fields["cpeApplicability"], version_key(facts.get("version"))
    )
    state, reason = "unknown", "incomplete_product_or_cpe_evidence"
    if product["state"] in ("affected", "unaffected") and cpe["state"] != "unknown":
        if (product["state"] == "affected") == (cpe["state"] == "matched"):
            state, reason = product["state"], "consistent_product_and_cpe_evidence"
        else:
            reason = "conflicting_product_and_cpe_evidence"
    return {**product, "state": state, "reason": reason, "product": product, "cpe": cpe}


def _evaluate_products(source_fields, *, provider, facts):
    profile = None

    def result(state, reason, entries=()):
        return dict(
            state=state,
            reason=reason,
            entries=list(entries),
            inventory=dict(facts),
            mapping_profile=profile,
            interpretation="publisher_product_version_statement_not_full_applicability",
        )

    if (
        facts.get("source") != "Intune"
        or facts.get("product") != "Microsoft Edge"
        or facts.get("publisher") != "Microsoft Corporation"
    ):
        return result("unknown", "unsupported_inventory_product_identity")
    candidate = version_key(facts.get("version"))
    if candidate is None or candidate[0] < 77:
        return result("unknown", "unsupported_or_missing_edge_chromium_version")
    profile = "intune-windows-microsoft-edge-chromium-v1"
    if (
        facts.get("platform") != "windows"
        or facts.get("operating_system") not in _WINDOWS
    ):
        return result("unknown", "missing_or_conflicting_inventory_platform")
    if provider != "microsoft" or not isinstance(source_fields, dict):
        return result("unknown", "missing_published_microsoft_cna_evidence")
    if "configurations" in source_fields:
        return result("unknown", "additional_cna_configuration_requires_evaluation")
    affected = source_fields.get("affected")
    if not isinstance(affected, list) or not affected:
        return result("unknown", "missing_affected_entries")
    entries = []
    for index, entry in enumerate(affected):
        if not isinstance(entry, dict):
            return result("unknown", "invalid_affected_entry")
        if (
            entry.get("vendor") != "Microsoft"
            or entry.get("product") != "Microsoft Edge (Chromium-based)"
        ):
            continue
        if set(entry) - {"vendor", "product", "versions", "defaultStatus", "platforms"}:
            return result("unknown", "unsupported_product_selectors")
        if "platforms" in entry and entry["platforms"] != ["Windows"]:
            return result("unknown", "missing_or_unsupported_platform_evidence")
        default = entry.get("defaultStatus", "unknown")
        versions = entry.get("versions")
        if default not in _STATES or not isinstance(versions, list) or not versions:
            return result("unknown", "missing_version_status")
        matches = []
        for position, rule in enumerate(versions):
            matched = version_match(rule, candidate)
            if matched is None:
                return result("unknown", "unsupported_or_conflicting_version_rules")
            if matched:
                matches.append(dict(index=position, status=rule["status"]))
        states = {match["status"] for match in matches} or {default}
        if len(states) != 1:
            return result("unknown", "conflicting_version_statuses")
        entries.append(dict(index=index, state=next(iter(states)), matches=matches))
    if not entries:
        return result("unknown", "no_supported_edge_entry")
    states = {entry["state"] for entry in entries}
    if len(states) != 1:
        return result("unknown", "conflicting_product_entries", entries)
    return result(
        next(iter(states)), "explicit_edge_product_version_statement", entries
    )
