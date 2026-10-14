"""Exact Windows application identities and conservative Microsoft CNA claims.

This evaluates publisher product/version statements, not patch applicability.
Unknown version ordering, selectors and configurations remain unknown.
"""

import re

from standalone.evidence_pipeline.assessment.edge_inventory_match import _WINDOWS

PACKAGE_PUBLISHER = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)
PROFILES = {
    ("Microsoft OneDrive", "Microsoft Corporation"): (
        "OneDrive for Windows",
        "intune-windows-onedrive-v1",
    ),
    ("MSTeams", PACKAGE_PUBLISHER): (
        "Microsoft Teams for Desktop",
        "intune-windows-msteams-v1",
    ),
}


_VERSION = re.compile(r"[0-9]{1,8}(?:\.[0-9]{1,8}){1,3}")


def version_key(value):
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        return None
    return tuple(int(part) for part in value.split("."))


def compare_versions(left, right):
    """Compare explicit numeric components; never invent an absent component."""
    width = min(len(left), len(right))
    if left[:width] != right[:width]:
        return -1 if left[:width] < right[:width] else 1
    return 0 if len(left) == len(right) else None


def version_match(rule, candidate):
    if not isinstance(rule, dict) or set(rule) - {
        "version",
        "status",
        "versionType",
        "lessThan",
        "lessThanOrEqual",
    }:
        return None
    if (
        rule.get("status") not in ("affected", "unaffected", "unknown")
        or rule.get("versionType", "custom") != "custom"
    ):
        return None
    lower = version_key(rule.get("version"))
    bounds = [key for key in ("lessThan", "lessThanOrEqual") if key in rule]
    if lower is None or len(bounds) > 1:
        return None
    low_cmp = compare_versions(candidate, lower)
    if not bounds:
        return None if low_cmp is None else low_cmp == 0
    upper = version_key(rule[bounds[0]])
    if upper is None:
        return None
    order = compare_versions(lower, upper)
    if order is None or order > 0 or (order == 0 and bounds[0] == "lessThan"):
        return None
    high_cmp = compare_versions(candidate, upper)
    if low_cmp is None or high_cmp is None:
        return None
    return low_cmp >= 0 and (high_cmp < 0 if bounds[0] == "lessThan" else high_cmp <= 0)


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

    identity = (facts.get("product"), facts.get("publisher"))
    if (
        facts.get("source") != "Intune"
        or not all(isinstance(value, str) for value in identity)
        or identity not in PROFILES
    ):
        return result("unknown", "unsupported_inventory_product_identity")
    target, profile = PROFILES[identity]
    if (
        facts.get("platform") != "windows"
        or facts.get("operating_system") not in _WINDOWS
    ):
        return result("unknown", "missing_or_conflicting_inventory_platform")
    candidate = version_key(facts.get("version"))
    if candidate is None or len(candidate) != 4:
        return result("unknown", "unsupported_or_missing_application_version")
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
        if entry.get("vendor") != "Microsoft" or entry.get("product") != target:
            continue
        if set(entry) - {"vendor", "product", "versions", "defaultStatus", "platforms"}:
            return result("unknown", "unsupported_product_selectors")
        if "platforms" in entry and entry["platforms"] != ["Windows"]:
            return result("unknown", "missing_or_unsupported_platform_evidence")
        default = entry.get("defaultStatus", "unknown")
        versions = entry.get("versions")
        if (
            default not in ("affected", "unaffected", "unknown")
            or not isinstance(versions, list)
            or not versions
        ):
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
        return result("unknown", "no_supported_application_entry")
    states = {entry["state"] for entry in entries}
    if len(states) != 1:
        return result("unknown", "conflicting_product_entries", entries)
    return result(
        next(iter(states)), "explicit_application_product_version_statement", entries
    )


def evaluate_windows_app(source_fields, *, provider, facts):
    product = _evaluate_products(source_fields, provider=provider, facts=facts)
    if (
        not isinstance(source_fields, dict)
        or "cpeApplicability" not in source_fields
        or "configurations" in source_fields
        or product["mapping_profile"] is None
    ):
        return product
    from standalone.evidence_pipeline.assessment.windows_app_cpe_match import (
        evaluate_configurations,
    )

    cpe = evaluate_configurations(source_fields["cpeApplicability"], facts)
    state, reason = "unknown", "incomplete_product_or_cpe_evidence"
    if product["state"] in ("affected", "unaffected") and cpe["state"] != "unknown":
        if (product["state"] == "affected") == (cpe["state"] == "matched"):
            state, reason = product["state"], "consistent_product_and_cpe_evidence"
        else:
            reason = "conflicting_product_and_cpe_evidence"
    return {**product, "state": state, "reason": reason, "product": product, "cpe": cpe}
