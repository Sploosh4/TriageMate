"""Explicit inventory identities, separate from finding-reported vulnerability.

Profiles are exact product/publisher/platform tuples, never fuzzy name matching.
The Tools profile recognises the VMware/Broadcom publisher identity for the
Windows application, not similarly named drivers or open-vm-tools. Original
facts and the selected profile remain inspectable in every result.
"""

from standalone.evidence_pipeline.assessment.vmware_tools_match import evaluate_tools

_TOOLS_PUBLISHERS = {"VMware, Inc.", "Broadcom Inc."}
_WINDOWS = {
    "Windows",
    "Windows10",
    "Windows11",
    "WindowsServer2012",
    "WindowsServer2012R2",
    "WindowsServer2016",
    "WindowsServer2019",
    "WindowsServer2022",
    "WindowsServer2025",
}
_TOOLS_NAMES = {"Tools", "VMware tools", "VMware Tools"}


def evaluate_inventory_product(
    source_fields,
    *,
    provider,
    source,
    product,
    publisher,
    version,
    platform,
    operating_system,
):
    facts = dict(
        source=source,
        product=product,
        publisher=publisher,
        version=version,
        platform=platform,
        operating_system=operating_system,
    )
    if product in ("Microsoft OneDrive", "MSTeams"):
        from standalone.evidence_pipeline.assessment.windows_app_match import (
            evaluate_windows_app,
        )

        return evaluate_windows_app(source_fields, provider=provider, facts=facts)
    if product == "Microsoft Edge":
        from standalone.evidence_pipeline.assessment.edge_inventory_match import (
            evaluate_edge,
        )

        return evaluate_edge(source_fields, provider=provider, facts=facts)
    profile = None

    def result(state, reason, entries=()):
        return dict(
            state=state,
            reason=reason,
            entries=list(entries),
            inventory=facts,
            mapping_profile=profile,
            interpretation="publisher_product_version_statement_not_full_applicability",
        )

    if (
        source != "Intune"
        or product != "VMware Tools"
        or not isinstance(publisher, str)
        or publisher not in _TOOLS_PUBLISHERS
    ):
        return result("unknown", "unsupported_inventory_product_identity")
    profile = "intune-windows-vmware-tools-v1"
    if (
        platform != "windows"
        or not isinstance(operating_system, str)
        or operating_system not in _WINDOWS
    ):
        return result("unknown", "missing_or_conflicting_inventory_platform")
    if not isinstance(source_fields, dict):
        return result("unknown", "missing_published_cna_evidence")
    if "cpeApplicability" in source_fields or "configurations" in source_fields:
        return result("unknown", "additional_cna_configuration_requires_evaluation")
    affected = source_fields.get("affected")
    if not isinstance(affected, list) or not affected:
        return result("unknown", "missing_affected_entries")
    validated = []
    for entry in affected:
        if (
            isinstance(entry, dict)
            and entry.get("vendor") == "VMware"
            and isinstance(entry.get("product"), str)
            and entry.get("product") in _TOOLS_NAMES
            and "platforms" in entry
        ):
            if entry["platforms"] != ["Windows"]:
                return result("unknown", "missing_or_unsupported_platform_evidence")
            # This one selector is established by the original inventory and
            # pinned OS facts above. Remove only that satisfied selector before
            # reusing the existing version-rule engine. Never invent an OS
            # release, mutate publisher evidence or discard other selectors.
            entry = {key: value for key, value in entry.items() if key != "platforms"}
        validated.append(entry)
    evaluated = evaluate_tools(
        validated,
        provider=provider,
        product="tools",
        publisher="vmware",
        version=version,
        operating_system=operating_system,
    )
    return result(evaluated["state"], evaluated["reason"], evaluated["entries"])
