"""Separate exact installed media name/version evidence from advisory conditions.

HEVC's manufacturer variant is deliberately not aliased to either CNA product.
The collector's manifest evidence is required; display-name resemblance alone
cannot establish identity. This evaluator never asserts patch applicability.
"""

from standalone.windows_inventory.manifest import validate_manifest
from standalone.evidence_pipeline.assessment.edge_inventory_match import _WINDOWS
from standalone.evidence_pipeline.assessment.windows_app_match import (
    PACKAGE_PUBLISHER,
    version_key,
    version_match,
)


# Exact manifest names agree with the publisher CNA product statements. Store
# catalogue recognition alone never supplies these advisory aliases.
MEDIA_PRODUCTS = {
    "Microsoft.AV1VideoExtension": ("AV1 Video Extension", "av1_video_extension"),
    "Microsoft.HEIFImageExtension": ("HEIF Image Extension", "heif_image_extension"),
    "Microsoft.RawImageExtension": ("Raw Image Extension", "raw_image_extension"),
    "Microsoft.WebMediaExtensions": ("Web Media Extensions", "web_media_extensions"),
    "Microsoft.WebpImageExtension": ("WebP Image Extension", "webp_image_extension"),
    "Microsoft.MPEG2VideoExtension": (
        "MPEG-2 Video Extension",
        "mpeg-2_video_extension",
    ),
}


def evaluate_media(source_fields, *, provider, facts):
    result = dict(
        state="unknown",
        reason="unsupported_inventory_product_identity",
        product_version_status="unknown",
        condition_status="unknown",
        mapping_profile=None,
        entries=[],
        inventory=dict(facts),
        interpretation="publisher_product_version_statement_not_full_applicability",
        applicability="unknown",
    )
    product = facts.get("product")
    target = MEDIA_PRODUCTS.get(product) if isinstance(product, str) else None
    if (
        facts.get("source") != "Windows inventory"
        or facts.get("kind") != "appx"
        or target is None
        or facts.get("name") != facts.get("product")
        or facts.get("publisher") != PACKAGE_PUBLISHER
        or facts.get("family_name") != product + "_8wekyb3d8bbwe"
        or facts.get("is_bundle") is not False
        or facts.get("is_resource_package") is not False
        or facts.get("is_framework") is not False
        or not isinstance(facts.get("native_id"), str)
        or not facts["native_id"].strip()
    ):
        return result
    if not isinstance(facts.get("user_states"), list) or not any(
        isinstance(user, dict) and user.get("install_state") == "Installed"
        for user in facts.get("user_states", [])
    ):
        return result | dict(reason="missing_installed_package_evidence")
    try:
        validate_manifest(facts)
    except (KeyError, ValueError, TypeError):
        return result | dict(reason="missing_or_conflicting_manifest_evidence")
    manifest = facts["manifest"]
    if manifest["state"] != "read" or manifest["display_name"] != target[0]:
        return result | dict(reason="missing_or_conflicting_manifest_product_name")
    result["mapping_profile"] = (
        "native-manifest-av1-cna-v1"
        if product == "Microsoft.AV1VideoExtension"
        else "native-manifest-store-media-cna-v1"
    )
    if (
        facts.get("platform") != "windows"
        or facts.get("operating_system") not in _WINDOWS
    ):
        return result | dict(reason="missing_or_conflicting_inventory_platform")
    version = version_key(facts.get("version"))
    if version is None or len(version) != 4:
        return result | dict(reason="unsupported_or_missing_application_version")
    if provider != "microsoft" or not isinstance(source_fields, dict):
        return result | dict(reason="missing_published_microsoft_cna_evidence")
    affected = source_fields.get("affected")
    if not isinstance(affected, list) or not affected:
        return result | dict(reason="missing_affected_entries")
    conditions_known = not any(
        key in source_fields for key in ("configurations", "cpeApplicability")
    )
    entries = []
    for index, entry in enumerate(affected):
        if not isinstance(entry, dict):
            return result | dict(reason="invalid_affected_entry")
        if entry.get("vendor") != "Microsoft" or entry.get("product") != target[0]:
            continue
        if set(entry) - {"vendor", "product", "versions", "defaultStatus", "platforms"}:
            conditions_known = False
        if "platforms" in entry and entry["platforms"] != ["Windows"]:
            conditions_known = False
        default = entry.get("defaultStatus", "unknown")
        rules = entry.get("versions")
        if (
            default not in ("affected", "unaffected", "unknown")
            or not isinstance(rules, list)
            or not rules
        ):
            return result | dict(reason="missing_version_status")
        matches = []
        for position, rule in enumerate(rules):
            matched = version_match(rule, version)
            if matched is None:
                return result | dict(reason="unsupported_or_conflicting_version_rules")
            if matched:
                matches.append(dict(index=position, status=rule["status"]))
        states = {match["status"] for match in matches} or {default}
        if len(states) != 1:
            return result | dict(reason="conflicting_version_statuses")
        entries.append(dict(index=index, state=next(iter(states)), matches=matches))
    if not entries:
        return result | dict(reason="no_supported_application_entry")
    result["entries"] = entries
    states = {entry["state"] for entry in entries}
    if len(states) != 1:
        return result | dict(reason="conflicting_product_entries")
    result["product_version_status"] = next(iter(states))
    if not conditions_known:
        return result | dict(reason="additional_or_unknown_advisory_conditions")
    return result | dict(
        state=result["product_version_status"],
        condition_status="supported",
        reason="explicit_application_product_version_statement",
    )
