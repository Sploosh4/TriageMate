"""Validate additive package-name evidence without turning names into CVE aliases."""

import re

_FIELDS = {
    "state",
    "reason",
    "sha256",
    "name",
    "version",
    "publisher",
    "display_name_reference",
    "display_name",
    "publisher_display_name",
    "display_name_basis",
    "signature_kind",
    "resource_lookup_hresult",
    "resolution_culture",
}
_IDENTITY = {
    "sha256",
    "name",
    "version",
    "publisher",
    "display_name_reference",
    "display_name",
    "publisher_display_name",
    "resource_lookup_hresult",
}


def supported_resource_reference(reference):
    """Accept plain PRI resource paths, never a file/URL or indirect DLL string."""
    if not isinstance(reference, str):
        return False
    match = re.fullmatch(
        r"ms-resource:(?://[A-Za-z0-9._-]*/|/)?"
        r"([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)",
        reference,
        re.IGNORECASE,
    )
    return bool(match and all(part not in (".", "..") for part in match[1].split("/")))


def validate_manifest(record):
    value = record["manifest"]
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("Unexpected package manifest metadata")
    for field, item in value.items():
        if field == "resource_lookup_hresult":
            if item is not None and (
                type(item) is not int or not -(2**31) <= item < 2**31
            ):
                raise ValueError("Invalid package resource lookup status")
        elif item is not None and (not isinstance(item, str) or len(item) > 4096):
            raise ValueError("Invalid package manifest text")
    if not value["signature_kind"] or value["resolution_culture"] is None:
        raise ValueError("Missing manifest observation context")
    state = value["state"]
    if state in ("unavailable", "not_applicable"):
        reasons = (
            ("manifest_read_failed", "manifest_identity_conflict")
            if state == "unavailable"
            else ("bundle_or_resource_package",)
        )
        if (
            value["reason"] not in reasons
            or value["display_name_basis"] != "unresolved"
            or any(value[field] is not None for field in _IDENTITY)
        ):
            raise ValueError("Unavailable manifest cannot assert identity or name")
        if state == "not_applicable" and not (
            record.get("is_bundle") is True or record.get("is_resource_package") is True
        ):
            raise ValueError("Manifest exclusion lacks package-kind evidence")
        return
    if state != "read" or value["reason"] != "exact_manifest_package_identity":
        raise ValueError("Invalid manifest observation state")
    if (
        record.get("is_bundle") is not False
        or record.get("is_resource_package") is not False
        or any(
            not isinstance(value[field], str)
            or not value[field].strip()
            or value[field] != record.get(field)
            for field in ("name", "version", "publisher")
        )
        or not isinstance(value["sha256"], str)
        or not re.fullmatch("[0-9a-f]{64}", value["sha256"])
    ):
        raise ValueError("Manifest identity differs from package observation")
    basis = value["display_name_basis"]
    name = value["display_name"]
    reference = value["display_name_reference"]
    if basis == "unresolved":
        if name is not None:
            raise ValueError("Unresolved package name cannot assert text")
    elif basis == "literal_manifest_value":
        if (
            not name
            or name != reference
            or name.lower().startswith("ms-resource:")
            or name.startswith("@")
            or value["resource_lookup_hresult"] is not None
        ):
            raise ValueError("Invalid literal manifest name")
    elif basis == "package_resource_text":
        if (
            not name
            or value["resource_lookup_hresult"] != 0
            or not supported_resource_reference(reference)
        ):
            raise ValueError("Invalid resolved package resource name")
    else:
        raise ValueError("Unknown package-name evidence basis")
