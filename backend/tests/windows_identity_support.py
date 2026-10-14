"""Synthetic observations for published Windows component identity tests."""

import json
from pathlib import Path

PROFILES = {
    "cbs": ("windows_cbs_identities.json", "native-windows-cbs-identities-v1"),
    "cloud": (
        "windows_cloud_identity.json",
        "native-windows-published-component-identities-v1",
    ),
    "inbox": (
        "windows_inbox_identities.json",
        "native-windows-published-component-identities-v1",
    ),
    "security-app": (
        "windows_security_app_identity.json",
        "native-windows-published-component-identities-v1",
    ),
}

REFERENCES = {
    family: json.loads(
        (
            Path(__file__).parents[1] / "database/baseline/references" / filename
        ).read_text()
    )
    for family, (filename, _) in PROFILES.items()
}


def facts(entry, *, family="cbs", **changes):
    return (
        dict(
            source="Windows inventory",
            kind="appx",
            native_id=f"synthetic-{family}-identity",
            name=entry["name"],
            product=entry["name"],
            publisher=entry["publisher"],
            family_name=entry["package_family"],
            version="1.2.3.4",
            platform="windows",
            operating_system="Windows11",
            is_framework=entry["is_framework"],
            is_bundle=False,
            is_resource_package=False,
            user_states=[dict(install_state="Installed")],
        )
        | changes
    )
