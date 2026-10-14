"""Validate selected native component observations; never fabricate full inventory.

Hashes bind retained bytes. Hardlinks are collector observations, not independent
proof of installed binary integrity or a CVE relationship. Conflicting Appx
identity stays visible and cannot become an applicable component observation.
"""

import base64
from datetime import datetime
import hashlib
import json
import re

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

from standalone.evidence_pipeline.contracts import utc
from standalone.evidence_pipeline.assessment.windows_version_match import windows_build
from .contract import DeviceBinding, _unique, _reject_constant
from .servicing_manifest import read_manifest

CONTRACT = "triagemate-windows-component-observations-v1"


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("Bounded nonempty component text required")


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("Component SHA-256 required")


def _bytes(value, digest):
    _digest(digest)
    if not isinstance(value, str) or len(value) > 16 * 1024 * 1024:
        raise ValueError("Bounded encoded manifest required")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Invalid encoded manifest") from exc
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("Component manifest hash mismatch")
    return raw


def validate_selected(raw, binding):
    if (
        not isinstance(raw, bytes)
        or len(raw) > 64 * 1024 * 1024
        or not isinstance(binding, DeviceBinding)
    ):
        raise ValueError(
            "Bounded component bytes and independent device binding required"
        )
    value = json.loads(
        raw.decode("utf-8-sig"),
        object_pairs_hook=_unique,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict) or set(value) != {
        "contract",
        "started_at",
        "finished_at",
        "machine_guid",
        "tenant_id",
        "device_id",
        "requested_names",
        "os",
        "dictionary",
        "rows",
        "complete",
        "scope",
    }:
        raise ValueError("Unexpected selected component envelope")
    if value["contract"] != CONTRACT or value["complete"] is not True:
        raise ValueError("Complete selected component contract required")
    if (
        DeviceBinding(*(value[k] for k in ("machine_guid", "tenant_id", "device_id")))
        != binding
    ):
        raise ValueError("Selected component device mismatch")
    started, finished = (
        utc(datetime.fromisoformat(value[k])) for k in ("started_at", "finished_at")
    )
    if finished < started:
        raise ValueError("Invalid component collection window")

    def observed(timestamp):
        result = utc(datetime.fromisoformat(timestamp))
        if not started <= result <= finished:
            raise ValueError("Component observation outside collection window")
        return result

    names = value["requested_names"]
    if not isinstance(names, list) or not names or len(names) > 512:
        raise ValueError("Bounded explicit requested component set required")
    for name in names:
        _text(name)
    if len(set(names)) != len(names):
        raise ValueError("Duplicate requested component")
    os = value["os"]
    if not isinstance(os, dict) or set(os) != {
        "caption",
        "release",
        "build",
        "ubr",
        "architecture",
    }:
        raise ValueError("Unexpected component OS evidence")
    for key in ("caption", "release", "build", "architecture"):
        _text(os[key])
    if (
        not re.fullmatch("[0-9]+", os["build"])
        or type(os["ubr"]) is not int
        or os["ubr"] < 0
    ):
        raise ValueError("Invalid component OS version")
    dictionary = value["dictionary"]
    if dictionary is not None:
        if not isinstance(dictionary, dict) or set(dictionary) != {
            "path",
            "dll_sha256",
            "dictionary_sha256",
        }:
            raise ValueError("Unexpected decoder provenance")
        _text(dictionary["path"])
        _digest(dictionary["dll_sha256"])
        _digest(dictionary["dictionary_sha256"])
    _text(value["scope"])
    if not isinstance(value["rows"], list) or len(value["rows"]) > 4096:
        raise ValueError("Bounded component rows required")
    records, assemblies, sources, seen, observed_names = [], [], {}, set(), set()
    unavailable = []
    for row in value["rows"]:
        if not isinstance(row, dict) or row.get("name") not in names:
            raise ValueError("Unexpected component row")
        observed(row["observed_at"])
        observed_names.add(row["name"])
        if row.get("state") == "not_observed":
            if set(row) != {"name", "state", "observed_at"}:
                raise ValueError("Unobserved component asserts fields")
            unavailable.append(row["name"])
            continue
        if row.get("state") != "observed" or set(row) != {
            "name",
            "state",
            "observed_at",
            "native_id",
            "version",
            "family_name",
            "publisher",
            "architecture",
            "status",
            "is_framework",
            "is_resource_package",
            "is_bundle",
            "user_states",
            "manifest",
            "assemblies",
            "error_code",
        }:
            raise ValueError("Unexpected observed component fields")
        for key in (
            "native_id",
            "version",
            "family_name",
            "publisher",
            "architecture",
            "status",
        ):
            _text(row[key])
        if row["native_id"] in seen or windows_build(row["version"]) is None:
            raise ValueError("Duplicate component identity or invalid version")
        seen.add(row["native_id"])
        if row["architecture"] not in ("X64", "X86", "Arm64", "Neutral"):
            raise ValueError("Unsupported package architecture")
        if any(
            type(row[k]) is not bool
            for k in ("is_framework", "is_resource_package", "is_bundle")
        ):
            raise ValueError("Explicit component flags required")
        if not isinstance(row["user_states"], list):
            raise ValueError("Explicit per-user states required")
        for user in row["user_states"]:
            if not isinstance(user, dict) or set(user) != {"sid", "install_state"}:
                raise ValueError("Invalid per-user component state")
            _text(user["sid"])
            _text(user["install_state"])
        if row["error_code"] not in (
            None,
            "component_evidence_unavailable",
            "package_changed_during_collection",
        ):
            raise ValueError("Unknown component collection failure")
        record = dict(row, kind="appx", manifest={"state": "unavailable"})
        records.append(record)
        manifest = row["manifest"]
        if manifest is not None:
            if not isinstance(manifest, dict) or set(manifest) != {
                "path",
                "sha256",
                "base64",
                "hardlinks",
            }:
                raise ValueError("Unexpected active manifest fields")
            _text(manifest["path"])
            raw_manifest = _bytes(manifest["base64"], manifest["sha256"])
            try:
                tree = ElementTree.fromstring(
                    raw_manifest,
                    forbid_dtd=True,
                    forbid_entities=True,
                    forbid_external=True,
                )
            except (ElementTree.ParseError, DefusedXmlException) as exc:
                raise ValueError("Unsafe or invalid Appx XML") from exc
            namespace = (
                "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
            )
            identities = tree.findall(namespace + "Identity")
            if tree.tag != namespace + "Package" or len(identities) != 1:
                raise ValueError("Unsupported Appx manifest identity")
            identity = identities[0]
            agrees = all(
                identity.get(xml) == row[key]
                for xml, key in [
                    ("Name", "name"),
                    ("Version", "version"),
                    ("Publisher", "publisher"),
                ]
            )
            manifest_architecture = identity.get("ProcessorArchitecture")
            architecture_agrees = manifest_architecture == row["architecture"].lower()
            if manifest_architecture is not None and not architecture_agrees:
                agrees = False
            record["manifest"] = {
                "state": "read"
                if agrees and row["error_code"] is None
                else "unavailable",
                "reason": "exact_manifest_package_identity"
                if agrees
                else "manifest_identity_conflict",
                "sha256": manifest["sha256"],
                "architecture_verified": architecture_agrees,
            }
            sources[manifest["sha256"]] = raw_manifest
            if not isinstance(manifest["hardlinks"], list):
                raise ValueError("Manifest hardlink observations required")
            for link in manifest["hardlinks"]:
                _text(link)
        if not isinstance(row["assemblies"], list) or (
            row["error_code"] is not None and row["assemblies"]
        ):
            raise ValueError("Invalid or failed component assembly observations")
        for assembly in row["assemblies"]:
            required = {
                "path",
                "active_hardlink",
                "source_sha256",
                "decoded_sha256",
                "decoded_base64",
                "observed_at",
            }
            if not isinstance(assembly, dict) or set(assembly) not in (
                required,
                required | {"source_base64"},
            ):
                raise ValueError("Unexpected servicing evidence fields")
            when = observed(assembly["observed_at"])
            if (
                manifest is None
                or assembly["active_hardlink"] not in manifest["hardlinks"]
            ):
                raise ValueError("Servicing evidence lacks observed active hardlink")
            match = re.fullmatch(
                r"\\Windows\\WinSxS\\([A-Za-z0-9_.-]+)\\.+",
                assembly["active_hardlink"],
                re.I,
            )
            if (
                not match
                or match[1] in (".", "..")
                or not assembly["path"]
                .lower()
                .endswith("\\winsxs\\manifests\\" + match[1].lower() + ".manifest")
            ):
                raise ValueError(
                    "Servicing path differs from active component directory"
                )
            _digest(assembly["source_sha256"])
            if "source_base64" in assembly:
                sources[assembly["source_sha256"]] = _bytes(
                    assembly["source_base64"], assembly["source_sha256"]
                )
            decoded = _bytes(assembly["decoded_base64"], assembly["decoded_sha256"])
            parsed = read_manifest(decoded, expected_sha256=assembly["decoded_sha256"])
            sources[assembly["decoded_sha256"]] = decoded
            assemblies.append(
                {
                    "native_id": row["native_id"],
                    "observed_at": when,
                    "identity": parsed["assembly"],
                    "sha256": assembly["decoded_sha256"],
                    "active_manifest_link": record["manifest"]["state"] == "read",
                    "compressed_bytes_retained": "source_base64" in assembly,
                }
            )
    if (
        observed_names != set(names)
        or len(unavailable) != len(set(unavailable))
        or any(r["name"] in unavailable for r in records)
    ):
        raise ValueError(
            "Requested component accounting is incomplete or contradictory"
        )
    return {
        "started_at": value["started_at"],
        "finished_at": value["finished_at"],
        "records": records,
        "assemblies": assemblies,
        "sources": sources,
        "os": os,
        "not_observed": unavailable,
        "scope": value["scope"],
    }
