"""Bounded bundle-member records; declarations never assert installed products."""

import hashlib
import json
import re

from standalone.evidence_pipeline.temporary_index import temporary_index

SUMMARY_FIELDS = {"state", "reason", "sha256", "member_count"}
MEMBER_FIELDS = {
    "kind",
    "native_id",
    "name",
    "version",
    "publisher",
    "family_name",
    "bundle_native_id",
    "bundle_version",
    "manifest_sha256",
    "member_index",
    "member_type",
    "architecture",
    "resource_id",
    "is_stub",
}


def member_identity(record):
    return hashlib.sha256(
        json.dumps(
            [
                record["bundle_native_id"],
                record["manifest_sha256"],
                record["member_index"],
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()


def _text(value, required=True):
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or (required and not value.strip())
    ):
        raise ValueError("Invalid bundle text")


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{1,5}(\.[0-9]{1,5}){3}", value
    ):
        raise ValueError("Invalid bundle version")
    if any(int(part) > 65535 for part in value.split(".")):
        raise ValueError("Invalid bundle version component")


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("Invalid bundle manifest fingerprint")


def validate_summary(record):
    summary = record["bundle_manifest"]
    if not isinstance(summary, dict) or set(summary) != SUMMARY_FIELDS:
        raise ValueError("Unexpected bundle manifest summary")
    if record.get("kind") != "appx" or record.get("is_bundle") is not True:
        raise ValueError("Bundle summary requires an explicit bundle observation")
    if type(summary["member_count"]) is not int or summary["member_count"] < 0:
        raise ValueError("Invalid bundle member count")
    if summary["state"] == "read":
        if summary["reason"] != "exact_bundle_manifest_identity":
            raise ValueError("Invalid bundle manifest identity state")
        _digest(summary["sha256"])
        for key in ("native_id", "name", "publisher", "family_name"):
            _text(record.get(key))
        _version(record.get("version"))
    elif summary["state"] == "unavailable":
        if summary["reason"] not in (
            "bundle_manifest_read_failed",
            "bundle_manifest_identity_conflict",
        ):
            raise ValueError("Invalid unavailable bundle reason")
        if summary["sha256"] is not None or summary["member_count"] != 0:
            raise ValueError("Unavailable bundle cannot assert members")
    else:
        raise ValueError("Invalid bundle manifest state")


def validate_member(record):
    if not isinstance(record, dict) or set(record) != MEMBER_FIELDS:
        raise ValueError("Unexpected bundle member fields")
    if record["kind"] != "appx_bundle_member":
        raise ValueError("Invalid bundle member kind")
    for key in ("native_id", "name", "publisher", "family_name", "bundle_native_id"):
        _text(record[key])
    for key in ("version", "bundle_version"):
        _version(record[key])
    _digest(record["manifest_sha256"])
    if type(record["member_index"]) is not int or record["member_index"] < 1:
        raise ValueError("Invalid bundle member index")
    if record["member_type"] not in ("application", "resource"):
        raise ValueError("Invalid bundle member type")
    if record["architecture"] not in (
        "x86",
        "x64",
        "arm",
        "arm64",
        "neutral",
        "x86a64",
    ):
        raise ValueError("Unsupported bundle member architecture")
    resource = record["resource_id"]
    if not isinstance(resource, str) or not re.fullmatch(
        r"[A-Za-z0-9.-]{0,30}", resource
    ):
        raise ValueError("Invalid bundle member resource identity")
    if type(record["is_stub"]) is not bool:
        raise ValueError("Invalid bundle stub flag")
    if record["native_id"] != member_identity(record):
        raise ValueError("Bundle member identity differs from its source declaration")


def validate_links(records, *, cancelled=lambda: False):
    """Check complete source relations using disk indexes, regardless of row order."""
    with temporary_index() as db:
        db.executescript("""
        CREATE TABLE parents(id TEXT PRIMARY KEY, fingerprint TEXT, name TEXT,
          publisher TEXT, family TEXT, version TEXT, expected INTEGER);
        CREATE TABLE members(parent TEXT, fingerprint TEXT, name TEXT,
          publisher TEXT, family TEXT, version TEXT, ordinal INTEGER,
          PRIMARY KEY(parent,ordinal));
        """)
        for record in records:
            if cancelled():
                raise ValueError("Inventory processing cancelled")
            if record.get("kind") == "appx" and "bundle_manifest" in record:
                validate_summary(record)
                summary = record["bundle_manifest"]
                db.execute(
                    "INSERT INTO parents VALUES(?,?,?,?,?,?,?)",
                    (
                        record["native_id"],
                        summary["sha256"],
                        record.get("name"),
                        record.get("publisher"),
                        record.get("family_name"),
                        record.get("version"),
                        summary["member_count"],
                    ),
                )
            elif record.get("kind") == "appx_bundle_member":
                validate_member(record)
                db.execute(
                    "INSERT INTO members VALUES(?,?,?,?,?,?,?)",
                    (
                        record["bundle_native_id"],
                        record["manifest_sha256"],
                        record["name"],
                        record["publisher"],
                        record["family_name"],
                        record["bundle_version"],
                        record["member_index"],
                    ),
                )
        if db.execute("""SELECT 1 FROM members m LEFT JOIN parents p ON p.id=m.parent
            WHERE p.id IS NULL OR p.fingerprint IS NOT m.fingerprint
            OR p.name IS NOT m.name OR p.publisher IS NOT m.publisher
            OR p.family IS NOT m.family OR p.version IS NOT m.version
            OR m.ordinal>p.expected LIMIT 1""").fetchone():
            raise ValueError("Bundle member lacks its exact collection parent")
        if db.execute("""SELECT 1 FROM parents p WHERE p.expected <>
            (SELECT count(*) FROM members m WHERE m.parent=p.id) LIMIT 1""").fetchone():
            raise ValueError("Incomplete bundle member declarations")
