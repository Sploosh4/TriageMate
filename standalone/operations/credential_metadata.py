"""Expiry declarations without reading secrets or claiming provider acceptance."""

from dataclasses import dataclass
import hashlib
import json

from standalone.evidence_pipeline.collection.snapshot_bundle import _read
from .certificates import Certificate
from .checkpoint import keys, timestamp


@dataclass(frozen=True)
class CredentialMetadata(Certificate):
    """Same private-file/provenance contract as certificate monitoring."""


def inspect_metadata(definition, now):
    observed = dict(
        condition="unavailable",
        fingerprint=None,
        not_before=None,
        expires_at=None,
        metadata_type="declared",
    )
    try:
        if definition.path.resolve() != definition.path:
            raise ValueError("Credential metadata cannot traverse symlinks")
        raw = _read(definition.path, 65536)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate credential metadata field")
                result[key] = value
            return result

        data = json.loads(raw, object_pairs_hook=unique)
        keys(
            data,
            ["version", "reference_id", "credential_type", "not_before", "expires_at"],
        )
        if (
            type(data["version"]) is not int
            or data["version"] != 1
            or data["reference_id"] != definition.reference_id
            or data["credential_type"]
            not in {"client_secret", "api_key", "certificate"}
        ):
            raise ValueError("Credential metadata identity or type differs")
        if data["expires_at"] is None:
            return observed
        expiry = timestamp(data["expires_at"])
        before = None if data["not_before"] is None else timestamp(data["not_before"])
        if before is not None and before >= expiry:
            raise ValueError("Invalid declared validity interval")
        observed.update(
            condition="not_yet_valid"
            if before is not None and now < before
            else "expired"
            if now >= expiry
            else "expiring"
            if (expiry - now).total_seconds() <= definition.warn_before_seconds
            else "healthy",
            fingerprint=hashlib.sha256(raw).hexdigest(),
            not_before=None if before is None else before.isoformat(),
            expires_at=expiry.isoformat(),
            metadata_type=data["credential_type"],
        )
    except (ValueError, TypeError, OSError, UnicodeError, OverflowError, RuntimeError):
        pass
    return observed
