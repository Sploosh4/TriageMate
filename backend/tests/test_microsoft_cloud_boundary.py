from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

import microsoft_evidence.cloud as cloud_module
from microsoft_evidence.cloud import (
    SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID,
    SYNTHETIC_PERMISSION_MANIFEST_ID,
    LiveTokenAuthorityUnavailable,
    MicrosoftPermissionManifest,
    PermissionGrant,
    SyntheticAppTokenClaims,
    assess_synthetic_token_fixture,
    prepare_collection_context,
    require_live_collection_authority,
)
from microsoft_evidence.contracts import MicrosoftEvidenceScope


NOW = datetime(2026, 8, 24, 8, 0, tzinfo=timezone.utc)
TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
APPLICATION_ID = UUID("20000000-0000-4000-8000-000000000002")
SERVICE_PRINCIPAL_ID = UUID("30000000-0000-4000-8000-000000000003")


def _scope(**updates) -> MicrosoftEvidenceScope:
    values = {
        "agency_id": "synthetic-agency-20",
        "tenant_id": TENANT_ID,
        "cloud": "global",
        "data_location": "synthetic-au-west",
        "product": "entra",
    }
    values.update(updates)
    return MicrosoftEvidenceScope(**values)


def _prepared(**updates):
    values = {
        "scope": _scope(),
        "endpoint_policy_id": SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID,
        "permission_manifest_id": SYNTHETIC_PERMISSION_MANIFEST_ID,
        "now": NOW,
    }
    values.update(updates)
    return prepare_collection_context(**values)


def _claims(**updates) -> SyntheticAppTokenClaims:
    values = {
        "issuer": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "tenant_id": TENANT_ID,
        "audience": "https://graph.microsoft.com",
        "application_id": APPLICATION_ID,
        "service_principal_id": SERVICE_PRINCIPAL_ID,
        "roles": ("Device.Read.All",),
        "scopes": (),
        "algorithm": "RS256",
        "presented_signing_key_id": "synthetic-untrusted-key-reference",
        "issued_at": NOW - timedelta(minutes=1),
        "not_before": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(updates)
    return SyntheticAppTokenClaims(**values)


def test_prepared_context_derives_exact_endpoint_from_server_policy() -> None:
    prepared = _prepared()
    assert prepared.endpoint.scheme == "https"
    assert prepared.endpoint.host == "graph.microsoft.com"
    assert prepared.endpoint.port == 443
    assert prepared.endpoint.path_template == "/v1.0/devices"
    assert prepared.audience == "https://graph.microsoft.com"
    assert prepared.classification == "synthetic"
    assert prepared.activation_allowed is False
    assert "url" not in prepared.model_dump_json().lower()


def test_caller_cannot_supply_an_endpoint_url() -> None:
    for endpoint in (
        "https://graph.microsoft.com/v1.0/users",
        "https://graph.microsoft.com:4443/v1.0/devices",
        "https://graph.microsoft.com/v1.0/devices?access_token=redacted",
    ):
        with pytest.raises(ValueError, match="endpoint policy"):
            _prepared(endpoint_policy_id=endpoint)


@pytest.mark.parametrize(
    "scope",
    [
        _scope(agency_id="other-agency"),
        _scope(tenant_id=UUID(int=10)),
        _scope(cloud="us_government"),
        _scope(data_location="other-location"),
        _scope(product="intune"),
    ],
)
def test_permission_manifest_must_match_scope_and_endpoint(scope) -> None:
    with pytest.raises(ValueError):
        _prepared(scope=scope)


def test_permission_manifest_rejects_write_or_empty_grants() -> None:
    base = cloud_module._synthetic_manifest_payload()
    with pytest.raises(ValidationError, match="read-only"):
        MicrosoftPermissionManifest(
            **{**base, "grants": (PermissionGrant(role="write", effect="write"),)}
        )
    with pytest.raises(ValidationError, match="nonempty"):
        MicrosoftPermissionManifest(**{**base, "grants": ()})


def test_permission_manifest_hash_is_recomputed() -> None:
    base = cloud_module._synthetic_manifest_payload()
    with pytest.raises(ValidationError, match="hash"):
        MicrosoftPermissionManifest(
            **{
                **base,
                "credential_reference_id": "different-synthetic-reference",
                "manifest_sha256": base["manifest_sha256"],
            }
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"consent_active": False},
        {"credential_revoked": True},
        {"authorization_healthy": False},
        {"effective_until": NOW},
        {"credential_effective_until": NOW},
    ],
)
def test_permission_manifest_requires_current_consent_and_health(
    monkeypatch, changes
) -> None:
    manifest = cloud_module._build_synthetic_manifest(**changes)
    monkeypatch.setitem(
        cloud_module._PERMISSION_MANIFESTS, manifest.manifest_id, manifest
    )
    with pytest.raises(ValueError):
        _prepared()


def test_caller_cannot_expand_roles_or_algorithms() -> None:
    with pytest.raises(TypeError):
        prepare_collection_context(
            scope=_scope(),
            endpoint_policy_id=SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID,
            permission_manifest_id=SYNTHETIC_PERMISSION_MANIFEST_ID,
            now=NOW,
            roles=("Directory.ReadWrite.All",),
        )
    with pytest.raises(ValueError, match="permission manifest"):
        _prepared(permission_manifest_id=UUID(int=99))


def test_matching_synthetic_claims_are_compatible_but_never_authorized() -> None:
    result = assess_synthetic_token_fixture(
        prepared=_prepared(), fixture=_claims(), now=NOW
    )
    assert result.compatible is True
    assert result.reasons == ()
    assert result.classification == "synthetic"
    assert result.cryptographic_verification == "not_performed"
    assert result.credential_acquisition_verified is False
    assert result.activation_allowed is False


def test_synthetic_signature_flags_and_secret_material_are_rejected() -> None:
    raw = _claims().model_dump(mode="python")
    for field, value in (
        ("signature_verified", True),
        ("raw_token", "redacted"),
        ("client_secret", "redacted"),
        ("private_key", "redacted"),
    ):
        with pytest.raises(ValidationError, match="Extra inputs"):
            SyntheticAppTokenClaims(**raw, **{field: value})


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"issuer": "https://invalid.example/tenant/v2.0"}, "issuer"),
        ({"tenant_id": UUID(int=99)}, "tenant"),
        ({"audience": "https://graph.microsoft.us"}, "audience"),
        ({"application_id": UUID(int=98)}, "application"),
        ({"service_principal_id": UUID(int=97)}, "service_principal"),
        ({"roles": ()}, "roles"),
        ({"roles": ("Device.Read.All", "Directory.Read.All")}, "roles"),
        ({"scopes": ("Device.Read",)}, "delegated_scopes"),
        ({"expires_at": NOW}, "expired"),
        ({"not_before": NOW + timedelta(seconds=1)}, "not_yet_valid"),
        ({"algorithm": "HS256"}, "algorithm"),
    ],
)
def test_synthetic_claim_mismatches_fail_closed(changes, reason) -> None:
    result = assess_synthetic_token_fixture(
        prepared=_prepared(), fixture=_claims(**changes), now=NOW
    )
    assert result.compatible is False
    assert reason in result.reasons
    assert result.activation_allowed is False


def test_arbitrary_matching_verifier_objects_cannot_authorize() -> None:
    for removed_name in (
        "SignatureVerifiedToken",
        "TrustedJwksVerifierContext",
        "ValidatedAppTokenContext",
        "validate_app_token",
    ):
        assert not hasattr(cloud_module, removed_name)


def test_live_collection_authority_is_unavailable_without_adapters() -> None:
    with pytest.raises(LiveTokenAuthorityUnavailable, match="server-owned"):
        require_live_collection_authority()


def test_serialized_contexts_never_contain_secrets() -> None:
    serialized = (
        _prepared().model_dump_json()
        + assess_synthetic_token_fixture(
            prepared=_prepared(), fixture=_claims(), now=NOW
        ).model_dump_json()
    ).lower()
    for forbidden in (
        "raw_token",
        "authorization",
        "client_secret",
        "certificate",
        "private_key",
        "request_url",
        "continuation",
    ):
        assert forbidden not in serialized
