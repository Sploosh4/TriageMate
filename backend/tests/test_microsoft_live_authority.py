"""Cryptographic and credential-boundary tests for live Microsoft authority."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
import pytest

import microsoft_evidence.cloud as cloud_module
from microsoft_evidence.cloud import (
    MicrosoftEndpointPolicy,
    MicrosoftPermissionManifest,
    prepare_server_owned_collection_context,
)
from microsoft_evidence.live_authority import (
    EnvironmentMicrosoftCredentialResolver,
    MicrosoftClientCredentialAuthority,
    MicrosoftCredentialMaterial,
    MicrosoftLiveAuthorityError,
    MicrosoftOidcSigningKeyProvider,
    verify_microsoft_app_token,
)


UTC = timezone.utc
NOW = datetime(2026, 8, 25, 12, tzinfo=UTC)
KEY_ID = "synthetic-signing-key"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _live_prepared(*, scope=None, source_input=None):
    synthetic_endpoint = next(iter(cloud_module._ENDPOINT_POLICIES.values()))
    endpoint_values = synthetic_endpoint.model_dump(
        mode="json", exclude={"endpoint_policy_sha256"}
    )
    endpoint_values.update(
        classification="live",
        endpoint_policy_id="live-global-entra-devices-v1",
    )
    if source_input is not None:
        product, path, audience, _ = source_input
        endpoint_values.update(
            product=product,
            path_template=path,
            token_audience=audience,
            host=audience.split("://", 1)[1],
        )
    endpoint = MicrosoftEndpointPolicy(
        **endpoint_values,
        endpoint_policy_sha256=cloud_module._canonical_sha256(endpoint_values),
    )
    synthetic_manifest = next(iter(cloud_module._PERMISSION_MANIFESTS.values()))
    manifest_values = {
        field: getattr(synthetic_manifest, field)
        for field in MicrosoftPermissionManifest.model_fields
        if field != "manifest_sha256"
    }
    manifest_values.update(
        manifest_id=uuid4(),
        classification="live",
        revision="live-test-policy-v1",
        credential_reference_id="local-test-credential-reference",
        endpoint_policy_ids=(endpoint.endpoint_policy_id,),
        credential_effective_from=NOW - timedelta(days=1),
        credential_effective_until=NOW + timedelta(days=1),
        effective_from=NOW - timedelta(days=1),
        effective_until=NOW + timedelta(days=1),
    )
    if scope is not None:
        manifest_values["scope"] = scope
    if source_input is not None:
        manifest_values.update(
            audience=source_input[2],
            grants=tuple(
                cloud_module.PermissionGrant(role=role, effect="read")
                for role in source_input[3]
            ),
        )
    canonical_manifest_values = MicrosoftPermissionManifest.model_construct(
        **manifest_values,
        manifest_sha256="0" * 64,
    ).model_dump(mode="json", exclude={"manifest_sha256"})
    manifest = MicrosoftPermissionManifest(
        **manifest_values,
        manifest_sha256=cloud_module._canonical_sha256(canonical_manifest_values),
    )
    return prepare_server_owned_collection_context(
        scope=manifest.scope,
        endpoint=endpoint,
        manifest=manifest,
        now=NOW,
    )


def _claims(prepared, **updates):
    values = {
        "iss": prepared.expected_issuers[0],
        "aud": prepared.audience,
        "iat": int((NOW - timedelta(minutes=1)).timestamp()),
        "nbf": int((NOW - timedelta(minutes=1)).timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "tid": str(prepared.scope.tenant_id),
        "azp": str(prepared.application_id),
        "oid": str(prepared.service_principal_id),
        "roles": list(prepared.expected_roles),
    }
    values.update(updates)
    return values


def _token(prepared, *, key=PRIVATE_KEY, **updates) -> str:
    return jwt.encode(
        _claims(prepared, **updates),
        key,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


class _Keys:
    def __init__(self, key=PRIVATE_KEY.public_key()):
        self.key = key
        self.calls = []

    def resolve(self, **values):
        self.calls.append(values)
        return self.key


def test_signature_verified_app_token_can_authorize_without_retaining_token() -> None:
    prepared = _live_prepared()
    keys = _Keys()
    raw = _token(prepared)

    verified = verify_microsoft_app_token(
        access_token=raw,
        prepared=prepared,
        signing_keys=keys,
        now=NOW,
    )

    assert verified.activation_allowed is True
    assert verified.cryptographic_verification == "verified"
    assert verified.credential_acquisition_verified is True
    assert verified.roles == prepared.expected_roles
    assert raw not in verified.model_dump_json()
    assert keys.calls == [
        {
            "authority_host": "login.microsoftonline.com",
            "tenant_id": prepared.scope.tenant_id,
            "signing_key_id": KEY_ID,
            "algorithm": "RS256",
        }
    ]


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"iss": "https://invalid.example/tenant/v2.0"}, "issuer"),
        ({"tid": str(UUID(int=99))}, "tenant"),
        ({"azp": str(UUID(int=98))}, "application"),
        ({"oid": str(UUID(int=97))}, "service principal"),
        ({"roles": []}, "roles"),
        ({"roles": ["Device.Read.All", "Device.Read.All"]}, "roles"),
        ({"scp": "Device.Read"}, "delegated"),
        ({"exp": int(NOW.timestamp())}, "expired"),
        ({"nbf": int((NOW + timedelta(seconds=1)).timestamp())}, "not yet"),
    ),
)
def test_live_token_claim_mismatch_fails_closed(changes, message) -> None:
    prepared = _live_prepared()

    with pytest.raises(MicrosoftLiveAuthorityError, match=message):
        verify_microsoft_app_token(
            access_token=_token(prepared, **changes),
            prepared=prepared,
            signing_keys=_Keys(),
            now=NOW,
        )


def test_wrong_signing_key_and_synthetic_policy_cannot_authorize() -> None:
    prepared = _live_prepared()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(MicrosoftLiveAuthorityError, match="signature"):
        verify_microsoft_app_token(
            access_token=_token(prepared),
            prepared=prepared,
            signing_keys=_Keys(other_key.public_key()),
            now=NOW,
        )

    synthetic = cloud_module.prepare_collection_context(
        scope=next(iter(cloud_module._PERMISSION_MANIFESTS.values())).scope,
        endpoint_policy_id=cloud_module.SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID,
        permission_manifest_id=cloud_module.SYNTHETIC_PERMISSION_MANIFEST_ID,
        now=NOW,
    )
    with pytest.raises(MicrosoftLiveAuthorityError, match="live server-owned"):
        verify_microsoft_app_token(
            access_token=_token(prepared),
            prepared=synthetic,
            signing_keys=_Keys(),
            now=NOW,
        )


def test_credential_reference_is_resolved_transiently_and_token_is_redacted() -> None:
    prepared = _live_prepared()
    raw = _token(prepared)
    resolved = []

    class Resolver:
        def resolve(self, reference):
            resolved.append(reference)
            return MicrosoftCredentialMaterial(
                kind="client_secret", value="synthetic-ephemeral-credential"
            )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(
            f"https://login.microsoftonline.com/{prepared.scope.tenant_id}"
            "/oauth2/v2.0/token"
        )
        body = request.content.decode()
        assert "synthetic-ephemeral-credential" in body
        assert f"client_id={prepared.application_id}" in body
        return httpx.Response(200, json={"access_token": raw, "token_type": "Bearer"})

    authority = MicrosoftClientCredentialAuthority(
        credential_resolver=Resolver(),
        signing_keys=_Keys(),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    lease = authority.acquire(prepared=prepared, now=NOW)

    assert resolved == [prepared.credential_reference_id]
    assert lease.verified.activation_allowed is True
    assert raw not in repr(lease)
    assert "synthetic-ephemeral-credential" not in repr(lease)
    assert lease.authorization_header() == f"Bearer {raw}"


def test_provider_failure_never_echoes_response_or_credential_material() -> None:
    prepared = _live_prepared()

    class Resolver:
        def resolve(self, _reference):
            return MicrosoftCredentialMaterial(
                kind="client_secret", value="synthetic-ephemeral-credential"
            )

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                401,
                text="synthetic-ephemeral-credential should never escape",
            )
        )
    )
    authority = MicrosoftClientCredentialAuthority(
        credential_resolver=Resolver(),
        signing_keys=_Keys(),
        client=client,
    )

    with pytest.raises(MicrosoftLiveAuthorityError) as captured:
        authority.acquire(prepared=prepared, now=NOW)

    message = str(captured.value)
    assert "status 401" in message
    assert "synthetic-ephemeral-credential" not in message


def test_environment_resolver_uses_only_allowlisted_references_and_redacts() -> None:
    resolver = EnvironmentMicrosoftCredentialResolver(
        references={"configured-reference": ("client_secret", "MS_TEST_CREDENTIAL")},
        environment={"MS_TEST_CREDENTIAL": "synthetic-ephemeral-credential"},
    )

    material = resolver.resolve("configured-reference")

    assert material.reveal_for_token_request() == "synthetic-ephemeral-credential"
    assert "synthetic-ephemeral-credential" not in repr(material)
    with pytest.raises(MicrosoftLiveAuthorityError, match="not configured"):
        resolver.resolve("caller-selected-reference")


def test_oidc_signing_key_provider_closes_discovery_host_and_caches_key() -> None:
    prepared = _live_prepared()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key(), as_dict=True)
    jwk.update(kid=KEY_ID, alg="RS256", use="sig")
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys"
                },
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(
            200,
            json={"keys": [jwk]},
            headers={"Content-Type": "application/json"},
        )

    provider = MicrosoftOidcSigningKeyProvider(
        client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    first = provider.resolve(
        authority_host="login.microsoftonline.com",
        tenant_id=prepared.scope.tenant_id,
        signing_key_id=KEY_ID,
        algorithm="RS256",
    )
    second = provider.resolve(
        authority_host="login.microsoftonline.com",
        tenant_id=prepared.scope.tenant_id,
        signing_key_id=KEY_ID,
        algorithm="RS256",
    )

    assert first is second
    assert len(calls) == 2
    assert (
        verify_microsoft_app_token(
            access_token=_token(prepared),
            prepared=prepared,
            signing_keys=provider,
            now=NOW,
        ).activation_allowed
        is True
    )
    assert len(calls) == 2


def test_oidc_signing_key_provider_rejects_foreign_jwks_and_redacts_body() -> None:
    prepared = _live_prepared()
    foreign = MicrosoftOidcSigningKeyProvider(
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    json={"jwks_uri": "https://evil.example/keys"},
                    headers={"Content-Type": "application/json"},
                )
            )
        )
    )
    with pytest.raises(MicrosoftLiveAuthorityError, match="not allowed"):
        foreign.resolve(
            authority_host="login.microsoftonline.com",
            tenant_id=prepared.scope.tenant_id,
            signing_key_id=KEY_ID,
            algorithm="RS256",
        )

    body = "synthetic signing provider body must not escape"
    failed = MicrosoftOidcSigningKeyProvider(
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(503, text=body)
            )
        )
    )
    with pytest.raises(MicrosoftLiveAuthorityError) as captured:
        failed.resolve(
            authority_host="login.microsoftonline.com",
            tenant_id=prepared.scope.tenant_id,
            signing_key_id=KEY_ID,
            algorithm="RS256",
        )
    assert body not in str(captured.value)
