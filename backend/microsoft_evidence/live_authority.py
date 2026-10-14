"""Server-owned live Microsoft token acquisition and verification boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import os
import re
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import jwt
from pydantic import model_validator

from evidence_types import NonEmptyText, Sha256, StrictModel

from .cloud import PreparedCollectionContext, cloud_profile


def _require_utc(name: str, value: datetime) -> None:
    if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")


class MicrosoftLiveAuthorityError(RuntimeError):
    """Live authority could not be proved without exposing provider details."""


class MicrosoftTokenRequestError(MicrosoftLiveAuthorityError):
    """Token endpoint rejection, without retaining its body or credentials."""

    def __init__(self, status):
        self.status = status
        super().__init__(f"Microsoft token acquisition failed with status {status}")


class MicrosoftTokenTimeout(MicrosoftLiveAuthorityError):
    """Token request deadline elapsed; no provider content is retained."""


class MicrosoftTokenTransportFailure(MicrosoftLiveAuthorityError):
    """Token HTTP transport failed; the underlying exception stays private."""


class MicrosoftCredentialMaterial:
    """Transient client credential material that is always redacted in output."""

    __slots__ = ("_value", "kind")

    def __init__(
        self, *, kind: Literal["client_secret", "client_assertion"], value: str
    ):
        if kind not in ("client_secret", "client_assertion") or not value:
            raise ValueError("resolved credential material cannot be empty")
        self.kind = kind
        self._value = value

    def reveal_for_token_request(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"<{type(self).__name__} kind={self.kind!r} value=<redacted>>"

    __str__ = __repr__


class MicrosoftCredentialResolver(Protocol):
    """Resolve one server-owned reference without storing material in policy."""

    def resolve(self, credential_reference_id: str) -> MicrosoftCredentialMaterial: ...


class EnvironmentMicrosoftCredentialResolver:
    """Resolve only configured references from process environment variables."""

    def __init__(
        self,
        *,
        references: Mapping[
            str, tuple[Literal["client_secret", "client_assertion"], str]
        ],
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if not references:
            raise ValueError("Microsoft credential reference map cannot be empty")
        for reference_id, (kind, variable) in references.items():
            if (
                kind not in ("client_secret", "client_assertion")
                or not reference_id.strip()
                or not re.fullmatch(r"[A-Z][A-Z0-9_]*", variable)
            ):
                raise ValueError(
                    "Microsoft credential reference configuration is invalid"
                )
        self._references = dict(references)
        self._environment = environment if environment is not None else os.environ

    def resolve(self, credential_reference_id: str) -> MicrosoftCredentialMaterial:
        configured = self._references.get(credential_reference_id)
        if configured is None:
            raise MicrosoftLiveAuthorityError(
                "Microsoft credential reference is not configured"
            )
        kind, variable = configured
        value = self._environment.get(variable, "")
        if not value:
            raise MicrosoftLiveAuthorityError(
                "Microsoft credential reference could not be resolved"
            )
        return MicrosoftCredentialMaterial(kind=kind, value=value)


class MicrosoftSigningKeyProvider(Protocol):
    """Return one trusted public verification key for a closed cloud and key ID."""

    def resolve(
        self,
        *,
        authority_host: str,
        tenant_id: UUID,
        signing_key_id: str,
        algorithm: str,
    ) -> Any: ...


class MicrosoftOidcSigningKeyProvider:
    """Fetch and cache RSA signing keys through closed-host OIDC discovery."""

    def __init__(self, *, client: httpx.Client, timeout_seconds: float = 10.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Microsoft signing-key timeout must be positive")
        self._client = client
        self._timeout = timeout_seconds
        self._cache: dict[tuple[str, UUID, str, str], Any] = {}

    def resolve(
        self,
        *,
        authority_host: str,
        tenant_id: UUID,
        signing_key_id: str,
        algorithm: str,
    ) -> Any:
        if algorithm != "RS256" or not signing_key_id:
            raise MicrosoftLiveAuthorityError(
                "Microsoft signing key request is not allowed"
            )
        cache_key = (authority_host, tenant_id, signing_key_id, algorithm)
        if cache_key in self._cache:
            return self._cache[cache_key]
        metadata_url = (
            f"https://{authority_host}/{tenant_id}"
            "/v2.0/.well-known/openid-configuration"
        )
        metadata = self._get_json(metadata_url, kind="discovery")
        jwks_uri = metadata.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise MicrosoftLiveAuthorityError(
                "Microsoft OIDC discovery schema is invalid"
            )
        parsed = urlsplit(jwks_uri)
        if (
            parsed.scheme != "https"
            or parsed.hostname != authority_host
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
            or parsed.path != "/common/discovery/v2.0/keys"
        ):
            raise MicrosoftLiveAuthorityError(
                "Microsoft signing-key endpoint is not allowed"
            )
        jwks = self._get_json(jwks_uri, kind="signing-key")
        keys = jwks.get("keys")
        if not isinstance(keys, list):
            raise MicrosoftLiveAuthorityError("Microsoft signing-key schema is invalid")
        for value in keys:
            if (
                isinstance(value, dict)
                and value.get("kid") == signing_key_id
                and value.get("kty") == "RSA"
                and value.get("alg", "RS256") == algorithm
                and value.get("use", "sig") == "sig"
            ):
                try:
                    key = jwt.PyJWK.from_dict(value, algorithm=algorithm).key
                except (jwt.PyJWTError, ValueError) as exc:
                    raise MicrosoftLiveAuthorityError(
                        "Microsoft signing key is invalid"
                    ) from exc
                self._cache[cache_key] = key
                return key
        raise MicrosoftLiveAuthorityError("Microsoft signing key was not found")

    def _get_json(self, url: str, *, kind: str) -> Mapping[str, object]:
        try:
            response = self._client.get(
                url,
                headers={"Accept": "application/json"},
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            raise MicrosoftLiveAuthorityError(
                f"Microsoft {kind} request timed out"
            ) from exc
        if response.status_code != 200:
            raise MicrosoftLiveAuthorityError(
                f"Microsoft {kind} request failed with status {response.status_code}"
            )
        if response.headers.get("Content-Type", "").split(";", 1)[0].casefold() != (
            "application/json"
        ):
            raise MicrosoftLiveAuthorityError(
                f"Microsoft {kind} response content type is invalid"
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise MicrosoftLiveAuthorityError(
                f"Microsoft {kind} response JSON is invalid"
            ) from exc
        if not isinstance(payload, dict):
            raise MicrosoftLiveAuthorityError(
                f"Microsoft {kind} response schema is invalid"
            )
        return payload


class VerifiedMicrosoftAppToken(StrictModel):
    """Serializable authority result that never contains the bearer token."""

    schema_version: Literal[1] = 1
    scope_sha256: Sha256
    permission_manifest_id: UUID
    permission_manifest_sha256: Sha256
    endpoint_policy_id: NonEmptyText
    endpoint_policy_sha256: Sha256
    tenant_id: UUID
    application_id: UUID
    service_principal_id: UUID
    issuer: NonEmptyText
    audience: NonEmptyText
    roles: tuple[NonEmptyText, ...]
    algorithm: Literal["RS256"]
    signing_key_id: NonEmptyText
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    credential_reference_id: NonEmptyText
    cryptographic_verification: Literal["verified"] = "verified"
    credential_acquisition_verified: Literal[True] = True
    activation_allowed: Literal[True] = True

    @model_validator(mode="after")
    def validate_times(self) -> VerifiedMicrosoftAppToken:
        for name in ("issued_at", "not_before", "expires_at"):
            _require_utc(name, getattr(self, name))
        if max(self.issued_at, self.not_before) >= self.expires_at:
            raise ValueError("verified token validity interval is empty")
        return self


class MicrosoftAccessTokenLease:
    """Ephemeral bearer token plus its verified, serializable authority result."""

    __slots__ = ("_access_token", "verified")

    def __init__(self, *, access_token: str, verified: VerifiedMicrosoftAppToken):
        if not access_token:
            raise ValueError("access token cannot be empty")
        self._access_token = access_token
        self.verified = verified

    def authorization_header(self) -> str:
        return f"Bearer {self._access_token}"

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} access_token=<redacted> "
            f"expires_at={self.verified.expires_at.isoformat()}>"
        )

    __str__ = __repr__


def _timestamp(value: object, *, name: str) -> datetime:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MicrosoftLiveAuthorityError(f"Microsoft token {name} claim is invalid")
    return datetime.fromtimestamp(value, tz=timezone.utc)


def _scope_sha256(prepared: PreparedCollectionContext) -> str:
    encoded = prepared.scope.model_dump_json().encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_microsoft_app_token(
    *,
    access_token: str,
    prepared: PreparedCollectionContext,
    signing_keys: MicrosoftSigningKeyProvider,
    now: datetime,
) -> VerifiedMicrosoftAppToken:
    """Verify signature and exact app-only authority without retaining the token."""

    _require_utc("now", now)
    if prepared.classification != "live":
        raise MicrosoftLiveAuthorityError(
            "live token verification requires live server-owned policy"
        )
    try:
        header = jwt.get_unverified_header(access_token)
    except jwt.PyJWTError as exc:
        raise MicrosoftLiveAuthorityError("Microsoft token header is invalid") from exc
    algorithm = header.get("alg")
    signing_key_id = header.get("kid")
    if algorithm not in prepared.allowed_algorithms or not isinstance(
        signing_key_id, str
    ):
        raise MicrosoftLiveAuthorityError(
            "Microsoft token algorithm or signing key is not allowed"
        )
    profile = cloud_profile(prepared.scope.cloud)
    key = signing_keys.resolve(
        authority_host=profile.authority_host,
        tenant_id=prepared.scope.tenant_id,
        signing_key_id=signing_key_id,
        algorithm=algorithm,
    )
    try:
        claims = jwt.decode(
            access_token,
            key=key,
            algorithms=list(prepared.allowed_algorithms),
            audience=prepared.audience,
            options={
                "require": [
                    "iss",
                    "aud",
                    "iat",
                    "nbf",
                    "exp",
                    "tid",
                    "azp",
                    "oid",
                    "roles",
                ],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise MicrosoftLiveAuthorityError(
            "Microsoft token signature or audience is invalid"
        ) from exc

    issuer = claims.get("iss")
    tenant_id = claims.get("tid")
    application_id = claims.get("azp")
    service_principal_id = claims.get("oid")
    roles = claims.get("roles")
    delegated_scope = claims.get("scp")
    if issuer not in prepared.expected_issuers:
        raise MicrosoftLiveAuthorityError("Microsoft token issuer is invalid")
    if str(tenant_id) != str(prepared.scope.tenant_id):
        raise MicrosoftLiveAuthorityError("Microsoft token tenant is invalid")
    if str(application_id) != str(prepared.application_id):
        raise MicrosoftLiveAuthorityError("Microsoft token application is invalid")
    if str(service_principal_id) != str(prepared.service_principal_id):
        raise MicrosoftLiveAuthorityError(
            "Microsoft token service principal is invalid"
        )
    if delegated_scope is not None:
        raise MicrosoftLiveAuthorityError(
            "delegated Microsoft token scopes are not allowed"
        )
    if (
        not isinstance(roles, list)
        or not all(isinstance(role, str) for role in roles)
        or len(set(roles)) != len(roles)
        or tuple(sorted(roles)) != tuple(prepared.expected_roles)
    ):
        raise MicrosoftLiveAuthorityError("Microsoft token roles are invalid")
    issued_at = _timestamp(claims.get("iat"), name="issued-at")
    not_before = _timestamp(claims.get("nbf"), name="not-before")
    expires_at = _timestamp(claims.get("exp"), name="expiry")
    if now < max(issued_at, not_before):
        raise MicrosoftLiveAuthorityError("Microsoft token is not yet valid")
    if now >= expires_at:
        raise MicrosoftLiveAuthorityError("Microsoft token has expired")
    return VerifiedMicrosoftAppToken(
        scope_sha256=_scope_sha256(prepared),
        permission_manifest_id=prepared.permission_manifest_id,
        permission_manifest_sha256=prepared.permission_manifest_sha256,
        endpoint_policy_id=prepared.endpoint.endpoint_policy_id,
        endpoint_policy_sha256=prepared.endpoint.endpoint_policy_sha256,
        tenant_id=prepared.scope.tenant_id,
        application_id=prepared.application_id,
        service_principal_id=prepared.service_principal_id,
        issuer=issuer,
        audience=prepared.audience,
        roles=tuple(sorted(roles)),
        algorithm=algorithm,
        signing_key_id=signing_key_id,
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        credential_reference_id=prepared.credential_reference_id,
    )


class MicrosoftClientCredentialAuthority:
    """Acquire one app token from a closed authority and verify it immediately."""

    def __init__(
        self,
        *,
        credential_resolver: MicrosoftCredentialResolver,
        signing_keys: MicrosoftSigningKeyProvider,
        client: httpx.Client,
        timeout_seconds: float = 15.0,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Microsoft token timeout must be positive")
        self._credential_resolver = credential_resolver
        self._signing_keys = signing_keys
        self._client = client
        self._timeout = timeout_seconds

    def acquire(
        self, *, prepared: PreparedCollectionContext, now: datetime
    ) -> MicrosoftAccessTokenLease:
        _require_utc("now", now)
        if prepared.classification != "live":
            raise MicrosoftLiveAuthorityError(
                "live acquisition requires live server-owned policy"
            )
        material = self._credential_resolver.resolve(prepared.credential_reference_id)
        profile = cloud_profile(prepared.scope.cloud)
        url = (
            f"https://{profile.authority_host}/{prepared.scope.tenant_id}"
            "/oauth2/v2.0/token"
        )
        form: dict[str, str] = {
            "client_id": str(prepared.application_id),
            "grant_type": "client_credentials",
            "scope": f"{prepared.audience}/.default",
        }
        if material.kind == "client_secret":
            form["client_secret"] = material.reveal_for_token_request()
        else:
            form.update(
                client_assertion=material.reveal_for_token_request(),
                client_assertion_type=(
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                ),
            )
        try:
            response = self._client.post(url, data=form, timeout=self._timeout)
        except httpx.TimeoutException as exc:
            raise MicrosoftLiveAuthorityError(
                "Microsoft token acquisition timed out"
            ) from exc
        if response.status_code != 200:
            raise MicrosoftTokenRequestError(response.status_code)
        try:
            payload: Mapping[str, object] = response.json()
            token = payload["access_token"]
            token_type = payload["token_type"]
        except (KeyError, TypeError, ValueError) as exc:
            raise MicrosoftLiveAuthorityError(
                "Microsoft token response schema is invalid"
            ) from exc
        if not isinstance(token, str) or str(token_type).casefold() != "bearer":
            raise MicrosoftLiveAuthorityError(
                "Microsoft token response schema is invalid"
            )
        verified = verify_microsoft_app_token(
            access_token=token,
            prepared=prepared,
            signing_keys=self._signing_keys,
            now=now,
        )
        return MicrosoftAccessTokenLease(access_token=token, verified=verified)


__all__ = [
    "EnvironmentMicrosoftCredentialResolver",
    "MicrosoftAccessTokenLease",
    "MicrosoftClientCredentialAuthority",
    "MicrosoftCredentialMaterial",
    "MicrosoftCredentialResolver",
    "MicrosoftLiveAuthorityError",
    "MicrosoftOidcSigningKeyProvider",
    "MicrosoftSigningKeyProvider",
    "VerifiedMicrosoftAppToken",
    "verify_microsoft_app_token",
]
