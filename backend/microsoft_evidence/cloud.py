"""Closed Microsoft cloud, endpoint, and permission-policy preparation.

This module validates immutable server-owned policy. Token acquisition and
cryptographic verification live in ``live_authority``. The synthetic claim
interface remains non-authorizing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Literal, NoReturn
from uuid import UUID

from pydantic import model_validator

from microsoft_evidence.contracts import Cloud, MicrosoftEvidenceScope, Product
from evidence_types import NonEmptyText, Sha256, StrictModel


SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID = "synthetic-global-entra-devices-v1"
SYNTHETIC_PERMISSION_MANIFEST_ID = UUID("40000000-0000-4000-8000-000000000004")
_SYNTHETIC_TENANT_ID = UUID("10000000-0000-4000-8000-000000000001")
_SYNTHETIC_APPLICATION_ID = UUID("20000000-0000-4000-8000-000000000002")
_SYNTHETIC_SERVICE_PRINCIPAL_ID = UUID("30000000-0000-4000-8000-000000000003")


def _require_utc(name: str, value: datetime) -> None:
    if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")


def _sorted_unique(name: str, values: tuple[str, ...]) -> None:
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{name} must be sorted and unique")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


class MicrosoftCloudProfile(StrictModel):
    schema_version: Literal[2] = 2
    cloud: Cloud
    authority_host: NonEmptyText
    issuer_templates: tuple[NonEmptyText, ...]
    profile_sha256: Sha256

    @model_validator(mode="after")
    def validate_profile(self) -> MicrosoftCloudProfile:
        _sorted_unique("issuer_templates", self.issuer_templates)
        payload = self.model_dump(mode="json", exclude={"profile_sha256"})
        if self.profile_sha256 != _canonical_sha256(payload):
            raise ValueError("cloud profile hash does not match its content")
        return self


def _profile(
    *, cloud: Cloud, authority_host: str, issuer_templates: tuple[str, ...]
) -> MicrosoftCloudProfile:
    payload = {
        "schema_version": 2,
        "cloud": cloud,
        "authority_host": authority_host,
        "issuer_templates": issuer_templates,
    }
    return MicrosoftCloudProfile(**payload, profile_sha256=_canonical_sha256(payload))


_CLOUD_PROFILES: dict[Cloud, MicrosoftCloudProfile] = {
    "global": _profile(
        cloud="global",
        authority_host="login.microsoftonline.com",
        issuer_templates=("https://login.microsoftonline.com/{tenant_id}/v2.0",),
    ),
    "us_government": _profile(
        cloud="us_government",
        authority_host="login.microsoftonline.us",
        issuer_templates=("https://login.microsoftonline.us/{tenant_id}/v2.0",),
    ),
    "china": _profile(
        cloud="china",
        authority_host="login.chinacloudapi.cn",
        issuer_templates=("https://login.chinacloudapi.cn/{tenant_id}/v2.0",),
    ),
}


def cloud_profile(cloud: Cloud) -> MicrosoftCloudProfile:
    """Return one immutable server-owned closed-cloud profile."""

    return _CLOUD_PROFILES[cloud]


class MicrosoftEndpointPolicy(StrictModel):
    schema_version: Literal[1] = 1
    endpoint_policy_id: NonEmptyText
    endpoint_policy_sha256: Sha256
    classification: Literal["synthetic", "live"] = "synthetic"
    cloud: Cloud
    product: Product
    scheme: Literal["https"] = "https"
    host: NonEmptyText
    port: Literal[443] = 443
    path_template: NonEmptyText
    api_versions: tuple[NonEmptyText, ...]
    token_audience: NonEmptyText
    allowed_query_parameter_names: tuple[NonEmptyText, ...] = ()
    continuation_query_parameter_names: tuple[NonEmptyText, ...] = ()

    @model_validator(mode="after")
    def validate_policy(self) -> MicrosoftEndpointPolicy:
        _sorted_unique("api_versions", self.api_versions)
        _sorted_unique(
            "allowed_query_parameter_names", self.allowed_query_parameter_names
        )
        _sorted_unique(
            "continuation_query_parameter_names",
            self.continuation_query_parameter_names,
        )
        if not self.path_template.startswith("/") or "?" in self.path_template:
            raise ValueError(
                "endpoint path template must be an absolute query-free path"
            )
        payload = self.model_dump(mode="json", exclude={"endpoint_policy_sha256"})
        if self.endpoint_policy_sha256 != _canonical_sha256(payload):
            raise ValueError("endpoint policy hash does not match its content")
        return self


def _endpoint_policy(
    *,
    endpoint_policy_id: str,
    cloud: Cloud,
    product: Product,
    host: str,
    path_template: str,
    api_versions: tuple[str, ...],
    token_audience: str,
    allowed_query_parameter_names: tuple[str, ...] = (),
    continuation_query_parameter_names: tuple[str, ...] = (),
) -> MicrosoftEndpointPolicy:
    payload = {
        "schema_version": 1,
        "endpoint_policy_id": endpoint_policy_id,
        "classification": "synthetic",
        "cloud": cloud,
        "product": product,
        "scheme": "https",
        "host": host,
        "port": 443,
        "path_template": path_template,
        "api_versions": api_versions,
        "token_audience": token_audience,
        "allowed_query_parameter_names": allowed_query_parameter_names,
        "continuation_query_parameter_names": continuation_query_parameter_names,
    }
    return MicrosoftEndpointPolicy(
        **payload, endpoint_policy_sha256=_canonical_sha256(payload)
    )


_ENDPOINT_POLICIES: dict[tuple[Cloud, Product, str], MicrosoftEndpointPolicy] = {
    ("global", "entra", SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID): _endpoint_policy(
        endpoint_policy_id=SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID,
        cloud="global",
        product="entra",
        host="graph.microsoft.com",
        path_template="/v1.0/devices",
        api_versions=("v1.0",),
        token_audience="https://graph.microsoft.com",
        allowed_query_parameter_names=("$filter", "$select"),
        continuation_query_parameter_names=("$skiptoken",),
    )
}


class PermissionGrant(StrictModel):
    role: NonEmptyText
    effect: Literal["read", "write"]


class MicrosoftConnectionScope(StrictModel):
    """Collection authority for the evidence workspace, without agency inference."""

    scope_kind: Literal["connection-v1"] = "connection-v1"
    connection_id: UUID
    tenant_id: UUID
    cloud: Cloud
    product: Product
    input_kind: NonEmptyText
    origin: Literal["synthetic", "lab"]
    scope_reference: NonEmptyText
    provenance: NonEmptyText

    @model_validator(mode="after")
    def validate_identifiers(self):
        if not self.connection_id.int or not self.tenant_id.int:
            raise ValueError("Connection and tenant identifiers must be nonzero")
        return self


CollectionScope = MicrosoftEvidenceScope | MicrosoftConnectionScope


class MicrosoftPermissionManifest(StrictModel):
    schema_version: Literal[1] = 1
    manifest_id: UUID
    manifest_sha256: Sha256
    classification: Literal["synthetic", "live"] = "synthetic"
    revision: NonEmptyText
    scope: CollectionScope
    application_id: UUID
    service_principal_id: UUID
    credential_reference_id: NonEmptyText
    endpoint_policy_ids: tuple[NonEmptyText, ...]
    audience: NonEmptyText
    grants: tuple[PermissionGrant, ...]
    elevated_permission_approval_id: NonEmptyText | None = None
    elevated_permission_approval_sha256: Sha256 | None = None
    allowed_algorithms: tuple[Literal["RS256"], ...]
    consent_record_id: NonEmptyText
    consent_record_sha256: Sha256
    consent_active: bool
    credential_effective_from: datetime
    credential_effective_until: datetime
    credential_revoked: bool
    authorization_healthy: bool
    effective_from: datetime
    effective_until: datetime

    @model_validator(mode="after")
    def validate_manifest(self) -> MicrosoftPermissionManifest:
        _sorted_unique("endpoint_policy_ids", self.endpoint_policy_ids)
        _sorted_unique("allowed_algorithms", self.allowed_algorithms)
        roles = tuple(grant.role for grant in self.grants)
        _sorted_unique("permission grant roles", roles)
        if not self.grants:
            raise ValueError("permission manifest requires nonempty grants")
        if any(grant.effect != "read" for grant in self.grants):
            raise ValueError("permission manifest must be read-only")
        approval = (
            self.elevated_permission_approval_id,
            self.elevated_permission_approval_sha256,
        )
        has_write_class_role = any(".ReadWrite.All" in role for role in roles)
        if has_write_class_role and any(value is None for value in approval):
            raise ValueError(
                "write-class Microsoft role requires elevated permission approval"
            )
        if not has_write_class_role and any(value is not None for value in approval):
            raise ValueError(
                "elevated permission approval requires a write-class Microsoft role"
            )
        if not self.allowed_algorithms:
            raise ValueError("permission manifest requires an allowed algorithm")
        for name in (
            "credential_effective_from",
            "credential_effective_until",
            "effective_from",
            "effective_until",
        ):
            _require_utc(name, getattr(self, name))
        if self.credential_effective_from >= self.credential_effective_until:
            raise ValueError("credential interval is inverted")
        if self.effective_from >= self.effective_until:
            raise ValueError("permission manifest interval is inverted")
        payload = self.model_dump(mode="json", exclude={"manifest_sha256"})
        if self.manifest_sha256 != _canonical_sha256(payload):
            raise ValueError("permission manifest hash does not match its content")
        return self


def _synthetic_manifest_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": 1,
        "manifest_id": SYNTHETIC_PERMISSION_MANIFEST_ID,
        "classification": "synthetic",
        "revision": "synthetic-permission-manifest-v1",
        "scope": MicrosoftEvidenceScope(
            agency_id="synthetic-agency-20",
            tenant_id=_SYNTHETIC_TENANT_ID,
            cloud="global",
            data_location="synthetic-au-west",
            product="entra",
        ),
        "application_id": _SYNTHETIC_APPLICATION_ID,
        "service_principal_id": _SYNTHETIC_SERVICE_PRINCIPAL_ID,
        "credential_reference_id": "synthetic-credential-reference-not-a-secret",
        "endpoint_policy_ids": (SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID,),
        "audience": "https://graph.microsoft.com",
        "grants": (PermissionGrant(role="Device.Read.All", effect="read"),),
        "allowed_algorithms": ("RS256",),
        "consent_record_id": "synthetic-consent-record",
        "consent_record_sha256": "c" * 64,
        "consent_active": True,
        "credential_effective_from": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "credential_effective_until": datetime(2027, 1, 1, tzinfo=timezone.utc),
        "credential_revoked": False,
        "authorization_healthy": True,
        "effective_from": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "effective_until": datetime(2027, 1, 1, tzinfo=timezone.utc),
    }
    serializable = {
        key: (
            value.model_dump(mode="json")
            if isinstance(value, StrictModel)
            else [item.model_dump(mode="json") for item in value]
            if isinstance(value, tuple) and value and isinstance(value[0], StrictModel)
            else value.isoformat()
            if isinstance(value, datetime)
            else str(value)
            if isinstance(value, UUID)
            else value
        )
        for key, value in payload.items()
    }
    payload["manifest_sha256"] = _canonical_sha256(serializable)
    return payload


def _build_synthetic_manifest(**updates: object) -> MicrosoftPermissionManifest:
    payload = _synthetic_manifest_payload()
    payload.update(updates)
    serializable = MicrosoftPermissionManifest.model_construct(
        **{**payload, "manifest_sha256": "0" * 64}
    ).model_dump(mode="json", exclude={"manifest_sha256"})
    payload["manifest_sha256"] = _canonical_sha256(serializable)
    return MicrosoftPermissionManifest(**payload)


_PERMISSION_MANIFESTS: dict[UUID, MicrosoftPermissionManifest] = {
    SYNTHETIC_PERMISSION_MANIFEST_ID: _build_synthetic_manifest()
}


class PreparedEndpointContext(StrictModel):
    endpoint_policy_id: NonEmptyText
    endpoint_policy_sha256: Sha256
    scheme: Literal["https"]
    host: NonEmptyText
    port: Literal[443]
    path_template: NonEmptyText
    api_versions: tuple[NonEmptyText, ...]
    allowed_query_parameter_names: tuple[NonEmptyText, ...]
    paging_query_parameter_names: tuple[NonEmptyText, ...]


class PreparedCollectionContext(StrictModel):
    scope: CollectionScope
    endpoint: PreparedEndpointContext
    permission_manifest_id: UUID
    permission_manifest_sha256: Sha256
    application_id: UUID
    service_principal_id: UUID
    credential_reference_id: NonEmptyText
    audience: NonEmptyText
    expected_issuers: tuple[NonEmptyText, ...]
    expected_roles: tuple[NonEmptyText, ...]
    elevated_permission_approval_id: NonEmptyText | None = None
    elevated_permission_approval_sha256: Sha256 | None = None
    allowed_algorithms: tuple[NonEmptyText, ...]
    classification: Literal["synthetic", "live"]
    cryptographic_verification: Literal["not_performed"] = "not_performed"
    credential_acquisition_verified: Literal[False] = False
    activation_allowed: Literal[False] = False


def prepare_collection_context(
    *,
    scope: MicrosoftEvidenceScope,
    endpoint_policy_id: str,
    permission_manifest_id: UUID,
    now: datetime,
) -> PreparedCollectionContext:
    """Prepare non-activating collection policy from server-owned registries."""

    _require_utc("now", now)
    endpoint = _ENDPOINT_POLICIES.get((scope.cloud, scope.product, endpoint_policy_id))
    if endpoint is None:
        raise ValueError("endpoint policy is not configured for scope")
    manifest = _PERMISSION_MANIFESTS.get(permission_manifest_id)
    if manifest is None:
        raise ValueError("permission manifest is not configured")
    return prepare_server_owned_collection_context(
        scope=scope,
        endpoint=endpoint,
        manifest=manifest,
        now=now,
    )


def prepare_server_owned_collection_context(
    *,
    scope: CollectionScope,
    endpoint: MicrosoftEndpointPolicy,
    manifest: MicrosoftPermissionManifest,
    now: datetime,
) -> PreparedCollectionContext:
    """Validate exact server-owned policy without accepting a caller URL or role."""

    _require_utc("now", now)
    if endpoint.cloud != scope.cloud or endpoint.product != scope.product:
        raise ValueError("endpoint policy is not configured for scope")
    if endpoint.classification != manifest.classification:
        raise ValueError("endpoint and permission classifications do not match")
    if manifest.scope != scope:
        raise ValueError("permission manifest scope does not match collection scope")
    if endpoint.endpoint_policy_id not in manifest.endpoint_policy_ids:
        raise ValueError("permission manifest does not allow endpoint policy")
    if manifest.audience != endpoint.token_audience:
        raise ValueError("permission manifest audience does not match endpoint")
    if not manifest.consent_active:
        raise ValueError("permission manifest consent is inactive")
    if manifest.credential_revoked:
        raise ValueError("configured credential reference is revoked")
    if not manifest.authorization_healthy:
        raise ValueError("permission manifest authorization is unhealthy")
    if not manifest.effective_from <= now < manifest.effective_until:
        raise ValueError("permission manifest is not current")
    if not (
        manifest.credential_effective_from <= now < manifest.credential_effective_until
    ):
        raise ValueError("configured credential reference is not current")
    profile = cloud_profile(scope.cloud)
    expected_issuers = tuple(
        template.format(tenant_id=scope.tenant_id)
        for template in profile.issuer_templates
    )
    return PreparedCollectionContext(
        scope=scope,
        endpoint=PreparedEndpointContext(
            endpoint_policy_id=endpoint.endpoint_policy_id,
            endpoint_policy_sha256=endpoint.endpoint_policy_sha256,
            scheme=endpoint.scheme,
            host=endpoint.host,
            port=endpoint.port,
            path_template=endpoint.path_template,
            api_versions=endpoint.api_versions,
            allowed_query_parameter_names=endpoint.allowed_query_parameter_names,
            paging_query_parameter_names=(endpoint.continuation_query_parameter_names),
        ),
        permission_manifest_id=manifest.manifest_id,
        permission_manifest_sha256=manifest.manifest_sha256,
        application_id=manifest.application_id,
        service_principal_id=manifest.service_principal_id,
        credential_reference_id=manifest.credential_reference_id,
        audience=manifest.audience,
        expected_issuers=expected_issuers,
        expected_roles=tuple(grant.role for grant in manifest.grants),
        elevated_permission_approval_id=manifest.elevated_permission_approval_id,
        elevated_permission_approval_sha256=(
            manifest.elevated_permission_approval_sha256
        ),
        allowed_algorithms=manifest.allowed_algorithms,
        classification=manifest.classification,
    )


class SyntheticAppTokenClaims(StrictModel):
    classification: Literal["synthetic"] = "synthetic"
    issuer: NonEmptyText
    tenant_id: UUID
    audience: NonEmptyText
    application_id: UUID
    service_principal_id: UUID
    roles: tuple[NonEmptyText, ...]
    scopes: tuple[NonEmptyText, ...] = ()
    algorithm: NonEmptyText
    presented_signing_key_id: NonEmptyText
    issued_at: datetime
    not_before: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def validate_claims(self) -> SyntheticAppTokenClaims:
        _sorted_unique("roles", self.roles)
        _sorted_unique("scopes", self.scopes)
        for name in ("issued_at", "not_before", "expires_at"):
            _require_utc(name, getattr(self, name))
        if self.issued_at > self.expires_at or self.not_before > self.expires_at:
            raise ValueError("synthetic token validity times are inverted")
        return self


class SyntheticTokenAssessment(StrictModel):
    compatible: bool
    reasons: tuple[NonEmptyText, ...]
    classification: Literal["synthetic"] = "synthetic"
    cryptographic_verification: Literal["not_performed"] = "not_performed"
    credential_acquisition_verified: Literal[False] = False
    activation_allowed: Literal[False] = False


def assess_synthetic_token_fixture(
    *,
    prepared: PreparedCollectionContext,
    fixture: SyntheticAppTokenClaims,
    now: datetime,
) -> SyntheticTokenAssessment:
    """Assess synthetic claim compatibility without authorizing collection."""

    _require_utc("now", now)
    reasons: list[str] = []
    if fixture.issuer not in prepared.expected_issuers:
        reasons.append("issuer")
    if fixture.tenant_id != prepared.scope.tenant_id:
        reasons.append("tenant")
    if fixture.audience != prepared.audience:
        reasons.append("audience")
    if fixture.application_id != prepared.application_id:
        reasons.append("application")
    if fixture.service_principal_id != prepared.service_principal_id:
        reasons.append("service_principal")
    if fixture.roles != prepared.expected_roles:
        reasons.append("roles")
    if fixture.scopes:
        reasons.append("delegated_scopes")
    if fixture.algorithm not in prepared.allowed_algorithms:
        reasons.append("algorithm")
    if now < max(fixture.issued_at, fixture.not_before):
        reasons.append("not_yet_valid")
    if now >= fixture.expires_at:
        reasons.append("expired")
    return SyntheticTokenAssessment(
        compatible=not reasons,
        reasons=tuple(reasons),
    )


class LiveTokenAuthorityUnavailable(RuntimeError):
    """A caller used the legacy guard without configured authority adapters."""


def require_live_collection_authority() -> NoReturn:
    """Fail closed when no prepared policy and verified token lease were supplied."""

    raise LiveTokenAuthorityUnavailable(
        "live collection requires server-owned verification and acquisition adapters"
    )


__all__ = [
    "SYNTHETIC_ENTRA_ENDPOINT_POLICY_ID",
    "SYNTHETIC_PERMISSION_MANIFEST_ID",
    "LiveTokenAuthorityUnavailable",
    "MicrosoftCloudProfile",
    "MicrosoftEndpointPolicy",
    "MicrosoftPermissionManifest",
    "PermissionGrant",
    "PreparedCollectionContext",
    "PreparedEndpointContext",
    "SyntheticAppTokenClaims",
    "SyntheticTokenAssessment",
    "assess_synthetic_token_fixture",
    "cloud_profile",
    "prepare_collection_context",
    "prepare_server_owned_collection_context",
    "require_live_collection_authority",
]
