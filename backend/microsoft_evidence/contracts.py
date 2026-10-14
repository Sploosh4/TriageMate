"""Fail-closed contracts for synthetic Microsoft collection evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID

from pydantic import Field, model_validator

from evidence_types import NonEmptyText, Sha256, StrictModel


Cloud = Literal["global", "us_government", "china"]
Product = Literal["entra", "intune", "defender"]
OriginClassification = Literal["synthetic", "public", "live_provider"]


def _require_utc(name: str, value: datetime) -> None:
    if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")


def _sorted_unique(name: str, values: tuple[str, ...]) -> None:
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{name} must be sorted and unique")


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_schema_v2_request_text(*, endpoint_template: str, query: str) -> None:
    """Allow only relative endpoints and non-checkpoint canonical query fields."""
    endpoint = urlsplit(endpoint_template)
    if endpoint.scheme or endpoint.netloc or endpoint.query or endpoint.fragment:
        raise ValueError("endpoint_template contains secret or continuation material")
    parsed = urlsplit(query)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("canonical_query contains secret or continuation material")
    allowed_query_fields = {
        "filter",
        "select",
        "expand",
        "orderby",
        "top",
        "count",
        "search",
    }
    sensitive_query_fields = {
        "skiptoken",
        "deltatoken",
        "continuationtoken",
        "cursor",
        "checkpoint",
        "accesstoken",
        "clientsecret",
        "apikey",
        "sharedaccesssignature",
        "sig",
        "code",
    }
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        normalized_key = (
            key.casefold().replace("$", "").replace("_", "").replace("-", "")
        )
        lowered_value = value.casefold()
        if (
            normalized_key in sensitive_query_fields
            or normalized_key not in allowed_query_fields
            or any(
                marker in lowered_value
                for marker in ("bearer ", "access_token", "client_secret", "api_key")
            )
        ):
            raise ValueError("canonical_query contains secret or continuation material")


class MicrosoftEvidenceScope(StrictModel):
    agency_id: NonEmptyText
    tenant_id: UUID
    cloud: Cloud
    data_location: NonEmptyText
    product: Product


class OriginStamp(StrictModel):
    classification: OriginClassification
    provenance: NonEmptyText
    licence: str = ""
    ingress_id: UUID
    ingress_sha256: Sha256

    @model_validator(mode="after")
    def validate_licence(self) -> OriginStamp:
        if self.classification == "public" and not self.licence.strip():
            raise ValueError("public evidence requires a licence")
        if self.classification != "public" and self.licence:
            raise ValueError("only public evidence can carry a licence")
        return self


class PopulationManifest(StrictModel):
    """Digest and completeness claim for one provider population."""

    manifest_sha256: Sha256
    cardinality: int = Field(strict=True, ge=0)
    complete: bool


class ProviderMembershipScope(StrictModel):
    """Provider-enforced dimensions that define collection membership."""

    token_audience: NonEmptyText
    application_roles: tuple[NonEmptyText, ...]
    rbac_scope_tag_ids: tuple[NonEmptyText, ...] = ()
    device_group_ids: tuple[NonEmptyText, ...] = ()
    inherited_group_ids: tuple[NonEmptyText, ...] = ()
    supported_platforms: tuple[NonEmptyText, ...]
    supported_states: tuple[NonEmptyText, ...]
    licensed_population: PopulationManifest
    provider_enforced_agency_scope: bool

    @model_validator(mode="after")
    def validate_dimensions(self) -> ProviderMembershipScope:
        for name in (
            "application_roles",
            "supported_platforms",
            "supported_states",
        ):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        for name in (
            "application_roles",
            "rbac_scope_tag_ids",
            "device_group_ids",
            "inherited_group_ids",
            "supported_platforms",
            "supported_states",
        ):
            _sorted_unique(name, getattr(self, name))
        return self


class EffectiveScopeAttestation(StrictModel):
    schema_version: Literal[1, 2] = 1
    attestation_id: UUID
    attestation_sha256: Sha256
    scope: MicrosoftEvidenceScope
    attester_issuer: NonEmptyText
    attester_principal_id: NonEmptyText
    application_id: NonEmptyText
    service_principal_id: NonEmptyText
    effective_roles: tuple[NonEmptyText, ...]
    provider_configuration_revision: NonEmptyText
    observed_at: datetime
    ingested_at: datetime | None = None
    effective_from: datetime
    effective_until: datetime
    expires_at: datetime
    provider_authenticated: bool
    effective_scope_complete: bool
    unenumerable_facets: tuple[NonEmptyText, ...] = ()
    effective_membership_scope: ProviderMembershipScope | None = None
    origin: OriginStamp

    @model_validator(mode="after")
    def validate_attestation(self) -> EffectiveScopeAttestation:
        for name in (
            "observed_at",
            "effective_from",
            "effective_until",
            "expires_at",
        ):
            _require_utc(name, getattr(self, name))
        if self.ingested_at is not None:
            _require_utc("ingested_at", self.ingested_at)
            if self.ingested_at < self.observed_at:
                raise ValueError("attestation ingestion cannot precede observation")
        if not self.effective_from <= self.observed_at <= self.effective_until:
            raise ValueError("attestation observation must be inside its interval")
        if self.expires_at < self.effective_until:
            raise ValueError("attestation expiry cannot precede its effective end")
        _sorted_unique("effective_roles", self.effective_roles)
        _sorted_unique("unenumerable_facets", self.unenumerable_facets)
        if self.schema_version == 2 and self.effective_membership_scope is None:
            raise ValueError(
                "schema v2 attestation requires effective membership scope"
            )
        if self.schema_version == 2 and self.ingested_at is None:
            raise ValueError("schema v2 attestation requires trusted ingestion time")
        if self.schema_version == 2 and (
            self.attestation_sha256 != canonical_attestation_sha256(self)
        ):
            raise ValueError("attestation hash is not canonical")
        return self


class ProviderScopeStabilityProof(StrictModel):
    """Provider-authenticated proof that one scope revision stayed unchanged."""

    schema_version: Literal[1] = 1
    proof_id: UUID
    proof_sha256: Sha256
    scope: MicrosoftEvidenceScope
    provider_configuration_revision: NonEmptyText
    observed_at: datetime
    ingested_at: datetime | None = None
    effective_from: datetime
    effective_until: datetime
    provider_authenticated: bool
    origin: OriginStamp

    @model_validator(mode="after")
    def validate_proof(self) -> ProviderScopeStabilityProof:
        for name in ("observed_at", "effective_from", "effective_until"):
            _require_utc(name, getattr(self, name))
        if self.ingested_at is not None:
            _require_utc("ingested_at", self.ingested_at)
            if self.ingested_at < self.observed_at:
                raise ValueError("scope stability ingestion cannot precede observation")
        if not self.effective_from <= self.effective_until:
            raise ValueError("scope stability interval is inverted")
        if self.observed_at < self.effective_until:
            raise ValueError(
                "scope stability proof must be observed after its interval"
            )
        if self.proof_sha256 != canonical_stability_proof_sha256(self):
            raise ValueError("scope stability proof hash is not canonical")
        return self


class MembershipCoverageContract(StrictModel):
    schema_version: Literal[1, 2] = 1
    coverage_id: UUID
    coverage_sha256: Sha256
    scope: MicrosoftEvidenceScope
    application_id: NonEmptyText
    service_principal_id: NonEmptyText
    endpoint_template: NonEmptyText
    api_version: NonEmptyText
    request_scope_sha256: Sha256
    granted_roles: tuple[NonEmptyText, ...]
    provider_enforced_agency_scope: bool
    required_membership_scope: ProviderMembershipScope | None = None
    canonical_query: str = ""
    filters: tuple[NonEmptyText, ...] = ()
    selected_fields: tuple[NonEmptyText, ...] = ()
    consistency_mode: str = ""
    inactive_record_semantics: str = ""
    deleted_record_semantics: str = ""
    lookback_seconds: int = Field(default=0, strict=True, ge=0)
    retention_seconds: int = Field(default=0, strict=True, ge=0)
    expected_asset_policy_id: str = ""
    expected_asset_policy_sha256: Sha256 | None = None
    pre_attestation: EffectiveScopeAttestation
    post_attestation: EffectiveScopeAttestation | None = None
    scope_stability_proof: ProviderScopeStabilityProof | None = None
    origin: OriginStamp

    @model_validator(mode="after")
    def validate_coverage(self) -> MembershipCoverageContract:
        _sorted_unique("granted_roles", self.granted_roles)
        _sorted_unique("filters", self.filters)
        _sorted_unique("selected_fields", self.selected_fields)
        if self.pre_attestation.scope != self.scope:
            raise ValueError("attestation scope does not match coverage scope")
        if self.post_attestation and self.post_attestation.scope != self.scope:
            raise ValueError("post-attestation scope does not match coverage scope")
        if self.origin != self.pre_attestation.origin:
            raise ValueError("coverage and attestation origin must match")
        if self.post_attestation and self.origin != self.post_attestation.origin:
            raise ValueError("coverage and post-attestation origin must match")
        if self.scope_stability_proof is not None:
            proof = self.scope_stability_proof
            if proof.scope != self.scope or proof.origin != self.origin:
                raise ValueError(
                    "scope stability proof boundary does not match coverage"
                )
        if self.schema_version == 2:
            if self.required_membership_scope is None:
                raise ValueError("schema v2 coverage requires membership scope")
            if self.pre_attestation.schema_version != 2:
                raise ValueError("schema v2 coverage requires schema v2 attestation")
            required_text = (
                self.canonical_query,
                self.consistency_mode,
                self.inactive_record_semantics,
                self.deleted_record_semantics,
                self.expected_asset_policy_id,
            )
            if not all(value.strip() for value in required_text):
                raise ValueError("schema v2 coverage requires canonical request fields")
            if not self.selected_fields or self.expected_asset_policy_sha256 is None:
                raise ValueError("schema v2 coverage requires fields and asset policy")
            if self.post_attestation and self.post_attestation.schema_version != 2:
                raise ValueError(
                    "schema v2 coverage requires schema v2 post-attestation"
                )
            required_roles: dict[Product, frozenset[str]] = {
                "entra": frozenset(("Device.Read.All", "Directory.Read.All")),
                "intune": frozenset(("DeviceManagementManagedDevices.Read.All",)),
                "defender": frozenset(("Machine.Read.All", "Machine.ReadWrite.All")),
            }
            if not required_roles[self.scope.product].intersection(self.granted_roles):
                raise ValueError("schema v2 coverage lacks a product-appropriate role")
            _validate_schema_v2_request_text(
                endpoint_template=self.endpoint_template,
                query=self.canonical_query,
            )
            for name, value in (
                ("endpoint_template", self.endpoint_template),
                ("canonical_query", self.canonical_query),
            ):
                lowered = value.casefold()
                forbidden = (
                    "bearer ",
                    "authorization",
                    "$skiptoken",
                    "skiptoken",
                    "continuationtoken",
                    "@odata.nextlink",
                    "access_token",
                    "client_secret",
                    "clientsecret",
                    "api_key",
                    "apikey",
                    "sharedaccesssignature",
                    "sig=",
                    "://",
                )
                if any(marker in lowered for marker in forbidden):
                    raise ValueError(f"{name} contains secret or continuation material")
            if self.coverage_sha256 != canonical_coverage_sha256(self):
                raise ValueError("coverage hash is not canonical")
        return self


def canonical_request_scope_sha256(coverage: MembershipCoverageContract) -> str:
    """Hash the complete schema-v2 request and membership boundary."""
    if coverage.schema_version != 2 or coverage.required_membership_scope is None:
        raise ValueError("canonical request scope requires schema v2 coverage")
    payload = {
        "domain": "triagemate.microsoft.request-scope.v2",
        "scope": coverage.scope.model_dump(mode="json"),
        "application_id": coverage.application_id,
        "service_principal_id": coverage.service_principal_id,
        "endpoint_template": coverage.endpoint_template,
        "api_version": coverage.api_version,
        "canonical_query": coverage.canonical_query,
        "filters": coverage.filters,
        "selected_fields": coverage.selected_fields,
        "consistency_mode": coverage.consistency_mode,
        "required_membership_scope": coverage.required_membership_scope.model_dump(
            mode="json"
        ),
        "inactive_record_semantics": coverage.inactive_record_semantics,
        "deleted_record_semantics": coverage.deleted_record_semantics,
        "lookback_seconds": coverage.lookback_seconds,
        "retention_seconds": coverage.retention_seconds,
        "expected_asset_policy_id": coverage.expected_asset_policy_id,
        "expected_asset_policy_sha256": coverage.expected_asset_policy_sha256,
    }
    return _sha256(payload)


class CoverageEvaluation(StrictModel):
    absence_authoritative: bool
    reason: NonEmptyText
    collection_started_at: datetime
    collection_completed_at: datetime
    attestation_id: UUID
    attestation_sha256: Sha256
    post_attestation_id: UUID | None = None
    post_attestation_sha256: Sha256 | None = None
    coverage_id: UUID
    coverage_sha256: Sha256

    @model_validator(mode="after")
    def validate_interval(self) -> CoverageEvaluation:
        _require_utc("collection_started_at", self.collection_started_at)
        _require_utc("collection_completed_at", self.collection_completed_at)
        if self.collection_started_at > self.collection_completed_at:
            raise ValueError("collection start cannot follow completion")
        if (self.post_attestation_id is None) != (self.post_attestation_sha256 is None):
            raise ValueError("post-attestation ID and hash must appear together")
        return self


def evaluate_coverage(
    coverage: MembershipCoverageContract,
    *,
    collection_started_at: datetime,
    collection_completed_at: datetime,
) -> CoverageEvaluation:
    """Evaluate whether one complete collection may prove record absence."""
    _require_utc("collection_started_at", collection_started_at)
    _require_utc("collection_completed_at", collection_completed_at)
    attestation = coverage.pre_attestation
    reason = "scope is current, authenticated, complete, and provider-enforced"
    authoritative = True
    if collection_started_at > collection_completed_at:
        raise ValueError("collection start cannot follow completion")
    if coverage.schema_version == 2 and (
        coverage.request_scope_sha256 != canonical_request_scope_sha256(coverage)
    ):
        authoritative = False
        reason = "request scope hash is not canonical"
    elif coverage.schema_version == 2 and (
        coverage.required_membership_scope is None
        or attestation.effective_membership_scope != coverage.required_membership_scope
        or coverage.required_membership_scope.application_roles
        != coverage.granted_roles
        or not coverage.required_membership_scope.licensed_population.complete
        or not coverage.required_membership_scope.provider_enforced_agency_scope
        or bool(attestation.unenumerable_facets)
    ):
        authoritative = False
        reason = "effective membership scope is incomplete or not provider-enforced"
    elif attestation.application_id != coverage.application_id:
        authoritative = False
        reason = "application identity does not match the scope attestation"
    elif attestation.service_principal_id != coverage.service_principal_id:
        authoritative = False
        reason = "service-principal identity does not match the scope attestation"
    elif attestation.effective_roles != coverage.granted_roles:
        authoritative = False
        reason = "granted roles do not match the effective scope attestation"
    elif not attestation.provider_authenticated:
        authoritative = False
        reason = "scope attestation is not provider-authenticated"
    elif not attestation.effective_scope_complete or attestation.unenumerable_facets:
        authoritative = False
        reason = "effective provider scope is incomplete"
    elif not coverage.provider_enforced_agency_scope:
        authoritative = False
        reason = "agency scope is not enforced by the provider"
    elif not (
        attestation.effective_from
        <= collection_started_at
        <= collection_completed_at
        <= attestation.effective_until
    ):
        authoritative = False
        reason = "scope attestation is not current for the collection interval"
    elif (
        coverage.schema_version == 2 and attestation.observed_at > collection_started_at
    ):
        authoritative = False
        reason = "pre-collection attestation must be observed before collection"
    elif coverage.schema_version == 2 and (
        attestation.ingested_at is None
        or attestation.ingested_at > collection_started_at
    ):
        authoritative = False
        reason = "pre-collection attestation must be ingested before collection"
    elif coverage.schema_version == 2 and (
        coverage.post_attestation is None and coverage.scope_stability_proof is None
    ):
        authoritative = False
        reason = "post-collection scope stability evidence is required"
    elif (
        coverage.schema_version == 2
        and coverage.post_attestation is not None
        and (
            coverage.post_attestation.observed_at < collection_completed_at
            or coverage.post_attestation.ingested_at is None
            or coverage.post_attestation.ingested_at < collection_completed_at
        )
    ):
        authoritative = False
        reason = "post-collection attestation must be observed after collection"
    elif (
        coverage.schema_version == 2
        and coverage.scope_stability_proof is not None
        and (
            not coverage.scope_stability_proof.provider_authenticated
            or coverage.scope_stability_proof.ingested_at is None
            or coverage.scope_stability_proof.ingested_at < collection_completed_at
            or coverage.scope_stability_proof.provider_configuration_revision
            != attestation.provider_configuration_revision
            or not (
                coverage.scope_stability_proof.effective_from
                <= collection_started_at
                <= collection_completed_at
                <= coverage.scope_stability_proof.effective_until
                <= coverage.scope_stability_proof.observed_at
            )
        )
    ):
        authoritative = False
        reason = "provider scope stability proof is not authoritative for collection"
    elif coverage.post_attestation is not None and (
        coverage.post_attestation.provider_configuration_revision
        != attestation.provider_configuration_revision
    ):
        authoritative = False
        reason = "provider scope changed during collection"
    elif coverage.post_attestation is not None and (
        not coverage.post_attestation.provider_authenticated
        or not coverage.post_attestation.effective_scope_complete
        or bool(coverage.post_attestation.unenumerable_facets)
    ):
        authoritative = False
        reason = "post-collection scope attestation is incomplete"
    elif coverage.post_attestation is not None and (
        coverage.post_attestation.application_id != coverage.application_id
        or coverage.post_attestation.service_principal_id
        != coverage.service_principal_id
        or coverage.post_attestation.effective_roles != coverage.granted_roles
    ):
        authoritative = False
        reason = "post-collection identity or roles changed"
    elif (
        coverage.schema_version == 2
        and coverage.post_attestation is not None
        and (
            coverage.post_attestation.effective_membership_scope
            != coverage.required_membership_scope
            or coverage.post_attestation.effective_membership_scope is None
            or not coverage.post_attestation.effective_membership_scope.licensed_population.complete
            or not coverage.post_attestation.effective_membership_scope.provider_enforced_agency_scope
        )
    ):
        authoritative = False
        reason = "post-collection membership scope is incomplete or changed"
    elif coverage.post_attestation is not None and not (
        coverage.post_attestation.effective_from
        <= collection_started_at
        <= collection_completed_at
        <= coverage.post_attestation.effective_until
    ):
        authoritative = False
        reason = "post-collection attestation does not cover the collection interval"
    if authoritative and coverage.schema_version == 2:
        digests_are_canonical = (
            attestation.attestation_sha256 == canonical_attestation_sha256(attestation)
            and coverage.coverage_sha256 == canonical_coverage_sha256(coverage)
            and (
                coverage.post_attestation is None
                or coverage.post_attestation.attestation_sha256
                == canonical_attestation_sha256(coverage.post_attestation)
            )
            and (
                coverage.scope_stability_proof is None
                or coverage.scope_stability_proof.proof_sha256
                == canonical_stability_proof_sha256(coverage.scope_stability_proof)
            )
        )
        if not digests_are_canonical:
            authoritative = False
            reason = "coverage or scope-attestation hash is not canonical"
    return CoverageEvaluation(
        absence_authoritative=authoritative,
        reason=reason,
        collection_started_at=collection_started_at,
        collection_completed_at=collection_completed_at,
        attestation_id=attestation.attestation_id,
        attestation_sha256=attestation.attestation_sha256,
        post_attestation_id=(
            coverage.post_attestation.attestation_id
            if coverage.post_attestation is not None
            else None
        ),
        post_attestation_sha256=(
            coverage.post_attestation.attestation_sha256
            if coverage.post_attestation is not None
            else None
        ),
        coverage_id=coverage.coverage_id,
        coverage_sha256=coverage.coverage_sha256,
    )


def continuation_evidence_sha256(
    *,
    page_sequence: int,
    request_scope_sha256: str,
    request_cursor_sha256: str | None,
    response_sha256: str,
    continuation_state: Literal["successor", "terminal", "unknown"],
    successor_cursor_sha256: str | None,
) -> str:
    """Hash cursor continuity without retaining cursor values or URLs."""
    return _sha256(
        {
            "domain": "triagemate.microsoft.page-continuation-evidence.v2",
            "page_sequence": page_sequence,
            "request_scope_sha256": request_scope_sha256,
            "request_cursor_sha256": request_cursor_sha256,
            "response_sha256": response_sha256,
            "continuation_state": continuation_state,
            "successor_cursor_sha256": successor_cursor_sha256,
        }
    )


class CollectionPageEvidence(StrictModel):
    schema_version: Literal[1, 2] = 1
    page_sequence: int = Field(strict=True, ge=0)
    request_scope_sha256: Sha256
    request_cursor_sha256: Sha256 | None = None
    response_sha256: Sha256
    observed_at: datetime
    completion: Literal["complete", "failed"] | None = None
    continuation_state: Literal["successor", "terminal", "unknown"] | None = None
    successor_cursor_sha256: Sha256 | None = None
    terminal_checkpoint_sha256: Sha256 | None = None
    continuation_evidence_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def validate_time(self) -> CollectionPageEvidence:
        _require_utc("observed_at", self.observed_at)
        if self.schema_version == 1:
            if self.completion is None:
                raise ValueError("schema v1 page requires completion")
            return self
        if self.completion is not None:
            raise ValueError("schema v2 page derives completion from continuation")
        if self.continuation_state is None or self.continuation_evidence_sha256 is None:
            raise ValueError("schema v2 page requires continuation evidence")
        expected = continuation_evidence_sha256(
            page_sequence=self.page_sequence,
            request_scope_sha256=self.request_scope_sha256,
            request_cursor_sha256=self.request_cursor_sha256,
            response_sha256=self.response_sha256,
            continuation_state=self.continuation_state,
            successor_cursor_sha256=self.successor_cursor_sha256,
        )
        if self.continuation_evidence_sha256 != expected:
            raise ValueError("page continuation evidence hash is not canonical")
        if self.continuation_state == "successor" and (
            self.successor_cursor_sha256 is None
            or self.terminal_checkpoint_sha256 is not None
        ):
            raise ValueError("successor page requires successor cursor only")
        if self.continuation_state == "terminal" and (
            self.successor_cursor_sha256 is not None
            or self.terminal_checkpoint_sha256 != expected
        ):
            raise ValueError("terminal page requires its derived checkpoint only")
        if self.continuation_state == "unknown" and (
            self.successor_cursor_sha256 is not None
            or self.terminal_checkpoint_sha256 is not None
        ):
            raise ValueError("unknown continuation cannot claim successor or terminal")
        return self


class CollectionBatch(StrictModel):
    schema_version: Literal[1, 2] = 1
    batch_id: UUID
    scope: MicrosoftEvidenceScope
    generation_id: UUID
    sequence: int = Field(strict=True, ge=0)
    kind: Literal["baseline", "delta"]
    predecessor_batch_id: UUID | None = None
    predecessor_batch_sha256: Sha256 | None = None
    coverage: MembershipCoverageContract
    coverage_evaluation: CoverageEvaluation
    request_started_at: datetime
    completed_at: datetime
    observation_started_at: datetime
    observation_ended_at: datetime
    status: Literal[
        "complete",
        "failed",
        "partial",
        "unauthorized",
        "throttled",
        "unsupported",
        "unlicensed",
    ]
    pages: tuple[CollectionPageEvidence, ...]
    page_chain_complete: bool
    terminal_checkpoint_sha256: Sha256 | None = None
    normalized_record_count: int = Field(strict=True, ge=0)
    normalized_manifest_sha256: Sha256 | None = None
    connector_version: NonEmptyText
    schema_revision: NonEmptyText
    freshness_deadline: datetime
    retention_until: datetime
    origin: OriginStamp
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_batch(self) -> CollectionBatch:
        for name in (
            "request_started_at",
            "completed_at",
            "observation_started_at",
            "observation_ended_at",
            "freshness_deadline",
            "retention_until",
        ):
            _require_utc(name, getattr(self, name))
        if self.scope != self.coverage.scope or self.origin != self.coverage.origin:
            raise ValueError("batch scope and origin must match coverage")
        if self.schema_version == 2 and self.coverage.schema_version != 2:
            raise ValueError("schema v2 batch requires schema v2 coverage")
        evaluation = self.coverage_evaluation
        attestation = self.coverage.pre_attestation
        post_attestation = self.coverage.post_attestation
        if (
            evaluation.coverage_id != self.coverage.coverage_id
            or evaluation.coverage_sha256 != self.coverage.coverage_sha256
            or evaluation.attestation_id != attestation.attestation_id
            or evaluation.attestation_sha256 != attestation.attestation_sha256
            or evaluation.post_attestation_id
            != (post_attestation.attestation_id if post_attestation else None)
            or evaluation.post_attestation_sha256
            != (post_attestation.attestation_sha256 if post_attestation else None)
        ):
            raise ValueError("coverage evaluation does not match batch coverage")
        if (
            evaluation.collection_started_at != self.request_started_at
            or evaluation.collection_completed_at != self.completed_at
        ):
            raise ValueError("coverage evaluation does not match collection interval")
        expected_evaluation = evaluate_coverage(
            self.coverage,
            collection_started_at=self.request_started_at,
            collection_completed_at=self.completed_at,
        )
        if evaluation != expected_evaluation:
            raise ValueError("coverage evaluation is not the derived result")
        if self.kind == "baseline" and (
            self.sequence != 0
            or self.predecessor_batch_id is not None
            or self.predecessor_batch_sha256 is not None
        ):
            raise ValueError("baseline must start at sequence zero without predecessor")
        if self.kind == "delta" and (
            self.sequence == 0
            or self.predecessor_batch_id is None
            or self.predecessor_batch_sha256 is None
        ):
            raise ValueError("delta requires a predecessor and positive sequence")
        if self.status != "complete" and self.coverage_evaluation.absence_authoritative:
            raise ValueError("non-complete batch cannot carry authoritative absence")
        if self.status == "complete":
            if not self.pages or not self.page_chain_complete:
                raise ValueError(
                    "complete batch requires a complete nonempty page chain"
                )
            if self.schema_version == 1 and any(
                page.completion != "complete" for page in self.pages
            ):
                raise ValueError("complete batch cannot contain a failed page")
            if self.terminal_checkpoint_sha256 is None:
                raise ValueError("complete batch requires a checkpoint digest")
            if self.normalized_manifest_sha256 is None:
                raise ValueError("complete batch requires a normalized manifest")
        sequences = tuple(page.page_sequence for page in self.pages)
        if sequences != tuple(range(len(self.pages))):
            raise ValueError("page sequence must be contiguous")
        if any(
            page.request_scope_sha256 != self.coverage.request_scope_sha256
            for page in self.pages
        ):
            raise ValueError("page request scope must match coverage")
        if self.schema_version == 2:
            if any(page.schema_version != 2 for page in self.pages):
                raise ValueError("schema v2 batch requires schema v2 pages")
            derived_complete = bool(self.pages)
            for position, page in enumerate(self.pages):
                expected_cursor = (
                    None
                    if position == 0
                    else self.pages[position - 1].successor_cursor_sha256
                )
                if page.request_cursor_sha256 != expected_cursor:
                    raise ValueError("page cursor chain is not contiguous")
                is_final = position == len(self.pages) - 1
                if is_final != (page.continuation_state == "terminal"):
                    derived_complete = False
                if not is_final and page.continuation_state != "successor":
                    derived_complete = False
                if page.continuation_state == "unknown":
                    derived_complete = False
            derived_checkpoint = (
                self.pages[-1].terminal_checkpoint_sha256
                if derived_complete and self.pages
                else None
            )
            if self.page_chain_complete != derived_complete:
                raise ValueError("page-chain completeness is not the derived result")
            if self.terminal_checkpoint_sha256 != derived_checkpoint:
                raise ValueError("batch checkpoint does not match final page")
            page_times = tuple(page.observed_at for page in self.pages)
            if page_times != tuple(sorted(page_times)) or any(
                not (
                    self.request_started_at <= observed_at <= self.completed_at
                    and self.observation_started_at
                    <= observed_at
                    <= self.observation_ended_at
                )
                for observed_at in page_times
            ):
                raise ValueError("page observations must be monotonic inside the batch")
        if not (
            self.observation_started_at
            <= self.observation_ended_at
            <= self.completed_at
            <= self.freshness_deadline
            <= self.retention_until
        ):
            raise ValueError("batch times are not ordered")
        if self.request_started_at > self.completed_at:
            raise ValueError("request start cannot follow completion")
        if self.schema_version == 2 and (
            self.content_sha256 != canonical_collection_batch_sha256(self)
        ):
            raise ValueError("batch content hash is not canonical")
        return self


def _canonical_contract_sha256(
    value: StrictModel,
    *,
    excluded_field: str,
    domain: str,
) -> str:
    return _sha256(
        {
            "domain": domain,
            "value": value.model_dump(mode="json", exclude={excluded_field}),
        }
    )


def canonical_attestation_sha256(attestation: EffectiveScopeAttestation) -> str:
    return _canonical_contract_sha256(
        attestation,
        excluded_field="attestation_sha256",
        domain="triagemate.microsoft.effective-scope-attestation.v2",
    )


def canonical_stability_proof_sha256(proof: ProviderScopeStabilityProof) -> str:
    return _canonical_contract_sha256(
        proof,
        excluded_field="proof_sha256",
        domain="triagemate.microsoft.scope-stability-proof.v1",
    )


def canonical_coverage_sha256(coverage: MembershipCoverageContract) -> str:
    return _canonical_contract_sha256(
        coverage,
        excluded_field="coverage_sha256",
        domain="triagemate.microsoft.membership-coverage.v2",
    )


def canonical_collection_batch_sha256(batch: CollectionBatch) -> str:
    return _canonical_contract_sha256(
        batch,
        excluded_field="content_sha256",
        domain="triagemate.microsoft.collection-batch.v2",
    )


def canonical_normalized_manifest_sha256(
    *,
    records: tuple[tuple[str, str], ...],
    tombstone_record_ids: tuple[str, ...],
) -> str:
    return _sha256(
        {
            "domain": "triagemate.microsoft.normalized-manifest.v2",
            "records": records,
            "tombstone_record_ids": tombstone_record_ids,
        }
    )
