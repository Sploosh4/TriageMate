from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from microsoft_evidence.contracts import (
    CollectionBatch,
    CollectionPageEvidence,
    EffectiveScopeAttestation,
    MembershipCoverageContract,
    MicrosoftEvidenceScope,
    OriginStamp,
    PopulationManifest,
    ProviderMembershipScope,
    ProviderScopeStabilityProof,
    CoverageEvaluation,
    canonical_attestation_sha256,
    canonical_collection_batch_sha256,
    canonical_coverage_sha256,
    canonical_request_scope_sha256,
    canonical_stability_proof_sha256,
    continuation_evidence_sha256,
    evaluate_coverage,
)


NOW = datetime(2026, 8, 24, 1, 0, tzinfo=timezone.utc)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64


def _population(**updates) -> PopulationManifest:
    values = {"manifest_sha256": HASH_D, "cardinality": 25, "complete": True}
    values.update(updates)
    return PopulationManifest(**values)


def _membership_scope(**updates) -> ProviderMembershipScope:
    values = {
        "token_audience": "https://graph.microsoft.com",
        "application_roles": ("DeviceManagementManagedDevices.Read.All",),
        "rbac_scope_tag_ids": ("scope-tag-001",),
        "device_group_ids": ("device-group-001",),
        "inherited_group_ids": (),
        "supported_platforms": ("windows",),
        "supported_states": ("active",),
        "licensed_population": _population(),
        "provider_enforced_agency_scope": True,
    }
    values.update(updates)
    return ProviderMembershipScope(**values)


def _scope() -> MicrosoftEvidenceScope:
    return MicrosoftEvidenceScope(
        agency_id="agency-wa-001",
        tenant_id=UUID("00000000-0000-4000-8000-000000000001"),
        cloud="global",
        data_location="australia",
        product="intune",
    )


def _origin() -> OriginStamp:
    return OriginStamp(
        classification="synthetic",
        provenance="TriageMate Microsoft contract fixture",
        ingress_id=UUID("00000000-0000-4000-8000-000000000002"),
        ingress_sha256=HASH_A,
    )


def _live_origin() -> OriginStamp:
    return OriginStamp(
        classification="live_provider",
        provenance="Live-origin laundering hostile contract test",
        ingress_id=UUID("00000000-0000-4000-8000-000000000099"),
        ingress_sha256=HASH_C,
    )


def _attestation(**updates) -> EffectiveScopeAttestation:
    values = {
        "attestation_id": UUID("00000000-0000-4000-8000-000000000003"),
        "attestation_sha256": HASH_B,
        "scope": _scope(),
        "attester_issuer": "synthetic-provider-attester",
        "attester_principal_id": "attester-001",
        "application_id": "app-001",
        "service_principal_id": "sp-001",
        "effective_roles": ("DeviceManagementManagedDevices.Read.All",),
        "provider_configuration_revision": "scope-revision-001",
        "observed_at": NOW - timedelta(minutes=5),
        "ingested_at": NOW - timedelta(minutes=4),
        "effective_from": NOW - timedelta(hours=1),
        "effective_until": NOW + timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=1),
        "provider_authenticated": True,
        "effective_scope_complete": True,
        "origin": _origin(),
    }
    values.update(updates)
    if values.get("schema_version") == 2:
        probe = EffectiveScopeAttestation.model_construct(**values)
        values["attestation_sha256"] = canonical_attestation_sha256(probe)
    return EffectiveScopeAttestation(**values)


def _coverage(**updates) -> MembershipCoverageContract:
    values = {
        "coverage_id": UUID("00000000-0000-4000-8000-000000000004"),
        "coverage_sha256": HASH_C,
        "scope": _scope(),
        "application_id": "app-001",
        "service_principal_id": "sp-001",
        "endpoint_template": "/deviceManagement/managedDevices",
        "api_version": "v1.0",
        "request_scope_sha256": HASH_A,
        "granted_roles": ("DeviceManagementManagedDevices.Read.All",),
        "provider_enforced_agency_scope": True,
        "pre_attestation": _attestation(),
        "origin": _origin(),
    }
    values.update(updates)
    if values.get("schema_version") == 2:
        probe = MembershipCoverageContract.model_construct(**values)
        values["coverage_sha256"] = canonical_coverage_sha256(probe)
    return MembershipCoverageContract(**values)


def _v2_coverage(**updates) -> MembershipCoverageContract:
    membership_scope = _membership_scope()
    post_attestation = _attestation(
        schema_version=2,
        attestation_id=UUID("00000000-0000-4000-8000-000000000007"),
        observed_at=NOW + timedelta(minutes=5),
        ingested_at=NOW + timedelta(minutes=6),
        effective_membership_scope=membership_scope,
    )
    values = {
        "schema_version": 2,
        "pre_attestation": _attestation(
            schema_version=2,
            effective_membership_scope=membership_scope,
        ),
        "required_membership_scope": membership_scope,
        "post_attestation": post_attestation,
        "canonical_query": "managedDevices",
        "filters": ("operatingSystem eq 'Windows'",),
        "selected_fields": ("azureADDeviceId", "id", "operatingSystem"),
        "consistency_mode": "eventual",
        "inactive_record_semantics": "included",
        "deleted_record_semantics": "explicit-tombstones",
        "lookback_seconds": 86400,
        "retention_seconds": 604800,
        "expected_asset_policy_id": "managed-windows-v1",
        "expected_asset_policy_sha256": HASH_B,
    }
    values.update(updates)
    coverage = _coverage(**values)
    coverage = coverage.model_copy(
        update={"request_scope_sha256": canonical_request_scope_sha256(coverage)}
    )
    coverage = coverage.model_copy(
        update={"coverage_sha256": canonical_coverage_sha256(coverage)}
    )
    return MembershipCoverageContract.model_validate(coverage.model_dump())


def _complete_batch(
    coverage: MembershipCoverageContract,
    evaluation: CoverageEvaluation,
    **updates,
) -> CollectionBatch:
    values = {
        "batch_id": UUID("00000000-0000-4000-8000-000000000005"),
        "scope": _scope(),
        "generation_id": UUID("00000000-0000-4000-8000-000000000006"),
        "sequence": 0,
        "kind": "baseline",
        "coverage": coverage,
        "coverage_evaluation": evaluation,
        "request_started_at": NOW,
        "completed_at": NOW + timedelta(minutes=1),
        "observation_started_at": NOW - timedelta(minutes=1),
        "observation_ended_at": NOW,
        "status": "complete",
        "pages": (
            CollectionPageEvidence(
                page_sequence=0,
                request_scope_sha256=HASH_A,
                response_sha256=HASH_B,
                observed_at=NOW,
                completion="complete",
            ),
        ),
        "page_chain_complete": True,
        "terminal_checkpoint_sha256": HASH_C,
        "normalized_record_count": 2,
        "normalized_manifest_sha256": HASH_B,
        "connector_version": "synthetic-1",
        "schema_revision": "1",
        "freshness_deadline": NOW + timedelta(hours=1),
        "retention_until": NOW + timedelta(days=1),
        "origin": _origin(),
        "content_sha256": HASH_C,
    }
    values.update(updates)
    if values.get("schema_version") == 2:
        probe = CollectionBatch.model_construct(**values)
        values["content_sha256"] = canonical_collection_batch_sha256(probe)
    return CollectionBatch(**values)


def test_batch_cannot_claim_authoritative_absence_without_matching_current_scope_attestation():
    coverage = _coverage()
    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert evaluation.absence_authoritative is True

    batch = CollectionBatch(
        batch_id=UUID("00000000-0000-4000-8000-000000000005"),
        scope=_scope(),
        generation_id=UUID("00000000-0000-4000-8000-000000000006"),
        sequence=0,
        kind="baseline",
        coverage=coverage,
        coverage_evaluation=evaluation,
        request_started_at=NOW,
        completed_at=NOW + timedelta(minutes=1),
        observation_started_at=NOW - timedelta(minutes=1),
        observation_ended_at=NOW,
        status="complete",
        pages=(
            CollectionPageEvidence(
                page_sequence=0,
                request_scope_sha256=HASH_A,
                response_sha256=HASH_B,
                observed_at=NOW,
                completion="complete",
            ),
        ),
        page_chain_complete=True,
        terminal_checkpoint_sha256=HASH_C,
        normalized_record_count=2,
        normalized_manifest_sha256=HASH_B,
        connector_version="synthetic-1",
        schema_revision="1",
        freshness_deadline=NOW + timedelta(hours=1),
        retention_until=NOW + timedelta(days=1),
        origin=_origin(),
        content_sha256=HASH_C,
    )
    assert batch.coverage_evaluation.absence_authoritative is True

    mismatched = _coverage(
        application_id="app-002",
    )
    rejected = evaluate_coverage(
        mismatched,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert rejected.absence_authoritative is False
    assert "application" in rejected.reason


def test_non_complete_batch_cannot_carry_authoritative_absence():
    coverage = _coverage()
    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )

    with pytest.raises(ValidationError, match="authoritative absence"):
        CollectionBatch(
            batch_id=UUID("00000000-0000-4000-8000-000000000005"),
            scope=_scope(),
            generation_id=UUID("00000000-0000-4000-8000-000000000006"),
            sequence=0,
            kind="baseline",
            coverage=coverage,
            coverage_evaluation=evaluation,
            request_started_at=NOW,
            completed_at=NOW + timedelta(minutes=1),
            observation_started_at=NOW - timedelta(minutes=1),
            observation_ended_at=NOW,
            status="partial",
            pages=(),
            page_chain_complete=False,
            normalized_record_count=0,
            connector_version="synthetic-1",
            schema_revision="1",
            freshness_deadline=NOW + timedelta(hours=1),
            retention_until=NOW + timedelta(days=1),
            origin=_origin(),
            content_sha256=HASH_C,
        )


def test_collection_contract_rejects_raw_provider_material():
    with pytest.raises(ValidationError, match="Extra inputs"):
        CollectionPageEvidence(
            page_sequence=0,
            request_scope_sha256=HASH_A,
            response_sha256=HASH_B,
            observed_at=NOW,
            completion="complete",
            raw_payload={"device": "must-not-be-retained"},
        )


def test_batch_rejects_an_authoritative_evaluation_from_another_coverage_contract():
    coverage = _coverage()
    forged = CoverageEvaluation(
        absence_authoritative=True,
        reason="scope is complete",
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
        attestation_id=coverage.pre_attestation.attestation_id,
        attestation_sha256=coverage.pre_attestation.attestation_sha256,
        coverage_id=UUID("00000000-0000-4000-8000-000000000099"),
        coverage_sha256=HASH_B,
    )

    with pytest.raises(ValidationError, match="coverage evaluation"):
        CollectionBatch(
            batch_id=UUID("00000000-0000-4000-8000-000000000005"),
            scope=_scope(),
            generation_id=UUID("00000000-0000-4000-8000-000000000006"),
            sequence=0,
            kind="baseline",
            coverage=coverage,
            coverage_evaluation=forged,
            request_started_at=NOW,
            completed_at=NOW + timedelta(minutes=1),
            observation_started_at=NOW - timedelta(minutes=1),
            observation_ended_at=NOW,
            status="complete",
            pages=(
                CollectionPageEvidence(
                    page_sequence=0,
                    request_scope_sha256=HASH_A,
                    response_sha256=HASH_B,
                    observed_at=NOW,
                    completion="complete",
                ),
            ),
            page_chain_complete=True,
            terminal_checkpoint_sha256=HASH_C,
            normalized_record_count=2,
            normalized_manifest_sha256=HASH_B,
            connector_version="synthetic-1",
            schema_revision="1",
            freshness_deadline=NOW + timedelta(hours=1),
            retention_until=NOW + timedelta(days=1),
            origin=_origin(),
            content_sha256=HASH_C,
        )


@pytest.mark.parametrize(
    ("post_updates", "reason_fragment"),
    [
        ({"provider_authenticated": False}, "post-collection scope attestation"),
        ({"effective_scope_complete": False}, "post-collection scope attestation"),
        (
            {"unenumerable_facets": ("defender-device-groups",)},
            "post-collection scope attestation",
        ),
    ],
)
def test_post_collection_scope_must_remain_authenticated_and_complete(
    post_updates, reason_fragment
):
    post = _attestation(
        attestation_id=UUID("00000000-0000-4000-8000-000000000007"),
        **post_updates,
    )
    coverage = _coverage(post_attestation=post)

    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )

    assert evaluation.absence_authoritative is False
    assert reason_fragment in evaluation.reason


@pytest.mark.parametrize(
    "post_updates",
    [
        {"application_id": "app-002"},
        {"service_principal_id": "sp-002"},
        {"effective_roles": ("Directory.Read.All",)},
        {
            "effective_from": NOW + timedelta(minutes=2),
            "observed_at": NOW + timedelta(minutes=2),
            "ingested_at": NOW + timedelta(minutes=3),
            "effective_until": NOW + timedelta(hours=2),
            "expires_at": NOW + timedelta(hours=2),
        },
    ],
)
def test_post_collection_attestation_must_bind_the_same_identity_roles_and_interval(
    post_updates,
):
    post = _attestation(
        attestation_id=UUID("00000000-0000-4000-8000-000000000007"),
        **post_updates,
    )
    coverage = _coverage(post_attestation=post)

    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )

    assert evaluation.absence_authoritative is False


def test_post_collection_attestation_cannot_launder_live_origin():
    post = _attestation(
        attestation_id=UUID("00000000-0000-4000-8000-000000000007"),
        origin=_live_origin(),
    )

    with pytest.raises(ValidationError, match="post-attestation origin"):
        _coverage(post_attestation=post)


def test_coverage_evaluation_binds_both_scope_attestations():
    post = _attestation(
        attestation_id=UUID("00000000-0000-4000-8000-000000000007"),
        attestation_sha256=HASH_A,
    )
    coverage = _coverage(post_attestation=post)

    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )

    assert evaluation.attestation_id == coverage.pre_attestation.attestation_id
    assert evaluation.attestation_sha256 == coverage.pre_attestation.attestation_sha256
    assert evaluation.post_attestation_id == post.attestation_id
    assert evaluation.post_attestation_sha256 == post.attestation_sha256

    with pytest.raises(ValidationError, match="coverage evaluation"):
        _complete_batch(
            coverage,
            evaluation.model_copy(update={"post_attestation_sha256": HASH_B}),
        )


def test_batch_rejects_scope_evaluation_from_a_different_collection_interval():
    coverage = _coverage()
    earlier_evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )

    with pytest.raises(ValidationError, match="collection interval"):
        _complete_batch(
            coverage,
            earlier_evaluation,
            request_started_at=NOW + timedelta(minutes=5),
            observation_started_at=NOW + timedelta(minutes=4),
            observation_ended_at=NOW + timedelta(minutes=5),
            completed_at=NOW + timedelta(minutes=6),
        )


def test_schema_v2_coverage_derives_request_scope_and_requires_exact_complete_membership():
    required = _membership_scope()
    attestation = _attestation(
        schema_version=2,
        effective_membership_scope=required,
    )
    coverage = _v2_coverage(
        pre_attestation=attestation,
        required_membership_scope=required,
        post_attestation=_attestation(
            schema_version=2,
            attestation_id=UUID("00000000-0000-4000-8000-000000000007"),
            observed_at=NOW + timedelta(minutes=5),
            ingested_at=NOW + timedelta(minutes=6),
            effective_membership_scope=required,
        ),
    )

    accepted = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert accepted.absence_authoritative is True

    incomplete = required.model_copy(
        update={"licensed_population": _population(complete=False)}
    )
    rejected = evaluate_coverage(
        coverage.model_copy(
            update={
                "pre_attestation": attestation.model_copy(
                    update={"effective_membership_scope": incomplete}
                )
            }
        ),
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert rejected.absence_authoritative is False
    assert "membership scope" in rejected.reason


def test_schema_v2_membership_scope_rejects_empty_effective_dimensions():
    for update in (
        {"application_roles": ()},
        {"supported_platforms": ()},
        {"supported_states": ()},
    ):
        with pytest.raises(ValidationError, match="must not be empty"):
            _membership_scope(**update)


def test_schema_v2_requires_post_collection_scope_stability_evidence():
    coverage = _v2_coverage().model_copy(update={"post_attestation": None})
    missing_post = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert missing_post.absence_authoritative is False
    assert "stability" in missing_post.reason

    predated_post = _v2_coverage()
    predated_post = predated_post.model_copy(
        update={
            "post_attestation": predated_post.post_attestation.model_copy(
                update={"observed_at": NOW - timedelta(minutes=1)}
            )
        }
    )
    predated = evaluate_coverage(
        predated_post,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert predated.absence_authoritative is False
    assert "after collection" in predated.reason

    late_pre = _v2_coverage()
    late_attestation = late_pre.pre_attestation.model_copy(
        update={"observed_at": NOW + timedelta(seconds=1)}
    )
    late_attestation = late_attestation.model_copy(
        update={"attestation_sha256": canonical_attestation_sha256(late_attestation)}
    )
    late_pre = late_pre.model_copy(update={"pre_attestation": late_attestation})
    late_pre = late_pre.model_copy(
        update={"coverage_sha256": canonical_coverage_sha256(late_pre)}
    )
    late_pre_result = evaluate_coverage(
        late_pre,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert late_pre_result.absence_authoritative is False
    assert "before collection" in late_pre_result.reason

    base = _v2_coverage()
    proof_values = {
        "proof_id": UUID("00000000-0000-4000-8000-000000000008"),
        "proof_sha256": HASH_A,
        "scope": base.scope,
        "provider_configuration_revision": (
            base.pre_attestation.provider_configuration_revision
        ),
        "observed_at": NOW + timedelta(minutes=5),
        "ingested_at": NOW + timedelta(minutes=6),
        "effective_from": NOW - timedelta(minutes=1),
        "effective_until": NOW + timedelta(minutes=1),
        "provider_authenticated": True,
        "origin": base.origin,
    }
    proof_probe = ProviderScopeStabilityProof.model_construct(**proof_values)
    proof_values["proof_sha256"] = canonical_stability_proof_sha256(proof_probe)
    proof = ProviderScopeStabilityProof(**proof_values)
    proof_coverage = base.model_copy(
        update={"post_attestation": None, "scope_stability_proof": proof}
    )
    proof_coverage = proof_coverage.model_copy(
        update={"coverage_sha256": canonical_coverage_sha256(proof_coverage)}
    )
    accepted_proof = evaluate_coverage(
        proof_coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert accepted_proof.absence_authoritative is True


def test_schema_v2_attestation_requires_trusted_ingestion_chronology():
    with pytest.raises(ValidationError, match="ingestion cannot precede observation"):
        _attestation(
            schema_version=2,
            effective_membership_scope=_membership_scope(),
            ingested_at=NOW - timedelta(minutes=6),
        )


def test_schema_v2_rejects_attestation_or_coverage_content_under_stale_digest():
    coverage = _v2_coverage()
    payload = coverage.model_dump()
    payload["pre_attestation"]["provider_configuration_revision"] = "changed"

    with pytest.raises(ValidationError, match="attestation hash"):
        MembershipCoverageContract.model_validate(payload)

    payload = coverage.model_dump()
    payload["canonical_query"] = "managedDevicesChanged"
    with pytest.raises(ValidationError, match="coverage hash"):
        MembershipCoverageContract.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("endpoint_template", "Bearer retained-access-token"),
        (
            "canonical_query",
            "https://graph.microsoft.com/v1.0/devices?$skiptoken=retained",
        ),
        ("canonical_query", "devices?continuationToken=retained"),
        ("canonical_query", "devices?$deltatoken=retained"),
        ("canonical_query", "devices?cursor=retained"),
        ("canonical_query", "devices?checkpoint=retained"),
        ("canonical_query", "devices?access_token=retained"),
        ("endpoint_template", "/devices?client_secret=retained"),
    ),
)
def test_schema_v2_rejects_secret_or_continuation_material(field, value):
    with pytest.raises(ValidationError, match="secret or continuation"):
        _v2_coverage(**{field: value})


def test_schema_v2_rejects_a_role_for_the_wrong_product():
    with pytest.raises(ValidationError, match="product-appropriate"):
        _v2_coverage(
            granted_roles=("Directory.Read.All",),
            required_membership_scope=_membership_scope(
                application_roles=("Directory.Read.All",)
            ),
        )


def test_schema_v2_page_observations_are_monotonic_and_inside_collection():
    coverage = _v2_coverage()
    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    terminal_evidence = continuation_evidence_sha256(
        page_sequence=0,
        request_scope_sha256=coverage.request_scope_sha256,
        request_cursor_sha256=None,
        response_sha256=HASH_B,
        continuation_state="terminal",
        successor_cursor_sha256=None,
    )
    page = CollectionPageEvidence(
        schema_version=2,
        page_sequence=0,
        request_scope_sha256=coverage.request_scope_sha256,
        response_sha256=HASH_B,
        observed_at=NOW + timedelta(days=10),
        continuation_state="terminal",
        terminal_checkpoint_sha256=terminal_evidence,
        continuation_evidence_sha256=terminal_evidence,
    )

    with pytest.raises(ValidationError, match="page observations"):
        _complete_batch(
            coverage,
            evaluation,
            schema_version=2,
            pages=(page,),
            terminal_checkpoint_sha256=terminal_evidence,
        )


def test_schema_v2_batch_content_digest_binds_page_and_connector_evidence():
    coverage = _v2_coverage()
    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    terminal_evidence = continuation_evidence_sha256(
        page_sequence=0,
        request_scope_sha256=coverage.request_scope_sha256,
        request_cursor_sha256=None,
        response_sha256=HASH_B,
        continuation_state="terminal",
        successor_cursor_sha256=None,
    )
    page = CollectionPageEvidence(
        schema_version=2,
        page_sequence=0,
        request_scope_sha256=coverage.request_scope_sha256,
        response_sha256=HASH_B,
        observed_at=NOW,
        continuation_state="terminal",
        terminal_checkpoint_sha256=terminal_evidence,
        continuation_evidence_sha256=terminal_evidence,
    )
    batch = _complete_batch(
        coverage,
        evaluation,
        schema_version=2,
        pages=(page,),
        terminal_checkpoint_sha256=terminal_evidence,
    )
    payload = batch.model_dump()
    payload["connector_version"] = "tampered"

    with pytest.raises(ValidationError, match="batch content hash"):
        CollectionBatch.model_validate(payload)


def test_schema_v2_coverage_rejects_noncanonical_or_client_side_scope():
    required = _membership_scope()
    attestation = _attestation(
        schema_version=2,
        effective_membership_scope=required,
    )
    coverage = _coverage(
        schema_version=2,
        pre_attestation=attestation,
        required_membership_scope=required,
        canonical_query="managedDevices",
        filters=("operatingSystem eq 'Windows'",),
        selected_fields=("azureADDeviceId", "id"),
        consistency_mode="eventual",
        inactive_record_semantics="included",
        deleted_record_semantics="explicit-tombstones",
        lookback_seconds=86400,
        retention_seconds=604800,
        expected_asset_policy_id="managed-windows-v1",
        expected_asset_policy_sha256=HASH_B,
    )

    rejected = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert rejected.absence_authoritative is False
    assert "request scope hash" in rejected.reason

    client_side = required.model_copy(update={"provider_enforced_agency_scope": False})
    client_side_coverage = coverage.model_copy(
        update={
            "required_membership_scope": client_side,
            "pre_attestation": attestation.model_copy(
                update={"effective_membership_scope": client_side}
            ),
        }
    )
    client_side_coverage = client_side_coverage.model_copy(
        update={
            "request_scope_sha256": canonical_request_scope_sha256(client_side_coverage)
        }
    )
    client_side_result = evaluate_coverage(
        client_side_coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    assert client_side_result.absence_authoritative is False
    assert "provider-enforced" in client_side_result.reason


def test_schema_v2_page_chain_is_derived_from_token_free_cursor_digests():
    coverage = _v2_coverage()
    scope_hash = coverage.request_scope_sha256
    first_evidence = continuation_evidence_sha256(
        page_sequence=0,
        request_scope_sha256=scope_hash,
        request_cursor_sha256=None,
        response_sha256=HASH_B,
        continuation_state="successor",
        successor_cursor_sha256=HASH_C,
    )
    second_evidence = continuation_evidence_sha256(
        page_sequence=1,
        request_scope_sha256=scope_hash,
        request_cursor_sha256=HASH_C,
        response_sha256=HASH_D,
        continuation_state="terminal",
        successor_cursor_sha256=None,
    )
    pages = (
        CollectionPageEvidence(
            schema_version=2,
            page_sequence=0,
            request_scope_sha256=scope_hash,
            request_cursor_sha256=None,
            response_sha256=HASH_B,
            continuation_state="successor",
            successor_cursor_sha256=HASH_C,
            terminal_checkpoint_sha256=None,
            continuation_evidence_sha256=first_evidence,
            observed_at=NOW,
        ),
        CollectionPageEvidence(
            schema_version=2,
            page_sequence=1,
            request_scope_sha256=scope_hash,
            request_cursor_sha256=HASH_C,
            response_sha256=HASH_D,
            continuation_state="terminal",
            successor_cursor_sha256=None,
            terminal_checkpoint_sha256=second_evidence,
            continuation_evidence_sha256=second_evidence,
            observed_at=NOW,
        ),
    )

    evaluation = evaluate_coverage(
        coverage,
        collection_started_at=NOW,
        collection_completed_at=NOW + timedelta(minutes=1),
    )
    batch = _complete_batch(
        coverage,
        evaluation,
        schema_version=2,
        pages=pages,
        terminal_checkpoint_sha256=second_evidence,
    )
    assert batch.page_chain_complete is True

    wrong_cursor_evidence = continuation_evidence_sha256(
        page_sequence=1,
        request_scope_sha256=scope_hash,
        request_cursor_sha256=HASH_A,
        response_sha256=HASH_D,
        continuation_state="terminal",
        successor_cursor_sha256=None,
    )
    wrong_cursor_page = CollectionPageEvidence(
        schema_version=2,
        page_sequence=1,
        request_scope_sha256=scope_hash,
        request_cursor_sha256=HASH_A,
        response_sha256=HASH_D,
        continuation_state="terminal",
        successor_cursor_sha256=None,
        terminal_checkpoint_sha256=wrong_cursor_evidence,
        continuation_evidence_sha256=wrong_cursor_evidence,
        observed_at=NOW,
    )
    with pytest.raises(ValidationError, match="cursor chain"):
        _complete_batch(
            coverage,
            evaluation,
            schema_version=2,
            pages=(pages[0], wrong_cursor_page),
            terminal_checkpoint_sha256=wrong_cursor_evidence,
        )
