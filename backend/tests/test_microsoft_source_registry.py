"""Independent checks for the canonical Microsoft source registry."""

from __future__ import annotations

import json
from pathlib import Path

from microsoft_evidence.source_registry import (
    REGISTRY_VERSION,
    SOURCE_INPUTS,
    check_generated_artifacts,
    registry_document,
    validate_registry,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

# This expectation is intentionally not generated from the registry. It makes
# accidental removal, renumbering, route substitution, or permission drift fail.
EXPECTED_CONTRACTS = (
    (1, "ms-entra-directory-device-v1", "/devices?$select=", "Device.Read.All"),
    (2, "ms-entra-directory-user-v1", "/users?$select=", "User.Read.All"),
    (3, "ms-entra-directory-group-v1", "/groups?$select=", "Group.Read.All"),
    (
        4,
        "ms-entra-direct-group-member-v1",
        "/groups/{group-id}/members?$select=id",
        "GroupMember.Read.All",
    ),
    (
        5,
        "ms-entra-enterprise-app-assignment-v1",
        "/servicePrincipals/{servicePrincipal-id}/appRoleAssignedTo",
        "Application.Read.All",
    ),
    (
        6,
        "ms-intune-managed-device-v1",
        "/deviceManagement/managedDevices?$select=",
        "DeviceManagementManagedDevices.Read.All",
    ),
    (
        7,
        "ms-intune-detected-app-v1",
        "/deviceManagement/detectedApps",
        "DeviceManagementManagedDevices.Read.All",
    ),
    (
        8,
        "ms-intune-detected-app-device-edge-v1",
        "/deviceManagement/detectedApps/{detectedApp-id}/managedDevices",
        "DeviceManagementManagedDevices.Read.All",
    ),
    (
        9,
        "ms-intune-quality-update-status-v1",
        "/deviceManagement/reports/exportJobs",
        "DeviceManagementConfiguration.ReadWrite.All",
    ),
    (10, "ms-defender-machine-v1", "/api/machines", "Machine.Read.All"),
    (
        11,
        "ms-defender-machine-cve-v1",
        "/api/vulnerabilities/machinesVulnerabilities",
        "Vulnerability.Read.All",
    ),
    (
        12,
        "ms-defender-vulnerability-catalogue-v1",
        "/api/vulnerabilities",
        "Vulnerability.Read.All",
    ),
    (
        13,
        "ms-defender-missing-kb-v1",
        "/api/machines/{machineId}/getmissingkbs",
        "Software.Read.All",
    ),
    (14, "ms-defender-antivirus-health-v1", "/api/deviceavinfo", "Machine.Read.All"),
    (
        15,
        "ms-defender-device-activity-v1",
        "/security/runHuntingQuery",
        "ThreatHunting.Read.All",
    ),
    (
        16,
        "ms-defender-vulnerability-baseline-v1",
        "/api/machines/SoftwareVulnerabilitiesByMachine",
        "Vulnerability.Read.All",
    ),
    (
        17,
        "ms-defender-vulnerability-events-v1",
        "/api/machines/SoftwareVulnerabilityChangesByMachine",
        "Vulnerability.Read.All",
    ),
    (
        18,
        "ms-defender-recommendation-v1",
        "/api/recommendations",
        "SecurityRecommendation.Read.All",
    ),
    (
        19,
        "ms-defender-recommendation-device-v1",
        "/api/recommendations/{id}/machineReferences",
        "SecurityRecommendation.Read.All",
    ),
)


def test_registry_has_the_independently_expected_19_contracts() -> None:
    validate_registry()

    actual = []
    for item in SOURCE_INPUTS:
        operation_text = " ".join(item.operations)
        expected = EXPECTED_CONTRACTS[item.row - 1]
        actual.append(
            (
                item.row,
                item.input_id,
                expected[2] in operation_text,
                expected[3] in item.application_permissions,
            )
        )

    assert actual == [
        (row, input_id, True, True)
        for row, input_id, _route, _permission in EXPECTED_CONTRACTS
    ]


def test_registry_contract_ids_are_stable_and_content_addressed() -> None:
    contract_ids = [item.source_contract_id for item in SOURCE_INPUTS]

    assert len(set(contract_ids)) == 19
    assert all(value.startswith("ms-source-v1:") for value in contract_ids)
    assert all(len(value.removeprefix("ms-source-v1:")) == 64 for value in contract_ids)


def test_minimized_hunting_contract_rejects_sensitive_fields() -> None:
    hunting = SOURCE_INPUTS[14]

    assert set(hunting.forbidden_fields) == {
        "AccountDomain",
        "AccountName",
        "AdditionalFields",
        "FolderPath",
        "InitiatingProcessCommandLine",
        "InitiatingProcessFolderPath",
        "ProcessCommandLine",
    }
    assert not set(hunting.retained_fields) & set(hunting.forbidden_fields)
    assert "AdditionalFields" not in hunting.retained_fields


def test_generated_registry_snapshot_matches_executable_registry() -> None:
    snapshot = json.loads(
        (
            REPOSITORY_ROOT
            / "backend/microsoft_evidence/microsoft_source_registry.json"
        ).read_text()
    )

    assert snapshot == registry_document()
    assert snapshot["registry_version"] == REGISTRY_VERSION
    assert len(snapshot["inputs"]) == 19


def test_all_generated_source_artifacts_are_current() -> None:
    assert check_generated_artifacts(REPOSITORY_ROOT) == []


def test_inventory_explicitly_says_no_input_is_live_yet() -> None:
    assert all(not item.inventory.currently_used for item in SOURCE_INPUTS)
    assert {item.inventory.test_demo_quality for item in SOURCE_INPUTS} <= set(
        range(11)
    )
    assert {
        item.inventory.production_source_potential for item in SOURCE_INPUTS
    } <= set(range(11))


def test_defender_device_contract_retains_explicit_architecture():
    source = next(
        item for item in SOURCE_INPUTS if item.input_id == "ms-defender-machine-v1"
    )
    assert {"osArchitecture", "osProcessor"} <= set(source.retained_fields)
