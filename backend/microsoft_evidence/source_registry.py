"""Canonical source contracts for the registered Microsoft evidence inputs.

The registry is executable data. Generated documentation and contract snapshots
must be produced from this module; provider parsing must not import generated
Markdown or CSV files.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Final


REGISTRY_VERSION: Final = "microsoft-source-registry-v1"


@dataclass(frozen=True)
class InventoryMetadata:
    """Human-facing planning attributes kept beside the source contract."""

    requirements: str
    request_limits: str
    most_beneficial_patch: bool
    high_risk_vulnerabilities: bool
    ssvc_automation: bool
    other: bool
    currently_used: bool
    current_use_level: str
    test_demo_quality: int
    production_source_potential: int
    implementation_status: str
    remaining_gap: str


@dataclass(frozen=True)
class MicrosoftSourceInput:
    """Immutable definition of one TriageMate Microsoft input contract."""

    row: int
    input_id: str
    signal: str
    product: str
    operations: tuple[str, ...]
    provider_schemas: tuple[str, ...]
    retained_fields: tuple[str, ...]
    openapi_coverage: str
    exactness: str
    application_permissions: tuple[str, ...]
    product_condition: str
    official_sources: tuple[str, ...]
    forbidden_fields: tuple[str, ...]
    inventory: InventoryMetadata

    @property
    def source_contract_id(self) -> str:
        """Return the content-addressed identity of the provider contract."""

        body = asdict(self)
        body.pop("inventory")
        encoded = json.dumps(
            body, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        return f"ms-source-v1:{hashlib.sha256(encoded).hexdigest()}"


def _fields(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(";") if part.strip())


def _inventory(
    requirements: str,
    limits: str,
    flags: str,
    use_level: str,
    quality: int,
    potential: int,
    status: str,
    gap: str,
) -> InventoryMetadata:
    patch, high_risk, ssvc, other = (flag == "1" for flag in flags)
    return InventoryMetadata(
        requirements=requirements,
        request_limits=limits,
        most_beneficial_patch=patch,
        high_risk_vulnerabilities=high_risk,
        ssvc_automation=ssvc,
        other=other,
        currently_used=False,
        current_use_level=use_level,
        test_demo_quality=quality,
        production_source_potential=potential,
        implementation_status=status,
        remaining_gap=gap,
    )


SOURCE_INPUTS: Final[tuple[MicrosoftSourceInput, ...]] = (
    MicrosoftSourceInput(
        1,
        "ms-entra-directory-device-v1",
        "Directory device identity and state",
        "Microsoft Graph v1.0",
        (
            "GET /devices?$select=id,deviceId,displayName,accountEnabled,operatingSystem,operatingSystemVersion,isManaged,isCompliant,trustType,registrationDateTime,approximateLastSignInDateTime",
        ),
        ("microsoft.graph.device collection",),
        _fields(
            "id; deviceId; displayName; accountEnabled; operatingSystem; operatingSystemVersion; isManaged; isCompliant; trustType; registrationDateTime; approximateLastSignInDateTime"
        ),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact",
        ("Device.Read.All",),
        "Entra tenant",
        (
            "https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0",
        ),
        (),
        _inventory(
            "Entra application with Device.Read.All and validated tenant scope",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            9,
            9,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        2,
        "ms-entra-directory-user-v1",
        "Directory user identity",
        "Microsoft Graph v1.0",
        (
            "GET /users?$select=id,displayName,userPrincipalName,accountEnabled,userType",
        ),
        ("microsoft.graph.user collection",),
        _fields("id; displayName; userPrincipalName; accountEnabled; userType"),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact",
        ("User.Read.All",),
        "Entra tenant",
        ("https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0",),
        (),
        _inventory(
            "Entra application with User.Read.All",
            "Microsoft service limits",
            "0101",
            "Inactive; obsolete implementation removed; retained source contract only",
            8,
            8,
            "Deliberately archived; long-term deferral well after the 23 September meeting",
            "Optional future source; assess coverage and maintenance cost before enabling it in a self-hosted installation.",
        ),
    ),
    MicrosoftSourceInput(
        3,
        "ms-entra-directory-group-v1",
        "Directory group identity",
        "Microsoft Graph v1.0",
        (
            "GET /groups?$select=id,displayName,groupTypes,mailEnabled,securityEnabled,membershipRule,membershipRuleProcessingState",
        ),
        ("microsoft.graph.group collection",),
        _fields(
            "id; displayName; groupTypes; mailEnabled; securityEnabled; membershipRule; membershipRuleProcessingState"
        ),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact",
        ("Group.Read.All",),
        "Entra tenant",
        ("https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0",),
        (),
        _inventory(
            "Entra application with Group.Read.All",
            "Microsoft service limits",
            "0101",
            "Inactive; obsolete implementation removed; retained source contract only",
            8,
            8,
            "Deliberately archived; long-term deferral well after the 23 September meeting",
            "Optional future source; assess coverage and maintenance cost before enabling it in a self-hosted installation.",
        ),
    ),
    MicrosoftSourceInput(
        4,
        "ms-entra-direct-group-member-v1",
        "Directory group membership",
        "Microsoft Graph v1.0",
        ("GET /groups/{group-id}/members?$select=id for each retained group",),
        ("microsoft.graph.directoryObject collection",),
        _fields("groupId; id; @odata.type"),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact for direct membership; transitive paths are derived locally",
        ("GroupMember.Read.All",),
        "Member.Read.Hidden only when hidden membership is approved",
        (
            "https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0",
        ),
        (),
        _inventory(
            "Entra application with GroupMember.Read.All; Member.Read.Hidden only for approved hidden membership",
            "Microsoft service limits",
            "0101",
            "Inactive; obsolete implementation removed; retained source contract only",
            9,
            8,
            "Deliberately archived; long-term deferral well after the 23 September meeting",
            "Optional future source; assess coverage and maintenance cost before enabling it in a self-hosted installation.",
        ),
    ),
    MicrosoftSourceInput(
        5,
        "ms-entra-enterprise-app-assignment-v1",
        "Enterprise application assignment",
        "Microsoft Graph v1.0",
        (
            "GET /servicePrincipals?$select=id,appId,displayName,appRoles",
            "GET /servicePrincipals/{servicePrincipal-id}/appRoleAssignedTo?$select=id,appRoleId,createdDateTime,principalId,principalType,resourceId",
        ),
        (
            "microsoft.graph.servicePrincipal collection",
            "microsoft.graph.appRoleAssignment collection",
        ),
        _fields(
            "id; appId; displayName; appRoles; appRoleId; createdDateTime; principalId; principalType; resourceId"
        ),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact",
        ("Application.Read.All",),
        "Entra tenant and approved administrator consent",
        (
            "https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0",
        ),
        (),
        _inventory(
            "Entra application with Application.Read.All and approved consent",
            "Microsoft service limits",
            "0101",
            "Inactive; obsolete implementation removed; retained source contract only",
            7,
            8,
            "Deliberately archived; long-term deferral well after the 23 September meeting",
            "Optional future source; assess coverage and maintenance cost before enabling it in a self-hosted installation.",
        ),
    ),
    MicrosoftSourceInput(
        6,
        "ms-intune-managed-device-v1",
        "Managed device identity and state",
        "Microsoft Graph v1.0",
        (
            "GET /deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,userId,managedDeviceOwnerType,managementState,enrolledDateTime,lastSyncDateTime,operatingSystem,osVersion,complianceState,manufacturer,model,serialNumber",
            "GET /deviceManagement/managedDevices/{managedDeviceId}",
        ),
        ("microsoft.graph.managedDevice collection",),
        _fields(
            "id; azureADDeviceId; deviceName; userId; managedDeviceOwnerType; managementState; enrolledDateTime; lastSyncDateTime; operatingSystem; osVersion; complianceState; manufacturer; model; serialNumber"
        ),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact",
        ("DeviceManagementManagedDevices.Read.All",),
        "Active Intune licence",
        (
            "https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0",
            "https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-get?view=graph-rest-1.0",
        ),
        (),
        _inventory(
            "Active Intune licence and DeviceManagementManagedDevices.Read.All",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            9,
            9,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        7,
        "ms-intune-detected-app-v1",
        "Detected application identity and version",
        "Microsoft Graph v1.0 inventory / beta device relationship",
        (
            "GET /deviceManagement/detectedApps",
            "GET /deviceManagement/managedDevices/{managedDeviceId}/detectedApps",
        ),
        ("microsoft.graph.detectedApp collection",),
        _fields(
            "id; displayName; version; publisher; platform; sizeInByte; deviceCount"
        ),
        "Inventory covered by pinned Graph v1.0 OpenAPI; device relationship documented in Graph beta",
        "Exact inventory evidence; not vulnerability evidence",
        ("DeviceManagementManagedDevices.Read.All",),
        "Active Intune licence",
        (
            "https://learn.microsoft.com/en-us/graph/api/intune-devices-detectedapp-list?view=graph-rest-1.0",
            "https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-beta",
        ),
        (),
        _inventory(
            "Active Intune licence and DeviceManagementManagedDevices.Read.All",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            8,
            7,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        8,
        "ms-intune-detected-app-device-edge-v1",
        "Detected-application-to-device link",
        "Microsoft Graph v1.0",
        (
            "GET /deviceManagement/detectedApps/{detectedApp-id}/managedDevices for each retained application",
        ),
        ("microsoft.graph.managedDevice collection",),
        _fields("detectedAppId; id; version"),
        "Covered by pinned Graph v1.0 OpenAPI",
        "Exact relationship; no separate Microsoft link entity",
        ("DeviceManagementManagedDevices.Read.All",),
        "Active Intune licence",
        (
            "https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0",
        ),
        (),
        _inventory(
            "Active Intune licence and DeviceManagementManagedDevices.Read.All",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            9,
            8,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        9,
        "ms-intune-quality-update-status-v1",
        "Device update and KB installation status",
        "Microsoft Graph beta",
        (
            "POST /deviceManagement/reports/exportJobs for QualityUpdateDeviceStatusByPolicy with a PolicyId filter and explicit select",
            "GET /deviceManagement/reports/exportJobs/{id} until complete",
            "DOWNLOAD the returned short-lived URL",
        ),
        (
            "microsoft.graph.deviceManagementExportJob",
            "QualityUpdateDeviceStatusByPolicy report row",
        ),
        _fields(
            "AADDeviceId; AggregateState; AggregateState_loc; CurrentDeviceUpdateStatus; CurrentDeviceUpdateStatus_loc; CurrentDeviceUpdateSubstatus; CurrentDeviceUpdateSubstatus_loc; DeviceId; DeviceName; EventDateTimeUTC; LastWUScanTimeUTC; LatestAlertMessage; LatestAlertMessage_loc; OwnerType; PolicyId; UPN"
        ),
        "Beta OpenAPI covers the job envelope; the report catalogue defines downloaded columns",
        "Exact for deployment status only; no named-KB installation proof",
        ("DeviceManagementConfiguration.ReadWrite.All",),
        "Active Intune licence and explicit security approval for the documented write permission",
        (
            "https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports",
        ),
        (),
        _inventory(
            "Active Intune licence and security approval for DeviceManagementConfiguration.ReadWrite.All",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            8,
            7,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures. Deployment state does not prove named-KB installation.",
        ),
    ),
    MicrosoftSourceInput(
        10,
        "ms-defender-machine-v1",
        "Endpoint machine identity and sensor state",
        "Defender for Endpoint",
        ("GET https://api.security.microsoft.com/api/machines",),
        ("Defender Machine collection",),
        _fields(
            "id; aadDeviceId; computerDnsName; firstSeen; lastSeen; osPlatform; version; osBuild; osArchitecture; osProcessor; onboardingStatus; healthStatus; riskScore; exposureLevel; rbacGroupId; machineTags"
        ),
        "Not covered by Graph OpenAPI",
        "Exact",
        ("Machine.Read.All",),
        "Defender entitlement, RBAC device scope, and onboarded sensors",
        ("https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines",),
        (),
        _inventory(
            "Defender entitlement, Machine.Read.All, RBAC scope, and onboarded sensors",
            "100 calls per minute and 1,500 per hour",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            9,
            9,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        11,
        "ms-defender-machine-cve-v1",
        "Machine CVE finding",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities",
        ),
        ("microsoft.windowsDefenderATP.api.PublicAssetVulnerabilityDto collection",),
        _fields(
            "id; cveId; machineId; fixingKbId; productName; productVendor; productVersion; severity"
        ),
        "Not covered by Graph OpenAPI",
        "Exact",
        ("Vulnerability.Read.All",),
        "Applicable Defender vulnerability entitlement and RBAC scope",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines",
        ),
        (),
        _inventory(
            "Applicable Defender vulnerability entitlement and Vulnerability.Read.All",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            9,
            9,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        12,
        "ms-defender-vulnerability-catalogue-v1",
        "Vulnerability catalogue record",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/vulnerabilities",
            "GET https://api.security.microsoft.com/api/vulnerabilities/{cveId}",
        ),
        ("Defender Vulnerability collection",),
        _fields(
            "id; name; description; severity; cvssV3; cvssVector; exposedMachines; publishedOn; updatedOn; firstDetected; publicExploit; exploitVerified; exploitInKit; exploitTypes; exploitUris; cveSupportability; epss; status; tags"
        ),
        "Not covered by Graph OpenAPI",
        "Exact Microsoft context; reconcile with designated public CVE authorities",
        ("Vulnerability.Read.All",),
        "Applicable Defender vulnerability entitlement",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities",
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-vulnerability-by-id",
        ),
        (),
        _inventory(
            "Applicable Defender vulnerability entitlement and Vulnerability.Read.All",
            "Bounded $top/$skip pages; maximum $top 8,000; obey provider throttling",
            "1100",
            "Receipt-bound catalogue claims and current SQL view, separate from device findings",
            7,
            8,
            "Current command, offset pagination, durable replay, restricted persistence and SQL query verified with synthetic input",
            "Live catalogue entitlement remains unverified; source exposed counts do not identify individual devices.",
        ),
    ),
    MicrosoftSourceInput(
        13,
        "ms-defender-missing-kb-v1",
        "Missing or fixing KB evidence",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities",
            "GET https://api.security.microsoft.com/api/machines/{machineId}/getmissingkbs when enrichment is approved",
        ),
        (
            "PublicAssetVulnerabilityDto collection",
            "microsoft.windowsDefenderATP.api.PublicProductFixDto collection",
        ),
        _fields(
            "machineId; cveId; fixingKbId; productName; productVendor; productVersion; id; name; productsNames; url; machineMissedOn; cveAddressed"
        ),
        "Not covered by Graph OpenAPI",
        "Exact as a two-schema join; enrichment alone does not identify addressed CVEs",
        ("Software.Read.All", "Vulnerability.Read.All"),
        "Applicable Defender vulnerability entitlement; Software.Read.All only for enrichment",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-missing-kbs-machine",
        ),
        (),
        _inventory(
            "Applicable Defender entitlement; Vulnerability.Read.All and Software.Read.All for enrichment",
            "Microsoft service limits",
            "1100",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            7,
            8,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        14,
        "ms-defender-antivirus-health-v1",
        "Endpoint antivirus health",
        "Defender for Endpoint",
        ("GET https://api.security.microsoft.com/api/deviceavinfo",),
        ("Defender DeviceAvInfo collection",),
        _fields(
            "id; machineId; computerDnsName; osKind; osPlatform; osVersion; avMode; avSignatureVersion; avEngineVersion; avPlatformVersion; lastSeenTime; quickScanResult; quickScanError; quickScanTime; fullScanResult; fullScanError; fullScanTime; dataRefreshTimestamp; avEngineUpdateTime; avSignatureUpdateTime; avPlatformUpdateTime; avIsSignatureUpToDate; avIsEngineUpToDate; avIsPlatformUpToDate; avSignaturePublishTime; rbacGroupId; rbacGroupName"
        ),
        "Not covered by Graph OpenAPI",
        "Provisional route; freeze only after an authorized synthetic-tenant smoke test resolves conflicting official pages",
        ("Machine.Read.All",),
        "Defender for Endpoint Plan 2 or Defender for Business",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/device-health-export-antivirus-health-report-api",
        ),
        (),
        _inventory(
            "Defender for Endpoint Plan 2 or Defender for Business and Machine.Read.All",
            "Microsoft service limits",
            "0101",
            "Receipt-bound PostgreSQL evidence and current SQL views; no custom Queue scoring",
            7,
            7,
            "Current collector/import/query path implemented with synthetic verification; historical stores remain retired",
            "Broader live entitlement and coverage remain unverified; repository acceptance uses synthetic or public fixtures.",
        ),
    ),
    MicrosoftSourceInput(
        15,
        "ms-defender-device-activity-v1",
        "Endpoint exploit or activity event",
        "Microsoft Graph v1.0",
        (
            "POST /security/runHuntingQuery with a version-controlled DeviceEvents query projecting Timestamp,DeviceId,DeviceName,ActionType,FileName,SHA1,SHA256,ReportId",
        ),
        (
            "microsoft.graph.security.huntingQueryResults",
            "query-defined DeviceEvents projection",
        ),
        _fields(
            "Timestamp; DeviceId; DeviceName; ActionType; FileName; SHA1; SHA256; ReportId; KQL hash; partition-contract hash; requested timespan; returned schema; per-partition count; retained-row count; collection time"
        ),
        "Graph OpenAPI covers the action envelope; the projected row and completeness proof are query-defined",
        "Exact only for complete positive activity partitions; never negative exploit proof",
        ("ThreatHunting.Read.All",),
        "Applicable Defender XDR source, RBAC scope, taxonomy, purpose, retention, and partition approval",
        (
            "https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0",
            "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview",
            "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table",
        ),
        (
            "AdditionalFields",
            "ProcessCommandLine",
            "InitiatingProcessCommandLine",
            "AccountName",
            "AccountDomain",
            "FolderPath",
            "InitiatingProcessFolderPath",
        ),
        _inventory(
            "ThreatHunting.Read.All plus approved data source, taxonomy, purpose, retention, and partition policy",
            "100,000 rows, 64 MB, 10 minutes per query, and 30-day native range",
            "0110",
            "Inactive; obsolete implementation removed; retained source contract only",
            9,
            7,
            "Deliberately archived; long-term deferral well after the 23 September meeting",
            "Optional future source; assess coverage and maintenance cost before enabling it in a self-hosted installation.",
        ),
    ),
    MicrosoftSourceInput(
        16,
        "ms-defender-vulnerability-baseline-v1",
        "Full software vulnerability assessment",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine",
        ),
        ("Defender software assessment JSON collection",),
        _fields(
            "id; deviceId; softwareVendor; softwareName; softwareVersion; cveId; rbacGroupId; deviceName; osPlatform; osVersion; osArchitecture; rbacGroupName; vulnerabilitySeverityLevel; exploitabilityLevel; recommendationReference; recommendedSecurityUpdate; recommendedSecurityUpdateId; recommendedSecurityUpdateUrl; firstSeenTimestamp; lastSeenTimestamp; cvssScore; isOnboarded; securityUpdateAvailable; diskPaths; registryPaths"
        ),
        "Not covered by Graph OpenAPI",
        "Documented JSON export; preserve source timestamp ambiguity",
        ("Vulnerability.Read.All",),
        "Applicable Defender vulnerability entitlement and RBAC scope",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities",
        ),
        (),
        _inventory(
            "Vulnerability.Read.All and supported Defender entitlement",
            "30 calls/minute, 1000/hour; generated every six hours; delta window at most 14 days",
            "1100",
            "Assessment history; no patch execution or inferred whole-device remediation",
            0,
            0,
            "Collector command, durable replay, restricted receipts and SQL query path implemented; synthetic regressions pass",
            "Core-input milestone gate pending. Live entitlement remains unverified; source references absent from the pinned device snapshot remain explicitly unbound.",
        ),
    ),
    MicrosoftSourceInput(
        17,
        "ms-defender-vulnerability-events-v1",
        "Software vulnerability source changes",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/machines/SoftwareVulnerabilityChangesByMachine",
        ),
        ("Defender software assessment JSON collection",),
        _fields(
            "id; deviceId; softwareVendor; softwareName; softwareVersion; cveId; rbacGroupId; deviceName; osPlatform; osVersion; osArchitecture; rbacGroupName; vulnerabilitySeverityLevel; exploitabilityLevel; recommendationReference; recommendedSecurityUpdate; recommendedSecurityUpdateId; recommendedSecurityUpdateUrl; firstSeenTimestamp; lastSeenTimestamp; cvssScore; isOnboarded; securityUpdateAvailable; diskPaths; registryPaths; status; eventTimestamp"
        ),
        "Not covered by Graph OpenAPI",
        "Documented JSON export; preserve source timestamp ambiguity",
        ("Vulnerability.Read.All",),
        "Applicable Defender vulnerability entitlement and RBAC scope",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-vulnerabilities",
        ),
        (),
        _inventory(
            "Vulnerability.Read.All and supported Defender entitlement",
            "30 calls/minute, 1000/hour; generated every six hours; delta window at most 14 days",
            "1100",
            "Assessment history; no patch execution or inferred whole-device remediation",
            0,
            0,
            "Collector command, durable replay, restricted receipts and SQL query path implemented; synthetic regressions pass",
            "Core-input milestone gate pending. Live entitlement remains unverified; source references absent from the pinned device snapshot remain explicitly unbound.",
        ),
    ),
    MicrosoftSourceInput(
        18,
        "ms-defender-recommendation-v1",
        "Device security recommendations",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/recommendations",
            "GET https://api.security.microsoft.com/api/machines/{machineId}/recommendations",
        ),
        ("Defender recommendation JSON collection",),
        _fields(
            "id; recommendationName; vendor; productName; recommendedVersion; recommendedProgram; recommendedVendor; recommendationCategory; subCategory; remediationType; status; weaknesses; totalMachineCount; exposedMachinesCount"
        ),
        "Not covered by Graph OpenAPI",
        "Documented source advice and direct associations",
        ("SecurityRecommendation.Read.All",),
        "Applicable Defender vulnerability entitlement and RBAC scope",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations",
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-security-recommendations",
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-recommendation-machines",
        ),
        (),
        _inventory(
            "SecurityRecommendation.Read.All and supported Defender entitlement",
            "Recommendations support $top up to 10000 and $skip; obey source throttling",
            "1100",
            "Source advice only; collection does not change devices",
            0,
            0,
            "Collector command, durable replay, restricted receipts and SQL query path implemented; synthetic regressions pass",
            "Core-input milestone gate pending. Live entitlement remains unverified; source references absent from the pinned device snapshot remain explicitly unbound.",
        ),
    ),
    MicrosoftSourceInput(
        19,
        "ms-defender-recommendation-device-v1",
        "Explicit recommendation/device associations",
        "Defender Vulnerability Management",
        (
            "GET https://api.security.microsoft.com/api/recommendations/{id}/machineReferences",
        ),
        ("Defender recommendation JSON collection",),
        _fields("id"),
        "Not covered by Graph OpenAPI",
        "Documented source advice and direct associations",
        ("SecurityRecommendation.Read.All",),
        "Applicable Defender vulnerability entitlement and RBAC scope",
        (
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-recommendations",
            "https://learn.microsoft.com/en-us/defender-endpoint/api/get-recommendation-machines",
        ),
        (),
        _inventory(
            "SecurityRecommendation.Read.All and supported Defender entitlement",
            "Recommendations support $top up to 10000 and $skip; obey source throttling",
            "1100",
            "Source advice only; collection does not change devices",
            0,
            0,
            "Collector command, durable replay, restricted receipts and SQL query path implemented; synthetic regressions pass",
            "Core-input milestone gate pending. Live entitlement remains unverified; source references absent from the pinned device snapshot remain explicitly unbound.",
        ),
    ),
)


def validate_registry() -> None:
    """Reject identity, coverage, field, and permission defects."""

    if tuple(item.row for item in SOURCE_INPUTS) != tuple(range(1, 20)):
        raise ValueError("Microsoft source rows must be exactly 1 through 19")
    if len({item.input_id for item in SOURCE_INPUTS}) != 19:
        raise ValueError("Microsoft input IDs must be unique")
    if len({item.source_contract_id for item in SOURCE_INPUTS}) != 19:
        raise ValueError("Microsoft source contract IDs must be unique")
    for item in SOURCE_INPUTS:
        if not all((item.operations, item.provider_schemas, item.retained_fields)):
            raise ValueError(f"{item.input_id} has an incomplete provider contract")
        if not item.application_permissions or not item.official_sources:
            raise ValueError(f"{item.input_id} lacks permission or provenance")
        overlap = set(item.retained_fields) & set(item.forbidden_fields)
        if overlap:
            raise ValueError(f"{item.input_id} retains forbidden fields: {overlap}")
        if not 0 <= item.inventory.test_demo_quality <= 10:
            raise ValueError(f"{item.input_id} has an invalid test quality score")
        if not 0 <= item.inventory.production_source_potential <= 10:
            raise ValueError(f"{item.input_id} has an invalid production score")


def registry_document() -> dict[str, object]:
    """Return the stable JSON representation used by tooling and review."""

    validate_registry()
    inputs = []
    for item in SOURCE_INPUTS:
        # Dataclass tuples are immutable in memory; normalize them to JSON arrays
        # so callers and the checked artifact receive the same representation.
        row = json.loads(json.dumps(asdict(item), ensure_ascii=False))
        row["source_contract_id"] = item.source_contract_id
        inputs.append(row)
    return {"registry_version": REGISTRY_VERSION, "inputs": inputs}


def registry_json() -> str:
    return (
        json.dumps(registry_document(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def _csv_text(header: tuple[str, ...], rows: list[tuple[object, ...]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return output.getvalue()


def mapping_csv() -> str:
    rows = []
    for item in SOURCE_INPUTS:
        rows.append(
            (
                item.row,
                item.signal,
                item.product,
                " then ".join(item.operations),
                " plus ".join(item.provider_schemas),
                "; ".join(item.retained_fields),
                item.openapi_coverage,
                item.exactness,
                "; ".join(item.official_sources),
                item.input_id,
                item.source_contract_id,
            )
        )
    return _csv_text(
        (
            "number",
            "Signal",
            "API product",
            "HTTP method and exact operation",
            "Microsoft response schema",
            "Fields TriageMate must retain",
            "Graph OpenAPI coverage",
            "Exactness status",
            "Official Microsoft source",
            "Input ID",
            "Source contract ID",
        ),
        rows,
    )


def inventory_csv() -> str:
    rows = []
    for item in SOURCE_INPUTS:
        inv = item.inventory
        product_name = (
            "Microsoft Graph Entra"
            if item.input_id.startswith("ms-entra-")
            else "Microsoft Graph Intune"
            if item.input_id.startswith("ms-intune-")
            else "Microsoft Defender for Endpoint"
        )
        rows.append(
            (
                item.row,
                item.signal,
                " then ".join(item.operations),
                inv.requirements,
                inv.request_limits,
                inv.most_beneficial_patch,
                inv.high_risk_vulnerabilities,
                inv.ssvc_automation,
                inv.other,
                "Yes" if inv.currently_used else "No",
                inv.current_use_level,
                f"{product_name} source contract {item.input_id}",
                inv.test_demo_quality,
                inv.production_source_potential,
                inv.implementation_status,
                inv.remaining_gap,
            )
        )
    return _csv_text(
        (
            "number",
            "Signal",
            "Delivery Method",
            "Delivery Method Requirements",
            "Request Limits (Per Minute)",
            "Most Beneficial Patch",
            "High-risk vulnerabilities",
            "SSVC Automation",
            "Other",
            "Currently used",
            "Current use level",
            "Replacement",
            "Test/demo quality (0-10)",
            "Production source potential (0-10)",
            "Implementation status",
            "Setup or remaining gap",
        ),
        rows,
    )


def mapping_markdown() -> str:
    lines = [
        "# Exact Microsoft API and schema mapping",
        "",
        "> Generated from `backend/microsoft_evidence/source_registry.py`. Do not edit by hand.",
        "",
        f"The {len(SOURCE_INPUTS)} rows are TriageMate inputs, not Microsoft schema fields. Each row has an immutable input ID and a content-addressed source contract ID.",
        "",
        "This is a retained contract catalogue, not a list of active collectors. Entra users, groups, direct memberships, enterprise application assignments and Defender raw activity remain deferred. Registry presence does not enable collection or scheduling. See [the input inventory](SPRINT_INPUT_INVENTORY.md) for active/deferred status and [the restoration guide](../guides/DEFERRED_INPUT_RESTORATION.md) for reopening boundaries.",
        "",
        "| number | Input ID | TriageMate input | Exact operation(s) | Provider schema | Retained fields | Permission | OpenAPI and exactness |",
        "|---:|---|---|---|---|---|---|---|",
    ]
    for item in SOURCE_INPUTS:
        cells = (
            str(item.row),
            f"`{item.input_id}`",
            item.signal,
            "<br>".join(f"`{operation}`" for operation in item.operations),
            "<br>".join(item.provider_schemas),
            "<br>".join(f"`{field}`" for field in item.retained_fields),
            "<br>".join(
                f"`{permission}`" for permission in item.application_permissions
            ),
            f"{item.openapi_coverage}. {item.exactness}.",
        )
        lines.append(
            "| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |"
        )
    lines.extend(
        (
            "",
            "## Enforced boundaries",
            "",
            "- Row 9 is deployment-status evidence, not proof that a named KB is installed.",
            "- Row 13 is a two-schema join. Missing-KB enrichment alone does not identify the addressed CVEs.",
            "- Row 14 retains its historical transport contract. Current collection uses GET /api/deviceavinfo; operators must verify source permissions, entitlement and device scope before enabling it.",
            "- Row 15 retains only the minimized projection. A saturated, partial, timed-out, size-limited, count-mismatched, or retention-gapped partition is incomplete and cannot prove absence or exploitation.",
            "- Microsoft Graph OpenAPI covers Graph operations. Defender REST schemas require separate pinned official-source validation.",
            "",
            "## Provenance",
            "",
        )
    )
    for item in SOURCE_INPUTS:
        links = ", ".join(
            f"[source {index + 1}]({url})"
            for index, url in enumerate(item.official_sources)
        )
        lines.append(f"- {item.row}. {item.signal}: {links}")
    return "\n".join(lines) + "\n"


def generated_artifacts(repository_root: Path) -> dict[Path, str]:
    """Return every derived artifact and its expected exact content."""

    return {
        repository_root
        / "backend/microsoft_evidence/microsoft_source_registry.json": registry_json(),
        repository_root
        / "docs/planning/MICROSOFT_API_SCHEMA_MAPPING.csv": mapping_csv(),
        repository_root
        / "docs/planning/MICROSOFT_API_SCHEMA_MAPPING.md": mapping_markdown(),
        repository_root
        / "docs/planning/MICROSOFT_INFORMATION_INPUTS.csv": inventory_csv(),
    }


def write_generated_artifacts(repository_root: Path) -> None:
    for path, content in generated_artifacts(repository_root).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def check_generated_artifacts(repository_root: Path) -> list[Path]:
    return [
        path
        for path, expected in generated_artifacts(repository_root).items()
        if not path.is_file() or path.read_text() != expected
    ]


if __name__ == "__main__":
    write_generated_artifacts(Path(__file__).resolve().parents[2])
