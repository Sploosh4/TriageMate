# Microsoft Intune report-export contract

This retains the August 2026 source contract and subsequent observed compatibility refinements. It is not a fresh provider/entitlement audit. Current self-hosted deployment is described in [the container guide](../guides/CONTAINERS.md).

The supported `QualityUpdateDeviceStatusByPolicy` export is an expedited-policy deployment-status report. It is not exact installed-KB evidence or a general per-device patch-need contract. A separate automated Windows update distribution/device applicability route remains unresolved; portal report names must not become unverified API report names.

Retained compatibility handling selects 12 source columns while validating the 16 documented CSV output columns, accepts observed lower-camel localization enum spelling, and permits pending jobs without a download URL. Completed jobs require an approved, unexpired URL. The two UTC-labelled report timestamps accept the observed seven-fractional-digit format, while generic job timestamps require an explicit offset. The exact year-one scan-time sentinel becomes unknown, not a scan date. These observations do not establish every provider response variant.

Scope checks precede export creation; post-download filtering is not collection authorization. Preserve selected policy/device context and original source dates. An expedited policy can accelerate installation and enforce restart deadlines, so creating or assigning one is not a harmless reporting prerequisite. Product device changes remain out of scope.

## Decision summary

TriageMate implements this source as an asynchronous, policy-scoped export. It must create an export job, poll that job, download a short-lived ZIP, and validate an explicitly selected CSV schema. The result is evidence about the deployment state of devices targeted by one expedited quality-update policy. It is not proof that a named KB is installed.

Microsoft documents the report name, required `PolicyId` filter, available columns, job states, job response fields, and ZIP download workflow. Microsoft does not document a report-specific request example, output field types, archive member name, normative download-host allowlist, response MIME type, polling deadline, or a cancellation guarantee. Those points need explicit defensive TriageMate policy and synthetic contract tests.

## Official operation

Create the job with:

```http
POST https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs
Authorization: Bearer <token>
Accept: application/json
Content-Type: application/json
```

The beta create method returns `201 Created` and a `deviceManagementExportJob`. Microsoft warns that beta APIs change more often and recommends v1.0 where possible. An active Intune licence is also required. [Create export job](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-create?view=graph-rest-beta)

Microsoft's operational export guide identifies five main request parameters: `reportName`, `filter`, `select`, `format`, and `localizationType`. Only `reportName` is generally required, but the report catalogue makes `PolicyId` a required filter for this report. The guide says clients must explicitly select columns and must not automate against default columns. [Export Intune reports](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis) [Available reports and properties](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports#qualityupdatedevicestatusbypolicy)

### Proposed exact request contract

```json
{
  "reportName": "QualityUpdateDeviceStatusByPolicy",
  "filter": "(PolicyId eq '<policy-id>')",
  "select": [
    "AADDeviceId",
    "AggregateState",
    "CurrentDeviceUpdateStatus",
    "CurrentDeviceUpdateSubstatus",
    "DeviceId",
    "DeviceName",
    "EventDateTimeUTC",
    "LastWUScanTimeUTC",
    "LatestAlertMessage",
    "OwnerType",
    "PolicyId",
    "UPN"
  ],
  "format": "csv",
  "localizationType": "LocalizedValuesAsAdditionalColumn"
}
```

The filter shape follows Microsoft's documented export example, `(OwnerType eq '1')`, while substituting the report catalogue's required `PolicyId` field. Microsoft does not publish a `QualityUpdateDeviceStatusByPolicy` request example, so the exact policy-ID canonical UUID filter has now succeeded in the authorized test source. Arbitrary literals and quote escaping are unsupported: the implementation builds this exact filter from a validated canonical UUID and does not accept raw filter text. [Export request example](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#request-example) [Report filter catalogue](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports#qualityupdatedevicestatusbypolicy)

The request selects the 12 canonical fields. Microsoft says `LocalizedValuesAsAdditionalColumn` preserves stable raw values under the original column names and adds human-readable, locale-dependent `_loc` columns. That produces the 16-column expected output listed below without depending on undocumented default selection. Microsoft lists both PascalCase values in its operational guide, while the Graph resource schema renders the enum values in lower camel case. Use the operational-guide spelling shown above for requests. Both response spellings are now accepted and tested, following the observed lower-camel spelling in the authorized test source. [Localization behaviour](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#localization-behavior) [Export-job resource](https://learn.microsoft.com/en-us/graph/api/resources/intune-reporting-devicemanagementexportjob?view=graph-rest-beta)

Do not send `id`, `status`, `url`, `requestDateTime`, or `expirationDateTime`. Those are job/result fields. Do not send `snapshotId` or `search` because this workflow does not use them. Microsoft documents maximums of 2,000 characters for `reportName` and `filter`, 256 selected columns, and 1,000 characters per selected column. [Create export job fields](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-create?view=graph-rest-beta#request-body)

## Permissions and authority

For an unattended connector, use application permission. Creating a job requires one of these application permissions:

- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementApps.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`

TriageMate's source contract selects `DeviceManagementConfiguration.ReadWrite.All`, because this export is tied to an Intune update policy. Do not grant the other two solely for this source. Microsoft lists only read/write permissions for job creation, even though job polling alone also accepts the corresponding read permissions. Microsoft Graph guidance says background services should use application permissions and apps must receive only the least privilege needed. [Create permissions](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-create?view=graph-rest-beta#permissions) [Get permissions](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-get?view=graph-rest-beta#permissions) [Graph consent guidance](https://learn.microsoft.com/en-us/graph/best-practices-concept#consent-and-authorization)

The connector must reject tokens with the wrong audience and must fail closed when its configured permission set exceeds the approved source contract. The permission is broad, so its credential must be an external secret reference, not repository content.

## Creation response and job schema

The successful create response is `201 Created`, with JSON content describing a `deviceManagementExportJob`. The documented fields are:

| Field | Documented meaning | TriageMate treatment |
|---|---|---|
| `id` | Unique job identifier | Required, non-empty, and used only to build the poll path |
| `reportName` | Report name | Must equal the requested report |
| `filter` | Applied report filter | Retain as provenance and compare with the requested filter |
| `select` | Selected report columns | Require exactly the requested set; retain returned order as provenance |
| `format` | `csv`, `pdf`, `json`, or `unknownFutureValue`; the export guide supports CSV and JSON data | Must equal `csv` |
| `snapshotId` | Optional report snapshot identifier | Must be absent or null for this workflow |
| `localizationType` | Localization mode | Must match the requested mode, with documented spelling normalization only |
| `search` | Optional report search term in beta | Must be absent or null for this workflow |
| `status` | Job state | Parse as described below |
| `url` | Temporary exported-report location | Must be absent/null until completion; validate before download |
| `requestDateTime` | Time Microsoft accepted the export request | Parse as a timezone-aware timestamp and retain |
| `expirationDateTime` | Time the export expires | Parse as a timezone-aware timestamp and enforce before download |

Microsoft documents these fields but does not state that every optional field is always present. The parser must distinguish a missing required contract field from a nullable optional field and retain unknown extra fields as schema-drift evidence without trusting them. [Create response](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-create?view=graph-rest-beta#response) [Export-job properties](https://learn.microsoft.com/en-us/graph/api/resources/intune-reporting-devicemanagementexportjob?view=graph-rest-beta#properties)

## Polling and state machine

Poll only the returned job ID:

```http
GET https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs/<url-encoded-job-id>
Authorization: Bearer <token>
Accept: application/json
```

Microsoft also shows the OData-parentheses form `exportJobs('<id>')`; the path-segment form is simpler if the ID is encoded as one path segment. A successful poll returns `200 OK` and the export-job object. Microsoft's operational example places the object at the JSON top level, while the autogenerated Graph GET example places it under a `value` property. Until a live-contract check resolves that inconsistency, the parser may accept either one top-level job object or one job object under `value`; it must reject an array, multiple objects, or any other envelope. [Export polling workflow](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#response-example) [Get export job](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-get?view=graph-rest-beta)

The complete documented status enum is:

| Status | Classification | Action |
|---|---|---|
| `notStarted` | Intermediate | Poll again after bounded backoff |
| `inProgress` | Intermediate | Poll again after bounded backoff |
| `completed` | Terminal success | Require a valid, unexpired URL, then download |
| `failed` | Terminal failure | Record the failed attempt; do not download or activate |
| `unknown` | Terminal-safe failure in TriageMate | Record an unsupported/unknown outcome; do not keep polling forever |
| Any new value | Terminal-safe failure in TriageMate | Record schema drift; do not download or activate |

Microsoft documents exactly `unknown`, `notStarted`, `inProgress`, `completed`, and `failed`. Its export guide says to poll until `completed`, but it does not define an interval or deadline. TriageMate therefore needs a bounded elapsed deadline, a maximum poll count, capped exponential backoff with jitter, and a per-request timeout. Expiry and timeout must record a failed collection attempt rather than create an empty successful revision. [Status enum](https://learn.microsoft.com/en-us/graph/api/resources/intune-reporting-devicemanagementexportjob?view=graph-rest-beta#properties) [Polling guidance](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#response-example)

The Intune export API allows up to 100 requests per tenant per minute, with additional limits of 48 requests per app per minute and eight requests per user per minute. On `429`, Microsoft says to honor `Retry-After`; if it is absent, use exponential backoff. The total job deadline still applies. [Intune export throttling](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#api-throttling-conditions) [Graph throttling](https://learn.microsoft.com/en-us/graph/throttling#best-practices-to-handle-throttling)

## Download and archive contract

On completion, `url` is a temporary location. Microsoft's example is an HTTPS Azure Blob Storage SAS URL under `*.blob.core.windows.net`, ending in `.zip`, and the guide says the URL directly downloads a compressed CSV. The requested `format` controls whether the ZIP contains CSV or JSON. [Completed-job example](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#response-example) [Download description](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports#download-the-completed-chromeosdevices-report)

Microsoft does not publish a normative hostname or MIME allowlist for Intune exports. It also does not specify the archive member name. Therefore, the following are TriageMate security policy, not claims about a guaranteed Microsoft schema:

- Accept HTTPS only.
- For the global cloud contract, accept only a DNS name that is a strict subdomain of `blob.core.windows.net`; do not accept user-info, IP literals, fragments, non-default ports, lookalike suffixes, or hostnames resolved from tenant data. Define separate exact suffixes before enabling a national cloud.
- Disable redirects, or validate every redirect target against the same policy.
- Never log or persist the URL query string. A SAS authorizes whoever possesses it, and Microsoft warns that leaked SAS URIs can expose data and should always use HTTPS.
- Accept `application/zip` and `application/octet-stream` as transport hints, but do not trust MIME or filename. Require ZIP magic, a valid central directory, bounded compressed bytes, bounded entry count, bounded per-entry and total uncompressed bytes, and one regular non-encrypted data member.
- Require that the one data member parses as CSV because this contract requests `format: csv`. Do not extract paths to disk. Reject nested archives, directories, duplicate member names, and absolute or traversal names.

Microsoft's public PowerShell sample requests the download with `application/zip`; Microsoft's Intune documentation does not promise a response `Content-Type`. Allowing `application/octet-stream` is therefore provisional and must be confirmed during the authorized live-contract check. [Microsoft Intune PowerShell export sample](https://github.com/microsoftgraph/powershell-intune-samples/blob/master/IntuneDataExport/Export-IntuneData.ps1) [SAS security guidance](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview#best-practices-when-using-sas)

## Exact documented report columns

The official report catalogue lists these 16 available properties and no data types:

| Column | Normalization constraint |
|---|---|
| `AADDeviceId` | Nullable string; validate UUID syntax when present; never replace `DeviceId` with it |
| `AggregateState` | Preserve raw source value; map only known tested values |
| `AggregateState_loc` | Human-readable, locale-dependent display value; never use as a stable key |
| `CurrentDeviceUpdateStatus` | Preserve raw source value; map only known tested values |
| `CurrentDeviceUpdateStatus_loc` | Human-readable, locale-dependent display value |
| `CurrentDeviceUpdateSubstatus` | Preserve raw source value; map only known tested values |
| `CurrentDeviceUpdateSubstatus_loc` | Human-readable, locale-dependent display value |
| `DeviceId` | Wire nullability is unresolved; TriageMate requires a valid Intune device UUID before activation |
| `DeviceName` | Display-only string; not an identity join key |
| `EventDateTimeUTC` | Live transport requires non-empty text: explicit UTC ISO or the observed seven-fraction UTC CSV format; preserve raw text, normalize to microseconds |
| `LastWUScanTimeUTC` | Same wire validation; the exact year-one zero sentinel normalizes to NULL. The standalone adapter also preserves absent/empty dates as unknown; live wire nullability beyond the observed sentinel remains unverified |
| `LatestAlertMessage` | Raw alert value; retain as source evidence, never execute or render as HTML |
| `LatestAlertMessage_loc` | Locale-dependent display text; never execute or render as HTML |
| `OwnerType` | Preserve raw source value; map only known tested values |
| `PolicyId` | Must equal the requested policy ID for every accepted row |
| `UPN` | Nullable user principal name; sensitive display/context field, not a device join key |

The catalogue names `AggregateState`, `OwnerType`, and `PolicyId` as filterable, and marks `PolicyId` required. It does not define field types, nullability, enum members, CSV encoding, delimiter, line endings, quoting, or column order. TriageMate must therefore validate header names as a set, accept and record a different wire order, write normalized output in the explicit request order, parse RFC-compatible CSV defensively, retain raw values, and treat type or enum additions as observed schema drift rather than inventing semantics. [QualityUpdateDeviceStatusByPolicy properties](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports#qualityupdatedevicestatusbypolicy) [Localization behaviour](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis#localization-behavior)

CSV fields beginning with spreadsheet formula characters must remain inert data in TriageMate. Any later CSV re-export must escape them for spreadsheet safety. The ingestion path must not interpret HTML, formulas, links, or commands from device names, UPNs, or alert messages.

## Expiry, timeout, and deletion

The job object exposes `requestDateTime` and `expirationDateTime`, and Microsoft calls the result URL temporary. Download must start and finish before the reported expiration time. If the URL is missing, expired, or returns an expiry failure, start a new export job under the normal schedule; do not replay or guess the SAS URL. [Export-job properties](https://learn.microsoft.com/en-us/graph/api/resources/intune-reporting-devicemanagementexportjob?view=graph-rest-beta#properties) [SAS expiry risk](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview#best-practices-when-using-sas)

Microsoft publishes no export-job service-level completion time and no polling timeout for this workflow. The implementation deadline is therefore a TriageMate operational control, not a Microsoft promise. It must be configurable within a bounded approved range and tested with a fake clock.

Microsoft documents `DELETE /deviceManagement/reports/exportJobs/{id}` as deleting a job and returning `204 No Content`. It does not say that DELETE cancels generation, retracts an already issued SAS, or guarantees removal of the exported blob. Do not describe DELETE as cancellation. A caller cancellation or local timeout should stop polling and record the attempt. Best-effort DELETE may be a separately configured cleanup action, but its outcome must not change the recorded collection result. [Delete export job](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-delete?view=graph-rest-beta)

## Semantic boundary: deployment status, not KB proof

Microsoft places this report under the Windows Expedited Update Report and says that report shows devices targeted by an expedite policy, including whether they are installing, completed, or in error. An expedited policy can cause a device to receive the latest applicable update, which may be newer than the release selected for the policy. The report's documented columns contain no KB identifier, OS build, installed-hotfix inventory, or installed package identity. [Expedite policy reporting](https://learn.microsoft.com/en-us/intune/device-updates/windows/quality-updates-policy#monitoring-and-reporting) [Latest applicable update behaviour](https://learn.microsoft.com/en-us/graph/windowsupdates-deploy-expedited-update#step-2-create-a-deployment) [Report columns](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports#qualityupdatedevicestatusbypolicy)

Therefore TriageMate may say, for example, “Microsoft reports this device as completed for expedited policy P at event time T.” It must not say “KB503xxxx is installed” from this source alone. Named-KB installation or missing-KB evidence must come from a source that reports that fact directly and must remain a separate provenance claim.

## Failure and activation rules

The source attempt fails without activation when any of these conditions occurs:

- job creation is not `201`, or the response has no usable ID;
- the response report, filter, selection, or format differs from the request;
- polling reaches `failed`, `unknown`, an unknown state, or the local deadline;
- a Graph request exhausts its bounded retry policy;
- the completed job has no usable unexpired download URL;
- the URL or a redirect violates endpoint policy;
- the download exceeds size or time bounds, or is not a safe single-file ZIP;
- the CSV header is missing, duplicated, or differs from the explicit contract;
- any accepted row has a different `PolicyId`;
- a required normalized invariant fails, or the report contains no rows when source completeness cannot be proved.

An empty but structurally valid report must be stored as an observation with an explicit `zero_rows` outcome. It must not prove that no targeted devices exist unless Microsoft provides and TriageMate records an independent completeness claim for that policy scope.

## Required synthetic contract tests

1. Exact POST method, beta path, body, select list, permission, and token audience.
2. Filter generation from a valid policy ID and rejection of raw/injected filter text.
3. `notStarted` to `inProgress` to `completed` polling with a fake clock.
4. `failed`, `unknown`, future status, timeout, cancellation, `429 Retry-After`, `503`, and retry exhaustion.
5. Job-ID path encoding and rejection of response contract substitution.
6. Missing, expired, malformed, redirected, and disallowed-host URLs, with query strings redacted from logs and evidence.
7. ZIP magic, MIME variants, size/ratio/count bounds, traversal, nested archive, duplicate member, multiple data members, corruption, and truncated download.
8. Exact 16-column CSV header, reordered-header canonicalization, missing/extra/duplicate columns, quoted delimiters, BOM, Unicode, multiline fields, malformed rows, and formula characters.
9. Cross-policy row rejection, duplicate rows, nullable identifiers, malformed timestamps, unknown enum values, and locale-dependent `_loc` values.
10. Zero rows, partial failure, replay/idempotency, provenance capture, and proof that no failure or unknown result activates a successful revision.
11. Semantic tests that reject a named-KB-installed claim derived only from this report.

## Precisely unresolved official ambiguities

These items cannot be closed from the public Microsoft documentation reviewed on 2026-08-26. The subsequent retained compatibility observations resolve the implemented canonical UUID filter, lower-camel response spelling and observed CSV timestamp form for the observed test source; they do not establish a universal Microsoft wire contract.

1. Exact live syntax and escaping for a `PolicyId` value in this report's filter. The proposed `(PolicyId eq '<policy-id>')` follows Microsoft's general export example but is not shown for this report.
2. Runtime data types, nullability, enum values, CSV encoding, and CSV member filename for all 16 fields.
3. A normative Intune download-host or redirect allowlist, and the exact response `Content-Type`. Microsoft's example shows global Azure Blob Storage and a ZIP; it does not define a universal host or MIME contract.
4. Normal job completion time, maximum job lifetime, poll interval, and whether a failed job includes machine-readable failure details.
5. Whether deleting an in-progress job cancels server work or only deletes the job resource.
6. Whether PascalCase and lower-camel localization values are both accepted. The operational guide and Graph resource schema display different casing.
7. Whether a GET poll response is a top-level job or a job under `value`. Microsoft's operational example and autogenerated GET example disagree.

Close these points only through an authorized live-contract check against a non-customer test tenant. The authorized test source source has now been explicitly authorized and verified through import/replay for its constrained contract. Keep the defensive validation and require explicit authorization for other connections; do not infer support for the remaining unobserved variants.

## Source register

All sources are Microsoft-owned and were accessed on 2026-08-26.

- [Export Intune reports using Microsoft Graph](https://learn.microsoft.com/en-us/intune/device-management/reports/export-graph-apis)
- [Intune reports and available properties](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports)
- [Create deviceManagementExportJob (beta)](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-create?view=graph-rest-beta)
- [Get deviceManagementExportJob (beta)](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-get?view=graph-rest-beta)
- [deviceManagementExportJob resource (beta)](https://learn.microsoft.com/en-us/graph/api/resources/intune-reporting-devicemanagementexportjob?view=graph-rest-beta)
- [Delete deviceManagementExportJob](https://learn.microsoft.com/en-us/graph/api/intune-reporting-devicemanagementexportjob-delete?view=graph-rest-beta)
- [Microsoft Graph throttling guidance](https://learn.microsoft.com/en-us/graph/throttling)
- [Microsoft Graph best practices](https://learn.microsoft.com/en-us/graph/best-practices-concept)
- [Azure Storage SAS security](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
- [Expedite policies for Windows quality updates](https://learn.microsoft.com/en-us/intune/device-updates/windows/quality-updates-policy)
- [Deploy an expedited quality update](https://learn.microsoft.com/en-us/graph/windowsupdates-deploy-expedited-update)
- [Microsoft Intune PowerShell export sample](https://github.com/microsoftgraph/powershell-intune-samples/blob/master/IntuneDataExport/Export-IntuneData.ps1)
