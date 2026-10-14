# Read-only Windows inventory

This retained read-only inventory contract supports optional authorized source-side exports imported into the self-hosted application. The Linux container cannot inspect another machine's registry automatically. Native identity, recognition, public advisory matching and exact CVE/update applicability remain separate questions. See [current scope](../../docs/planning/PIVOT_SCOPE.md) and [container deployment](../../docs/guides/CONTAINERS.md). No source credentials or live inventory collection are configured by default.

Writes require the shared baseline and restricted writer. Ordinary inventory/component/OS-review imports never migrate or repair schema. The existing database lifecycle remains intact pending the [standards discussion](../../docs/architecture/REFACTOR_STANDARDS.md); see [database contracts](../../backend/database/README.md) for explicit backup/adoption.

## Collection, staging and durable evidence

The collector verifies the independently configured MachineGuid, tenant and device before enumeration. It reads machine uninstall registry views, already-loaded user hives and explicit Appx package types: Main, Framework, Resource, Bundle, Xap and Optional. It does not load hives, query `Win32_Product`, install or repair software, read user documents/private keys or change devices. Portable programs and unloaded-user registry entries are outside this enumeration. An uninstall registration is not proof that binaries exist; staged Appx packages are not automatically installed applications.

The retained source-side transport is optional and requires explicit authorized configuration; it is not a separate runtime service in the two-container deployment. `transport.collect()` takes an explicit owner-only SSH configuration, one host alias and validated device binding. Existing host-key trust, noninteractive authentication, disabled forwarding and disabled proxy commands/jumps are required. The fixed script travels on stdin; credentials are not command-line arguments.

A configurable overall deadline covers collection and validation. Local SSH processes are killed and reaped on failure/cancellation. Each remote invocation has a unique marker and in-process deadline. Failure permits one additional bounded cleanup attempt targeting only that exact invocation and checking creation identity; loss of connectivity does not remove the remote deadline. This creates no persistent remote service or task. Failed output is not published, and raw stderr stays out of shared errors.

Production `staging.stage()` performs complete-document validation with streaming passes and a disk-backed identity index before exposing rows. It retains the exact source-byte SHA-256 and rejects duplicate keys/identities, changed bindings, incorrect counts and incomplete output. Its row iterator and source spool are valid only inside their context and must be durably consumed before success. There is no backend download byte ceiling; this is not a guarantee that every record or downstream evaluation has constant memory use. `contract.validate()` is the in-memory equivalent for small fixtures.

`bundle.prepare()` stores exact bytes and a private receipt binding source, execution, device and pinned prerequisite attempt. Offline replay validates those bytes without SSH or fixture rereads. A failed transport records a safe failure code and no partial observations. Interrupted writes remain explicitly incomplete; they do not silently recollect under the same execution. Preserve them for explicit recovery rather than deleting or retrying by assumption.

Owner-only registration fixes the source connection's tenant, MachineGuid, registration identity, provider-native ID and device-source connection. Restricted persistence pins a complete device observation and stores source revisions, receipts and the complete validated row set transactionally. Failed imports preserve previous complete current inventory. A complete empty success replaces current observations while remaining inspectable in history. Synthetic verification does not establish actual authorized source collection.

## Native identities, manifests and installation state

Preserve original names, versions, package families, publishers, architectures, flags, source kinds and per-user installation states. Missing or conflicting source identity remains inspectable rather than being replaced with guessed product names. Source-kind completeness measures eligible reported fields; inferred identities and bundle declarations must not inflate inventory completeness.

Appx manifests can provide names and declared identities, but a manifest result is separate from the package registration. Conflicting or unavailable manifests cannot establish applicability. Original version namespaces remain distinct: package versions must not silently become Windows build numbers, upstream releases, CPE versions or installed-fix claims. Resource, framework, bundle and optional-package flags retain their specific meaning.

Bundle manifests retain declarations as separate records scoped to the same snapshot/device/tenant. Candidate associations, actual Installed-user evidence, architecture/version agreement, stubs and ambiguous members remain distinguishable. A declared member or absent member registration is not proof that an application is installed or missing. Relationship views expose supporting source rows and unresolved mappings rather than manufacturing membership.

### Published Windows application package identities

Supported package recognition uses exact published references retained under [baseline references](../../backend/database/baseline/references/), with their source URLs, retrieval times and content hashes. Store, framework, native-framework, system-component, Windows CBS, Windows Security, inbox and Cloud Experience Host profiles retain their individual publisher/family/architecture/package-kind and installation-state conditions. Similar names or an unlisted alias do not satisfy an exact profile.

A recognized source identity is not a CNA/CPE alias, vulnerability verdict or patch-applicability claim. The UI can show **Source identified; advisory mapping unknown** while keeping original names and versions. Missing identity remains unknown, and staged-only packages stay distinct from installed software. Media-product and public-version evaluations preserve exact publisher conditions and unsupported namespaces rather than treating every recognized package as evaluated. Historical observation totals do not establish current coverage; unverified mappings remain unknown.

## Independent component checker

`component_check.py` is an offline evaluator for the complete native inventory envelope or a separately validated selected-component capture. It takes an independently configured `DeviceBinding`, observation-bound OS/condition evidence and reviewed declarative public-source rules. It performs no collection, repairs, database writes or updates when invoked through the file checker:

```bash
docker compose exec app python -m standalone.windows_inventory.component_check_commands \
  --inventory INVENTORY_FILE --binding BINDING_JSON \
  --evidence RULE_EVIDENCE_JSON --sources CONTENT_ADDRESSED_DIRECTORY
```

Run from the repository root. Replace `--inventory INVENTORY_FILE` with `--selected SELECTED_FILE` for a selected capture; the two options are mutually exclusive. The command writes JSON to stdout. Keep private operator inputs, source files and output in the private locations permitted by lab authority, including authorised configured storage; never commit their identities or payloads.

The binding contains `machine_guid`, `tenant_id` and `device_id`. Complete-inventory rule evidence uses `triagemate-component-rules-v1` with `context` and `rules`; selected rules use `triagemate-selected-component-rules-v1` without a supplied context. The checker validates retained content-addressed sources, exact identity, version namespace, observation window and source anchors. The implementation dataclasses define the full field contract. Empty reviewed rules are valid and produce unknown answers; no reviewed production rules currently establish complete component/CVE coverage.

Selected captures preserve their own envelope, requested-name accounting, exact source bytes, native OS facts, Appx XML identity and retained servicing-manifest bytes. They must not be converted into a fabricated complete inventory. Selected applicability requires explicit matching manifest processor architecture; an omitted optional architecture remains unknown. A conflicting or unavailable manifest, missing compressed bytes or uncollected condition cannot establish applicability. Hardlink and decoder attribution remain collector observations, not proof of active file integrity.

`servicing_manifest.py` validates decoded XML and its hash, requires a complete unambiguous root assembly identity, and preserves literal file/dependency attributes. Parent applicability references are not dependency edges; basenames and path macros are not normalized into matches. Compressed decoding, active-hardlink attribution and current file integrity remain separate stages.

`update_required` and `fix_present` are scoped to a reviewed rule/CVE and its admitted evidence. They do not establish overall vulnerability coverage, Windows Update completeness or Defender's internal assessment coverage. Unknown conditions stay explicit. Windows 10 and Windows Server acceptance are outside this bounded checker.

## Component assessment workflow integration

The normal inventory worker commits inventory and its default component assessment together. It introduces no synthetic rule, additional network request or schedule activation. Callers consume all source/result streams before commit; checking or persistence failure rolls back both, preserving prior successful history. Same inventory and evaluator replay is idempotent; changed evaluator or reviewed evidence creates separately attributable history.

Selected captures are imported explicitly against an existing registered inventory snapshot:

```bash
docker compose exec app python -m standalone.windows_inventory.selected_component_commands \
  --inventory-snapshot UUID --selected SELECTED_FILE \
  --binding BINDING_FILE --evidence EVIDENCE_FILE --sources SOURCE_DIRECTORY
```

The command validates its retained inputs, uses the restricted writer and acknowledges only after commit. Selected history retains independent observation times and original bytes. Successful completed assessments and selected captures update committed-evidence refresh; rollback or interrupted evaluation does not. The fixed React dashboard uses reviewed SQL definitions in `ui-engine/src/dashboard.json`; no Markdown page engine is involved.

Evaluator identity is part of deterministic replay. `engine_identity.py` recognizes only explicitly recorded exact predecessor fingerprint equivalences. Refactoring must not introduce broad fingerprint normalization or rewrite retained reports to match new code. Keep the original engine identity and source provenance inspectable.

## Dated Windows OS evidence review

`os_update_evidence.py` and restricted `os_update_store.py` combine retained native identity, bounded HotFix observations, complete Defender machine and per-device software/vulnerability exports, and an exact-machine missing-KB export. They retain original UTF-8 documents, request receipts, hashes and separate observation times. This is offline evidence review, not new collection or a full Windows Update scan. Each export must have one terminal page; pagination is rejected rather than truncated.

After verified baseline installation or adoption, import a prepared private bundle from the repository root:

```bash
docker compose exec app python -m standalone.windows_inventory.os_update_store BUNDLE \
  --inventory-attempt UUID --binding BINDING_JSON --origin lab
```

Use `--origin synthetic` only for explicitly synthetic evidence. The caller supplies the independently configured device binding and an existing complete native inventory attempt. The bundle declares `triagemate-windows-os-evidence-v1`, origin, collection tenant, exact `queried_kbs` and `sources`. Every source contains original `text` and `sha256`; required keys are `native`, `installed`, `requests`, `devices-0`, `software-inventory-0`, `vulnerabilities-0` and `current-missing-kbs-0`. The command does not fetch URLs, rerun collectors, modify a device or activate schedules.

Selection supports explicitly identified Windows 11 24H2/25H2 x64 observations. It requires a unique compatible per-device Windows version and provider architecture, matching registration, bounded same-day native/export association and provider activity within 24 hours of the native observation. A competing provider active after the selected record first appeared blocks selection. Merger/duplicate/exclusion flags prevent that provider being selected. Multiple compatible identities, conflicting same-time reviews or newer native inventory keep selection unresolved. Historical providers are retained; hostname matching never transfers their findings.

The 24-hour bound is a conservative import association rule, not a freshness guarantee. The database independently checks resolved identity, exact-endpoint receipts, observation times and competing identities. Missing/non-integer Windows revisions, incompatible installed-update observation times and an incorrect bounded HotFix query scope are rejected. Unresolved reviews also derive their ordering timestamp from complete retained request receipts within the native/export observation window; direct writes cannot bypass that rule or substitute a historical provider.

`current_windows_os_reviews` exposes the decision and source references, while `current_windows_os_provider_evidence` exposes alternatives. `current_windows_os_findings` uses only the selected identity's retained export. `current_windows_os_update_status` separates observed installed KBs, provider-reported missing updates, historical candidates with exact-product MSRC replacement paths and candidates with unknown applicability. `current_windows_os_replacement_evidence` retains supporting edges and receipts. A replacement path does not prove exhaustive per-CVE remediation; an empty missing-KB export means none reported at that request time, not fully patched. HotFix absence does not mean not installed.

Imports are transactional and idempotent by inventory binding, complete bundle bytes including request times, and evaluator identity. Readers cannot write and the runtime writer cannot update/delete reviews. Failures preserve earlier records. Only committed sealed evidence changes refresh visibility. A retained OS review does not establish broader platform coverage or the unresolved Intune device-specific applicability workflow.

## Verification

```bash
python -m pytest standalone/windows_inventory -q
```

Run contributor tests in an environment with the pinned development dependencies; the application runtime image does not include pytest. Use isolated synthetic targets for behavioral and authority checks. Preserve direct negative coverage for wrong device/tenant/identity, malformed and duplicate input, incomplete output, unsupported versions, source-hash tampering, role restrictions, cancellation, rollback and deterministic replay. Identity-profile tests preserve every profile-specific condition rather than sampling a shared happy path. Retained actual replay, fresh collection and synthetic tests are distinct evidence categories.

Follow [root verification](../../README.md#development-and-verification). Historical test totals, counts and benchmarks do not replace current whole-task evidence.
