# PostgreSQL evidence pipeline

This package supplies the self-hosted FastAPI/React application with source records, provenance, scope and history. It does not calculate combined risk scores or execute patches. See [current scope](../../docs/planning/PIVOT_SCOPE.md) and [container deployment](../../docs/guides/CONTAINERS.md). Source credentials and live collections are unconfigured by default; collector research is not installed integration.

Repository fixtures are synthetic/public. Private operator evidence stays outside Git. Historical collection results, test totals and benchmarks do not prove acceptance of a fresh container installation. The database standards remain unchanged pending discussion.

## Package responsibilities

| Package | Responsibility |
|---|---|
| `parsing/` | Source decoding, normalized records and fixed public-route definitions; no collection or database publication. |
| `collection/` | Explicit transport, durable bundle preparation, source selection and offline bundle readers. |
| `assessment/` | Evidence evaluation and applicability rules, preserving unknown and conflicting source conditions. |
| `persistence/` | Transactional publication, provenance, current projections, authority and retained-row verification. |
| `backend/configuration/` | Immutable application paths, service locations and verified storage copying. |
| `backend/database/` | Target selection, role-specific connections, current schema, future revisions, backup/restore and adoption. |

Existing root command modules remain executable entry points. Reusable code belongs to its responsibility package; imports must not start collection or services. The narrow retained-replay dependency from current CVE/GitHub publication to bundle readers is intentional: it uses offline replay and one authoritative bundle-validation contract, with no new network collection. See the [coding standard](../../docs/architecture/coding-conventions.md) for naming, dependency rules and enforced checks.

## Database setup

Compose provisions PostgreSQL and application bootstrap explicitly installs/verifies the fixture-free baseline. [Shared database contracts](../../backend/database/README.md) retain fingerprints, role separation and explicit supported migration/adoption. Ordinary imports cannot provision schema or elevate authority. Existing databases are not silently reset or adopted; recovery requires verified backup, isolated restore and attribution. Old synthetic/prepared profiles remain test/compatibility contracts, not runtime deployment models.

## Registration, snapshots and transactions

Register an immutable source scope explicitly before ingestion. Registration uses the owner connection and shared registration barrier; runtime ingestion uses the restricted pipeline writer. Scope, tenant, origin and source-contract identity must remain consistent across attempts. Register child connections with their explicit device/baseline dependencies rather than inferring them from names.

```bash
docker compose exec app python -m standalone.evidence_pipeline.commands register --scope /absolute/private/scope.json
docker compose exec app python -m standalone.evidence_pipeline.commands --help
```

The import subcommands expose their required input, execution and source timestamps through `--help`. Device-dependent inputs additionally require their saved device attempt and, where applicable, explicit software associations. Synthetic files must be explicitly synthetic; do not use them as evidence of live provider acceptance.

A current snapshot is the latest complete successful attempt for one source connection. A complete empty success can clear that connection's current observations; failure retains the previous usable success. Neither absence nor a provider Fixed event establishes remediation of an entire computer/CVE. Keep native provider identifiers, exact source records, separate collection/publication/device times, scope and receipt provenance. Unknown timestamps and applicability stay unknown.

Ingestion owns one complete transaction: source attempts, receipts, projections and checkpoint changes either commit together or roll back. A caller must not report durable success before commit. Replaying the same execution and bytes must not duplicate records; changed payloads, scopes or bindings under a retained execution are errors. An uncertain commit requires inspecting the existing execution, not inventing a replacement identity and assuming the first write failed.

Intune inventory retains software even without CVEs or associated devices. App-to-device associations use a pinned complete snapshot. Computer matching preserves tenant/origin and native identity; hostname alone cannot merge devices. Classification corrections use their constrained API and preserve original observations. These contracts do not restore a full CMDB, general ownership policy or general SQL writes.

## Microsoft collection and offline replay

Run the retained collector inside the application container with explicit private configuration accessible there. Its established import root requires the container paths in `PYTHONPATH`:

```bash
docker compose exec -e PYTHONPATH=/opt/triagemate:/opt/triagemate/backend app python -m microsoft_evidence.collector_command --help
docker compose exec -e PYTHONPATH=/opt/triagemate:/opt/triagemate/backend app python -m microsoft_evidence.collector_command --config /absolute/private/collector.json --execution-id EXISTING_EXECUTION_ID
```

A new collection requires `--allow-network`. Reusing an existing complete execution bundle replays without network access; leaving that flag off must not trigger a replacement fetch. Device-dependent collection supplies both `--device-config` and `--device-execution-id`. `--association-config`, `--predecessor` and `--since` retain their source-specific meanings and do not authorise unrelated collection.

Microsoft authority is bound to the configured tenant, resource, application, exact route and permission contract. Access tokens are opaque credentials, not evidence supplied by decoding an assumed JWT shape. Keep tokens, certificates, continuation URLs and raw provider errors out of published artifacts. The [Microsoft operation/schema map](../../docs/planning/MICROSOFT_API_SCHEMA_MAPPING.md) and [report-export contract](../../docs/planning/MICROSOFT_REPORT_EXPORT_CONTRACT_RESEARCH.md) define source distinctions and unresolved wire behavior.

Durable bundles bind scope, execution, payload fingerprints, safe failure outcomes and any pinned device snapshot or association map before publication. Unsafe permissions, symlinks, changed bindings and incomplete bundles fail rather than silently refetch. Preserve incomplete attempts for inspection; a genuinely new collection uses a new execution. Empty successes and recorded failures also retain their replay identity.

Defender findings preserve source CVE/product/version/severity and raw fixing-KB references. Unknown devices or invalid device bindings reject the collection. A full terminal page must not be treated as proof of completeness where the source contract requires a bounded response. Live entitlement and paging coverage are source-specific acceptance questions, not implications of a parser test.

Defender full assessments and delta events preserve native event instances, original timestamp precision and separate baseline/checkpoint contracts. Committed attempt/checkpoint pairs are exposed through `assessment_checkpoints`; failed imports do not advance them. Baseline/event history remains queryable through `current_assessment_baseline` and `vulnerability_event_history`. Generation overlap and checkpoint expiry follow the source contract; expired history requires a fresh baseline rather than invented continuation. Actual Fixed transitions and source entitlement/completeness need independent collection evidence; synthetic event tests are not that evidence.

The independent Defender vulnerability catalogue uses `current_vulnerability_catalogue` and retains historical claims in `catalogue_observations`. Provider catalogue EPSS without a score date is not FIRST EPSS, and aggregate exposure counts do not manufacture individual device findings. Recommendations, antivirus and policy reports likewise preserve what their source states rather than deriving unsupported applicability.

### Device-scoped missing-patch collection

The missing-patch bridge requests every device from an explicitly pinned complete Defender device snapshot through the registered `Defender/missing_patches` connection and `/api/machines/{machineId}/getmissingkbs` route. The device identity comes from the request route, not a guessed CVE/product join. Any device failure rejects the complete collection; aggregate record bounds still apply.

Registration binds the missing-patch connection to its device connection. The collector takes `--device-config` and `--device-execution-id`, with `--allow-network` for new collection. The retained source contract uses `Software.Read.All` and `Vulnerability.Read.All`; historical contract fingerprints are preserved, not rewritten. Exact replay is device-bound and offline. These missing-KB observations do not prove patch applicability, installation, CVE resolution or the deferred Intune device-specific patch workflow.

## Public collection and durable bundles

The public collector is a separate entry point with different network controls:

```bash
docker compose exec app python -m standalone.evidence_pipeline.public_collection --help
docker compose exec app python -m standalone.evidence_pipeline.public_collection --scope /absolute/private/scope.json --execution-id EXISTING_EXECUTION_ID --bundle /absolute/private/saved-bundle --replay-only
```

Use `--replay-only` to require saved evidence without network access. Do not assume this command uses the Microsoft collector's `--allow-network` flag. A new public collection follows its validated source/input pair and fixed route; it requires the user's applicable collection authority. Source-specific selectors such as CVE or MSRC month must match the retained bundle on retry. Explicit `--synthetic-input` is a labelled verification path, not a public collection result.

The [deferral/restoration guide](../../docs/guides/DEFERRED_INPUT_RESTORATION.md) owns the exact excluded source list. Retained parsers, command options, schemas or saved OSV/GitHub/vendor evidence do not activate their deferred collectors. Shared active dependencies and historical readability remain supported. Current FIRST collection is distinct from deferred historical score-date backfill.

Public evidence preserves original wire and decoded fingerprints, source URLs, publication/observation dates, native identifiers and licence/provenance metadata. Large inputs use file-backed bundles and streaming parsing where supported. A failed or cancelled import must not publish partial projections or advance a success checkpoint. Durable evidence is not disposable cache: the same URL may later return different content.

CVE Program, CISA contributor, NVD, KEV, FIRST EPSS and Microsoft advisory/KB evidence remain independently attributable. Preserve separate CVSS assessments and conflicts; no blended score or hidden winning assessment is introduced. A CVE join identifies candidate fixes, not applicability to every product/version/device. Keep CVEs without a known fix and describe them as no fix known to TriageMate.

## Queries, assessment and completeness

Analyst SQL remains read-only under the query role. Manual Microsoft classification corrections use a separate constrained API. The frontend's 45,000,000-byte complete-result budget and query deadline do not limit backend collection, import or replay bytes. Do not truncate source evidence to fit a chart. [Query execution](../../docs/planning/ui-postgresql/QueryExecution.md) describes the read-only SQL contract; fixed React screens own their display definitions.

Current computer groups, observations, receipts, candidate patch/CVE relationships and historical source records remain independently queryable. Source-identified Windows products are distinct from supported advisory mappings and exact installed-product applicability. Preserve unknown platform/version conditions, source precedence boundaries and staged-versus-installed distinctions. The [Windows inventory guide](../windows_inventory/README.md) owns its supported identity profiles and remaining limits.

Whole-product completeness reports populated applicable eligible cells for the selected current evidence, with the agreed exclusions, explicit scope and unknown applicability. Known false and zero values are populated; an empty eligible denominator is Not assessable. Domain completeness and collection coverage remain separate, and a completeness percentage does not establish device health or vulnerability coverage. Scope and current acceptance are defined in the [current scope](../../docs/planning/PIVOT_SCOPE.md).

## Separate historical-event completeness

Historical vulnerability events have their own completeness measure and are excluded from the current whole-product percentage. `historical_event_completeness_definition` describes the eligible source fields; `historical_event_completeness_cells` exposes values, populated state, applicability, connection, event fingerprint and receipt. `historical_event_completeness_summary(uuid[])` takes explicit source connections and returns populated/applicable counts, unknown applicability, distinct events, percentage and assessment.

Duplicate selections and repeated observations within one connection do not add cells. Different connections and tenants remain separate; combined counts are not globally unique events. Internal keys, fingerprints, collection clocks and derived joins are inspection metadata, not eligible source cells. Known false, zero and explicit empty sets count as populated. Null, blank and all-null change pairs do not. Missing optional source fields remain missing rather than being silently excluded. No eligible events yields NULL and Not assessable. This provisional source-contract measure does not assess current device health or prove remediation.

## Operations, failures and recovery

Operations uses explicit private configuration, Running/Off/Maintenance modes, durable checkpoints, worker leases, notifications and cancellation. An installed collector or discovered configuration file does not activate schedules. The default container install supplies no Microsoft credentials or live source configuration.

Collection failures retain prior usable evidence and create their source/scope-specific failure history and critical notification. Reading or dismissing a notification does not resolve the underlying failure. A complete success for the same source/scope resolves an ordinary failure episode while retaining the failed attempt. Planned shutdown, provider outages, storage conditions and recovery-required states retain their distinct contracts.

Stop through the owning application's normal drain path, retain terminal receipts and verify worker termination. Preserve interrupted bundles and uncertain commits for inspection. Do not treat a missing success response as authority to discard evidence or advance a checkpoint. Moving retained evidence requires coordinated backup/restore, attribution, activation and rollback checks; never treat a copy as proof of verified migration.

## Verification

Follow the [root verification commands](../../README.md#development-and-verification) and run tests for the changed parser, assessment, publication, authority or command contract. Source-specific corruption, malformed input, cancellation, replay, restricted-role and rollback checks remain necessary. Whole-dataset attribution checks remain separate from focused parser tests. Historical gates do not establish current acceptance.

Parser scratch indexes and the retained-evidence verification spool use SQLite-owned anonymous temporary databases on the supported Linux runtime. Normal close and process termination release their scratch files without deleting retained bundles. Reference mappings retain payloads once and store lookup identities; nested iteration uses the backing index's explicit insertion ordinal. Sorting a view's implicit rowid would create an unnecessary temporary payload copy. Regression checks preserve exact values/order and reject temporary sorting in the actual iteration queries. Large scratch records use lossless compression when it reduces their stored size; short or incompressible records remain raw. Decoded lengths are checked and cache admission uses the uncompressed size, so compressibility cannot admit oversized records into the cache. This private per-process format does not alter stored evidence or reusable bundles. Disk exhaustion or interrupted verification remains a failure, never permission to skip rows.

Current installation/adoption tests use independently frozen synthetic predecessors and exact authority contracts. Actual collection, private replay and synthetic tests remain distinct evidence. Complete applicable checks before claiming the whole refactor ready.
