# Offline synthetic EPSS persistence and failure verification

This is a retained technical contract with historical verification observations, not acceptance evidence for the new refactor. The offline importer processes explicitly synthetic fixtures in the shared local PostgreSQL instance. It does not fetch sources or run a scheduler. Current public EPSS collection and operational behavior are documented in the [pipeline guide](../../../standalone/evidence_pipeline/README.md).

## Installation and verification

The consolidated baseline includes the offline synthetic EPSS fingerprint column, fixed synthetic source connection, restricted importer/function roles and the complete `epss_import` schema. Fresh synthetic setup uses `ui-engine/postgres/manage.py setup`; existing explicitly provisioned targets use the shared baseline installer with their intended profile. EPSS no longer has a separate historical migration command or schema projection dispatcher. Current schema and authority are verified through `backend.database.schema`, while `ui-engine/postgres/epss/baseline.py` retains full row/provenance attribution checks.

Existing v113 databases require the verified backup, isolated restore and explicit adoption workflow. Setup never silently upgrades a legacy installation, resets evidence or replaces a provisioned password. Role provisioning and credential recovery remain explicit administrative operations; normal import and UI startup neither install schema nor alter grants. Credentials stay in private local files outside Git.

## Authority and transaction boundary

`tm_epss_importer` can connect and execute only `epss_import.submit(uuid,bytea)` and `epss_import.resolve(uuid,bytea)`. It cannot directly insert/update/delete evidence, create permanent/temporary tables, become the owner/function role, use internal helpers or access files. The UI reader cannot execute the importer functions.

The SECURITY DEFINER functions use fixed SQL, a fixed source connection and `search_path=pg_catalog`. Their owner, `tm_epss_function`, is NOLOGIN/non-superuser without role memberships or schema creation authority. Its mutations are limited to INSERT on five evidence/provenance tables and UPDATE of three attempt-outcome columns. Existing cross-table provenance triggers require read access to the original evidence/mock tables; no mutation authority on those other tables exists. Required calculation, JSON, operator/cast and trigger metadata helpers are granted to this internal role, not to the importer login or UI reader. A missing `textin` permission was corrected specifically; no blanket type-input function grant was made.

Raw bytes reach database validation even when the pure Python parser rejects them, so malformed input can receive a durable failed attempt. The database independently validates the complete envelope and all records, including duplicate JSON keys, Unicode-only blank model versions, decimal strings, dates and CVE identity. Existing CVEs belonging outside this slice cannot be adopted. Callers cannot supply a source connection, stored content hash, outcome, collection time or observation ID.

One transaction-scoped advisory lock serializes this small offline source. The function validates before evidence writes, then writes attempts, revisions, receipts, CVE identities and observations inside a subtransaction. It forces deferred provenance checks before success. A failure rolls back all evidence for that execution and records a sanitized failure outside the rolled-back subtransaction. Failure-recording errors escape; they are never reported as successfully persisted failures.

## Replay and stored facts

- Exact input fingerprint includes contract, fixed scope and raw bytes. Same execution and same bytes returns the stored outcome, including failure. Different bytes under that ID are rejected without altering it. A fresh attempt uses a new UUID.
- Semantic source hashes match the approved Python parser. Unchanged content in a new execution reuses revisions and creates separate receipts/observations. Changed probability, percentile, date, model or attribution creates new history.
- IDs are deterministic, source-scoped SHA-256-derived UUIDs, with database identity conflicts failing rather than overwriting evidence. No general preferred-score rule.
- Empty success creates no observations, implied zero, snapshot selection or deletion.
- Collection timestamps are database-generated. Unknown source update time, URL and model version remain NULL; source score date is retained separately.

The supplied fixture's stored probability is exactly `0.12345678901234567890123456789`, with percentile `0.75`; the second probability is exactly zero with unknown percentile/model. A changed-input execution retained percentile `0.76` alongside `0.75`. The original two seeded EPSS rows are unchanged. Verification executions remain separately attributed under the fixed synthetic connection, including verification-generated inputs; they are not baseline rows.

## Uncertain commits

`standalone/synthetic_epss_import.py` uses only the importer credentials and fixed functions. After a connection/commit acknowledgement failure it calls the resolver. The resolver waits on the same transaction lock before reading stored state. A recorded success or failure is returned unchanged. If the preceding transaction ended without an outcome, the client may retry the exact execution once; submit rechecks identity under the lock. Failure to confirm state raises `OutcomeUnknown`. The client never writes a replacement failure in response to an uncertain commit.

```sh
.venv/bin/python -m standalone.synthetic_epss_import \
  standalone/fixtures/synthetic_epss_v1.json \
  --execution-id YOUR-NEW-UUID
```

Use the same UUID and exact file to resolve an uncertain result; use a new UUID for a new attempt after a recorded failure. Exit status is 0 for recorded success, 1 for recorded failure, and 2 for rejection/unconfirmed storage. No network source fetch or automatic startup import occurs.

## Direct verification

`ui-engine/postgres/epss/test_import.py` uses the actual importer login in the retained database. Direct function calls bypass the Python validator to prove database checks. Fault constraints target only test execution IDs/receipts, are removed in finally, and verify rollback of newly inserted CVEs, revisions, receipts and observations. The additional adversarial suite extends these direct boundary checks.

Coverage includes exact decimals, same-ID replay/mismatch, unchanged-content receipts, changed history, empty success, malformed/invalid/foreign-scope input, concurrent same-ID requests and competing payloads, direct authority denials, inability to record failure, lost success/failure commit acknowledgements, no-outcome retry and unavailable outcome resolution. The acknowledgement loss is injected after an actual commit; reconnect and stored-state resolution use real PostgreSQL. It is not a physical network-disconnection test.

`epss/baseline.py` preserves exact baseline counts and typed field values, rejects missing/altered baseline records and unexplained extra rows, and validates permitted slice provenance, hashes and deterministic identities. Failed attempts cannot own observations. It does not relax the whole database to a minimum row count. The six reservation tables contain no baseline fixture rows. Current pipeline notifications and classification corrections can populate the corresponding `evidence` tables; recognized additive migrations are verified separately. The UI reader must remain unable to invoke importer functions.

```sh
.venv/bin/python -m pytest standalone/test_synthetic_epss.py standalone/test_epss_lookup.py ui-engine/postgres/epss/test_import.py -q
.venv/bin/python -m unittest discover -s ui-engine/postgres -p 'test_*.py' -v
```

## Additional failure and permission coverage

`ui-engine/postgres/epss/test_adversarial.py` reuses the direct importer helpers. Query-slot cleanup regression coverage is documented in [QueryExecution.md](QueryExecution.md#restart-cleanup-regression-verification).

- Nine direct-call inputs bypass Python validation: invalid top-level shapes, null data, exponent/negative/over-scale scores, caller-supplied scope/execution fields and an embedded NUL. Each returns an invalid-input failure, without committing test evidence.
- Targeted, initially deferred constraint triggers exercise evidence failure, failure-recording failure, and both together. Evidence failure records a stable replayable failure; failure-recording errors propagate without falsely claiming a recorded outcome. Combined failures leave no attempt, receipt, observation or revision changes. All temporary triggers/functions are removed afterward.
- Conflicting valid/invalid executions are tested in both winning orders. The second actual importer connection is observed waiting on the advisory lock until the first commits, then rejects the changed input. The first success or failure remains the recorded outcome.
- Simulated loss of a commit acknowledgement followed by an unavailable resolver produces `OutcomeUnknown` and no replacement write. Later replay returns the original success or failure, with the entire stored attempt unchanged.
- Both actual roles are denied INSERT, UPDATE, DELETE and TRUNCATE on all 47 tables (376 write-denial checks). Reader checks explicitly override the default read-only transaction setting so table grants are independently exercised. The reader can SELECT all 47 tables; the importer cannot directly SELECT them. Private helper grants are checked by the owner and non-null direct calls are denied for both roles. The UI reader cannot call submit or resolve.

Run from the repository root, with the existing approved PostgreSQL instance running:

```sh
.venv/bin/python -m pytest ui-engine/postgres/epss/test_adversarial.py -q
```

These tests deliberately retain committed synthetic replay outcomes. The test-only fault triggers simulate database constraint/storage-path errors. Lost acknowledgements and resolver unavailability are injected around real commits; they are not physical connection-failure tests. These tests retain synthetic outcomes; running them is not a destructive restore.

## Deployment and limits

The container database includes this retained offline synthetic import contract. The application reader cannot execute importer functions; its SQL explorer can inspect permitted evidence views. No Markdown note or graph-definition persistence is required. Public EPSS collection is a separate pipeline path.

The importer remains serialized per source, with attributed execution history. Catastrophic storage failure can prevent failure recording; report uncertainty rather than inventing an outcome. Historical acknowledgement-loss tests use real commits with injected resolver/response failures and do not prove resilience to every physical failure. Match database target and restricted importer credentials explicitly; never use owner credentials as a runtime importer fallback.
