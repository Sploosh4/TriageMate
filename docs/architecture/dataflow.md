# Application data flow

The browser loads compiled React screens from FastAPI in `app`. Fixed definitions contain reviewed SQL and display bindings; the explorer submits explicit queries to the same API. There is no runtime Markdown renderer or editable page engine.

FastAPI validates models, host/origin/session boundaries and query lifecycle. The retained PostgreSQL executor parses SQL, admits approved read-only forms, applies limits and connects as the restricted reader. PostgreSQL independently enforces role permissions and read-only transactions. Classification edits use a separate constrained API and preserve original observations.

The application container also holds collection/operation code. Collection preserves original responses and bounded bundles; parsing validates source contracts and exact values; assessment applies supported identity/version rules; restricted persistence publishes evidence and provenance receipts. Failed/incomplete attempts must not replace previous usable evidence with misleading empty results. Durable state and bundles live in the application volume.

PostgreSQL stores observations, receipts, history, corrections and views in the database volume. Existing baseline, fingerprints, authority and migration/adoption paths remain intact. Delivery changes are not a schema redesign.

Microsoft inputs are operator-configured with scope/permission checks. CVE/CVSS, EPSS and KEV remain separate dated assertions. A CVE ID links assertions but does not prove installed-product applicability. Provider missing-update results, publisher fix relationships and verified installed updates are distinct evidence. Unsupported matches and absent data remain unknown.

The application does not patch devices. Windows inventory requires an authorized source-side export; Linux containers cannot inspect remote registry/Appx state. Deferred metadata and Git history do not activate collectors. See [input boundaries](../guides/DEFERRED_INPUT_RESTORATION.md), [data boundaries](data-boundary.md) and [container operation](../guides/CONTAINERS.md).
