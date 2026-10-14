# Standards and simplification decisions

The user selected GPL-3.0-only, container-only self-hosting, FastAPI, fixed React screens and a read-only SQL explorer. The user requested discussion before database changes. This first pass changes delivery/presentation while retaining schema, evidence model, fingerprints, authority and migration/adoption behavior.

## Current standards

| Area | Current contract | Purpose |
|---|---|---|
| Provenance | Source scope, bytes/hash, observation time, receipt and origin | Makes evidence inspectable and separates synthetic/public/operator observations |
| SQL | Parsed read-only forms, relation/function limits, restricted reader and read-only transactions | Keeps exploration from becoming arbitrary database execution |
| Database integrity | Frozen baseline artifacts and complete schema/authority fingerprints | Detects edited grants, ownership, functions and schema beyond a version number |
| Database changes | Explicit provisioning, supported revisions, adoption and verified backup/restore | Avoids silent reset/adoption on startup |
| Inputs | Identity, exact values, completeness, replay/idempotency and failure isolation | Generic collection does not prove device matching or complete evidence |
| Code | Ruff, staged strict Python typing, strict TypeScript, ESLint, Prettier and behavior tests | Established tools and reproducible failures |
| Delivery | Locked dependencies, immutable base images, two services, named volumes and loopback | Reproducible installation through one supported runtime |

GPL-3.0-only is the selected license for current first-party code. Libraries, parser sources and input data retain their licenses/notices, and valid earlier grants are not revoked. See [licensing and redistribution](licensing.md). Preparing the license does not publish the private repository.

## Database tradeoffs to discuss

| Option | Benefit | Cost or risk |
|---|---|---|
| Keep fingerprints/adoption | Strong drift detection and compatibility with retained evidence/authority | More maintenance across schema, grants and installation profiles |
| Ordinary versioned migrations plus focused authority checks | Easier upgrades and familiar contributor workflow | Version labels cannot detect edited grants/functions; tests must deliberately replace removed guarantees |
| Reduce/redesign schema | Removes unused tables and overlapping abstractions | Requires field/consumer audit, evidence semantics and export/restore plan to avoid losing useful provenance |

Recommendation: move gradually toward ordinary versioned migrations while retaining provenance, reader/writer separation and direct authority tests. First identify each fingerprint/adoption guarantee, decide whether it remains necessary and prove its replacement. This is a recommendation awaiting discussion, not permission or an implemented database change.

Schema reduction is a separate step. Inventory populated tables, writers, UI queries, replay consumers and retained sources first. With no deployed users, a deliberate fresh-install path may be viable, but existing local evidence must still be preserved rather than silently deleted.

## Recommended next work

1. Repeat container startup, restart/persistence, read-only SQL and UI/API failure checks on each release. These checks passed for this local refactor; source collection still requires separate configured-input validation.
2. Agree on database guarantees and simplify one bounded surface at a time.
3. Compare maintained Microsoft adapters on synthetic fixtures; keep source validation, provenance, completeness and matching explicit.
4. Prefer official CVE/CVSS, EPSS and KEV feeds where an aggregator adds a service without removing meaningful code. Compare exact identity, dates, score versions, licensing and incremental refresh.
5. Add tested private backup/restore commands, retention/freshness policy and bounded collection resources.
6. Decide authentication/TLS and multi-user authorization before network exposure.

See source-backed [Microsoft](../research/MICROSOFT_COLLECTORS.md) and [public feed](../research/PUBLIC_FEEDS.md) candidates. Tool availability is not suitability; run a bounded experiment before replacing collectors.
