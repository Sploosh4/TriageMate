# Confirmed TriageMate scope

The user-authorized overhaul makes TriageMate GPL-3.0-only, open-source-ready and self-hosted. It is in development with no deployed users. Prepare local code/container setup; visibility changes, publication, external deployment and `main` integration need applicable user authorization.

Use exactly two runtime containers: PostgreSQL 16 with a persistent database volume, and FastAPI/React with collection/operation code. Preserve application state/bundles in a separate volume. Default access is local through `127.0.0.1:5190`; PostgreSQL has no host port.

The user approved fixed React screens and a read-only SQL explorer instead of the Markdown page engine and arbitrary notebook editing. Preserve existing page analyses as code-backed screens. FastAPI replaces the custom HTTP layer.

Discuss database standards before changing them. Keep fingerprints, role/authority, migrations/adoption and provenance in this pass. See [standards tradeoffs](../architecture/REFACTOR_STANDARDS.md).

Keep supported Microsoft technical inputs and public CVE/CVSS, EPSS and KEV. Research reusable open-source collection/validation tools before replacing collectors. Identity, exact values, dates, completeness and unknowns remain requirements. Patch execution, custom combined scoring, full CMDB, Queue/Case, Nessus, Network visualization, Copilot and Sentinel remain outside scope. Deferred collectors are not restored by this refactor.

Historical programme operating rules/architecture are superseded, and obsolete recovery history has been removed. Retained historical identifiers create no recovery guarantee or new collection authority. See [input boundaries](../guides/DEFERRED_INPUT_RESTORATION.md) and [data boundaries](../architecture/data-boundary.md).
