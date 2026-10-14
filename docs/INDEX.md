# TriageMate documentation

TriageMate is a GPL-3.0-only, self-hosted application with a FastAPI/React container and a persistent PostgreSQL container. It is in development; build/test results must be distinguished from production acceptance.

| Need | Reference |
|---|---|
| Container setup, storage and recovery | [Container guide](guides/CONTAINERS.md) |
| Hosted container CI and private runner boundaries | [CI runners](guides/CI_RUNNERS.md) |
| Refactor scope and pending decisions | [Current scope](planning/PIVOT_SCOPE.md) |
| Retained standards and simplification tradeoffs | [Standards discussion](architecture/REFACTOR_STANDARDS.md) |
| Input/application flow | [Data flow](architecture/dataflow.md) |
| Fixtures and private operator evidence | [Data boundary](architecture/data-boundary.md) |
| Code/module conventions | [Coding conventions](architecture/coding-conventions.md) |
| Microsoft collector alternatives | [Microsoft research](research/MICROSOFT_COLLECTORS.md) |
| CVE, CVSS, EPSS and KEV tools | [Public feed research](research/PUBLIC_FEEDS.md) |
| Exact Microsoft API/field mapping | [Generated catalogue](planning/MICROSOFT_API_SCHEMA_MAPPING.md) |
| Intune report contract and unknowns | [Export contract](planning/MICROSOFT_REPORT_EXPORT_CONTRACT_RESEARCH.md) |
| Source semantics and license references | [Source research](planning/MICROSOFT_SCORING_INPUTS_RESEARCH.md) |
| Active/deferred input boundaries | [Input inventory](planning/SPRINT_INPUT_INVENTORY.md) and [restoration](guides/DEFERRED_INPUT_RESTORATION.md) |
| SQL execution | [Query contract](planning/ui-postgresql/QueryExecution.md) |
| Retained synthetic schema data | [Fixture reference](planning/ui-postgresql/TableGuide.md) |
| Offline EPSS parser/import | [Import](planning/ui-postgresql/SyntheticEpssImport.md) and [persistence](planning/ui-postgresql/SyntheticEpssPersistence.md) |
| Project licensing and redistribution | [Licensing policy](architecture/licensing.md) |
| SQL parser licensing | [Third-party notices](ui/engine/ParserThirdPartyNotices.md) |
| Bundled frontend licensing | [Notice maintenance](ui/engine/FrontendThirdPartyNotices.md) and [verbatim notices](ui/engine/FrontendThirdPartyNotices.txt) |

Historical operating/sprint plans, executable Markdown pages and obsolete recovery history have been removed. Retained source/construction identifiers are provenance records, not promises of recoverable Git objects. They do not authorize restoring retired features or changing database standards. Module READMEs describe technical contracts; the container guide owns deployment instructions.
