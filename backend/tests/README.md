# Backend tests

Tests cover Microsoft transport and source contracts, shared database authority, parsing, provenance and failure isolation. Provider tests use synthetic transports rather than tenant credentials. Run database integration tests against isolated disposable test storage, never the operator's application volume.

The [project guide](../../README.md) describes container setup and focused verification. FastAPI transport tests live in `app/tests/`; retained read-only query, parser and collector tests remain with their modules. Retired notebook editing does not remove the reader, cancellation, exact-value or evidence-integrity contracts.
