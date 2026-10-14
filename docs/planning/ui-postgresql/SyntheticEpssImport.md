# Offline synthetic EPSS import

This is the retained offline synthetic parser/import contract. It is separate from public FIRST collection. See [persistence](SyntheticEpssPersistence.md) and the [pipeline](../../../standalone/evidence_pipeline/README.md). Historical implementation test counts are not current refactor acceptance.

## Parser contract

`standalone/synthetic_epss.py` parses bytes into immutable records without files, network or database calls. Explicit synthetic attribution uses origin, fixture ID, fixed source scope `offline-synthetic-epss-v1` and contract version. The fixture contains invented CVEs and is not public provider evidence.

Input is UTF-8 JSON with exactly `origin`, `fixture_id` and `data`. Records require canonical uppercase CVE ID, `epss` and calendar `date`; percentile/model version may be absent or null and remain unknown. Blank model versions, unknown fields, duplicate keys or CVE/date rows, malformed UTF-8/JSON, invalid dates and missing required values reject the complete payload. Empty data is a valid empty observation set, not zero scores.

Scores are plain decimal strings in [0,1], without exponents/spaces. Numbers, floats, booleans, nonfinite/out-of-range values and excessive PostgreSQL numeric scale reject rather than round. Decimal handling is independent of the caller's context. Exact zero is retained.

`fingerprint(raw)` binds contract, scope and exact bytes with SHA-256/NUL separators. It also identifies invalid input for failure records. Execution IDs and collection clocks are not input identity; whitespace changes the byte identity.

Observation hashes bind CVE, date, exact decimal scores, model version, attribution, scope and contract. Equivalent decimal trailing zeros and absent/null optional values have equivalent semantic hashes. Record order does not change revisions; changed facts create history.

## Persistence and authority

- Identical execution/input replays the stored outcome, including failure; changed input under that execution is rejected.
- A new execution with identical facts reuses revisions while retaining independent receipts/observations.
- Resolve uncertain commits from stored state before retrying; do not assume acknowledgement loss means rollback.
- Invalid input publishes no partial evidence; failed outcome recording remains explicit uncertainty.
- Import uses the restricted importer, never owner/UI reader authority. PostgreSQL independently validates the envelope and source scope.
- Baseline/slice checks retain exact original IDs/content/counts and reject unexplained additions.

The consolidated baseline includes this contract. The first container refactor keeps schema/authority fingerprints and migration/adoption protections pending [standards discussion](../../architecture/REFACTOR_STANDARDS.md). Importing synthetic EPSS does not enable network collection, schedules, retention or classification policy.

## Verification

Retain precision/scale, zero/unknown, malformed/duplicate, whole-payload rejection, fingerprint, replay, concurrent execution, rollback, function-bypass and authority tests. Pure parser checks are `standalone/test_synthetic_epss.py` and `standalone/test_epss_lookup.py`; database behavior/authority checks are under `ui-engine/postgres/epss/`. Use isolated synthetic targets and the dependencies/checks described in [README](../../../README.md#development-and-verification).
