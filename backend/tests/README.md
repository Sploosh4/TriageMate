# Test categories

The default `pytest tests/` run remains the project correctness gate. The
markers below make tests with additional runtime or artifact expectations
discoverable without removing them from CI.

| Marker | Meaning | Examples | How to run |
| --- | --- | --- | --- |
| `artifact` | Needs a committed or locally generated ML artifact; it may skip when the artifact is absent. | `test_npz_metadata.py`; artifact cases in `test_feature_parity.py` | `pytest -m artifact` |
| `integration` | Exercises multiple application components together. | `test_integration.py` | `pytest -m integration` |
| `benchmark` | Measures performance and is normally run through the dedicated benchmark workflow. | `test_benchmark.py` | `pytest -m benchmark` |
| `fuzz` | Corpus-backed robustness test; opt-in through `TRIAGEMATE_RUN_FUZZ=1`. | `test_fuzzed_ingest.py` | `TRIAGEMATE_RUN_FUZZ=1 pytest -m fuzz` |
| `load` | External Locust workload, not a pytest-collected test. | `tests/load/locustfile.py` | `just stress-test` |

`xdist_group(name)` is reserved for tests that must share a serial execution
group because they mutate a common resource. Prefer isolated fixtures over
adding new uses of that marker.

## Deliberately not covered here

`POST /api/ingest` currently persists a `(vulnerability_id, hostname)` pair
with a database uniqueness constraint but does not expose an API-level
duplicate-ingest contract. Do not add a test that accepts the current database
error as intended behavior. Add a focused duplicate test only with a
corresponding endpoint contract and implementation.
