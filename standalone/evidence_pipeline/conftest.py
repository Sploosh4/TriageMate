"""Keep shared evidence-schema tests on one of the bounded xdist workers.

This directory tests one retained PostgreSQL schema, including rollback-only
DDL/role drift and baseline verification. Those administrative mutations cannot
run alongside another test's multi-connection verification. Concurrency tests
still create their own connections/threads inside the scheduled test.
"""

from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    for item in items:
        if Path(str(item.path)).resolve().is_relative_to(HERE):
            item.add_marker(pytest.mark.xdist_group("retained_evidence_schema"))
