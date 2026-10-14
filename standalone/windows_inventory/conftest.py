"""Run retained-database inventory tests with other schema-mutating tests.

Pure parser tests remain parallel. Database fixtures use the shared retained
schema and migration locks, so they must share the existing xdist group with
rollback-only migration and multi-connection attribution tests.
"""

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    for item in items:
        if item.path.parent.name == "windows_inventory" and "db" in item.fixturenames:
            if not any(
                mark.args == ("retained_evidence_schema",)
                for mark in item.iter_markers("xdist_group")
            ):
                item.add_marker(pytest.mark.xdist_group("retained_evidence_schema"))
