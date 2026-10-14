"""Serialize retained-database operations with evidence schema/attribution tests.

Process-based scheduler tests commit through several connections. They cannot run
beside rollback-only role/DDL tests or a READ COMMITTED baseline scan on that same
database. Pure scheduling, parsing and in-memory worker tests remain parallel.
"""

import pytest


DATABASE_MODULES = {
    "test_catalog_age.py",
    "test_catalog_target_service.py",
    "test_catalog_target_worker.py",
    "test_certificates.py",
    "test_credential_metadata.py",
    "test_enrichment_notice_filter.py",
    "test_enrichment_refresh_schedule.py",
    "test_microsoft_service.py",
    "test_msrc_age.py",
    "test_notifications.py",
    "test_overdue.py",
    "test_process_worker.py",
    "test_provider_age.py",
    "test_redhat_service.py",
    "test_repository_failure_service.py",
    "test_repository_failures.py",
    "test_repository_proof.py",
    "test_repository_service.py",
    "test_storage_monitor.py",
    "test_store.py",
    "test_wasoc_service.py",
}


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items):
    for item in items:
        if item.path.parent.name == "operations" and (
            item.path.name in DATABASE_MODULES or "db" in item.fixturenames
        ):
            if not any(
                mark.args == ("retained_evidence_schema",)
                for mark in item.iter_markers("xdist_group")
            ):
                item.add_marker(pytest.mark.xdist_group("retained_evidence_schema"))
