"""Rollback-only pinned Ubuntu authority, upgrade compatibility and attribution."""

from backend.database import schema as database_schema

import pytest


from .test_store import db as database_fixture

db = database_fixture


@pytest.mark.parametrize("damage", ["function", "grant", "metadata"])
def test_authority_drift_is_rejected(db, damage):
    with db.cursor() as cur:
        database_schema.verify(cur)
        if damage == "function":
            cur.execute(
                "CREATE OR REPLACE FUNCTION evidence_pipeline.ubuntu_source_allowed(native_id text,source_url text) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true'"
            )
        elif damage == "grant":
            cur.execute(
                "GRANT EXECUTE ON FUNCTION evidence_pipeline.ubuntu_source_allowed(text,text) TO PUBLIC"
            )
        else:
            cur.execute(
                "UPDATE evidence_pipeline.installation SET artifacts=artifacts-'schema.sql'"
            )
        with pytest.raises(ValueError, match="schema/authority differs|metadata"):
            database_schema.verify(cur)


@pytest.mark.parametrize("native", ["USN-9999-1", "LSN-9999-1", "UBUNTU-CVE-2099-1234"])
def test_database_rejects_false_publisher_routes(db, native):
    from standalone.evidence_pipeline.parsing.ubuntu_advisories import (
        endpoint,
        repository_endpoint,
        BASE,
    )

    path = "osv/" + endpoint(native).removeprefix(BASE)
    pinned = repository_endpoint("a" * 40, path, native)
    bad = [
        pinned.replace("canonical/", "other/"),
        pinned + "?x=1",
        pinned.replace("a" * 40, "a" * 39),
        pinned.replace("a" * 40, "0" * 40),
        pinned.replace("/osv/", "/osv/../osv/"),
        pinned.replace(".json", ".xml"),
    ]
    with db.cursor() as cur:
        database_schema.verify(cur)
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        for url in [endpoint(native), pinned, *bad]:
            cur.execute(
                "SELECT evidence_pipeline.ubuntu_source_allowed(%s,%s)", (native, url)
            )
            assert cur.fetchone() == (url in [endpoint(native), pinned],), url
