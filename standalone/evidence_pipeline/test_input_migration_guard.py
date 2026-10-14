"""Input write guards accept installed upgrades and reject older/unknown versions."""

import pytest
from standalone.evidence_pipeline.persistence.store import require_input_migration
from .test_store import db as database_fixture

db = database_fixture


@pytest.mark.parametrize("feature", ["update-status", "antivirus", "catalogue"])
@pytest.mark.parametrize("version", [None, "pipeline-unknown-v999", "pipeline-lab-v9"])
def test_writer_guard_uses_only_existing_version_permission(db, feature, version):
    with db.cursor() as cur:
        if version:
            cur.execute(
                "UPDATE evidence_pipeline.installation SET version=%s", (version,)
            )
        cur.execute("SET LOCAL SESSION AUTHORIZATION tm_pipeline_writer")
        if version:
            with pytest.raises(ValueError, match="migration required"):
                require_input_migration(cur, feature)
        else:
            require_input_migration(cur, feature)
