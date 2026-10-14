"""Restricted writers require the centrally registered current database version."""

from pathlib import Path
from unittest.mock import Mock

import pytest

from backend.database import migrations
from backend.database.schema import VERSION, latest_version
from standalone.evidence_pipeline.persistence.store import require_input_migration


@pytest.mark.parametrize("feature", ["update-status", "antivirus", "catalogue"])
@pytest.mark.parametrize("future", [False, True])
def test_current_registered_version_preserves_restricted_writers(
    feature, future, monkeypatch
):
    if future:
        monkeypatch.setattr(
            migrations,
            "MIGRATIONS",
            (
                migrations.Migration(
                    "synthetic-future-v2", Path("unused.sql"), (Path("unused.json"),)
                ),
            ),
        )
    cursor = Mock()
    cursor.fetchone.return_value = (latest_version(),)
    require_input_migration(cursor, feature)


@pytest.mark.parametrize("feature", ["update-status", "antivirus", "catalogue"])
@pytest.mark.parametrize(
    "version",
    [
        "pipeline-lab-v9",
        "pipeline-updates-v10",
        "pipeline-windows-os-native-facts-v113",
        "unrecognized-future-version",
        None,
    ],
)
def test_predecessor_unknown_or_missing_input_schema_requires_explicit_adoption(
    feature, version
):
    cursor = Mock()
    cursor.fetchone.return_value = None if version is None else (version,)
    with pytest.raises(ValueError, match="migration required"):
        require_input_migration(cursor, feature)


def test_new_revision_makes_previous_baseline_insufficient(monkeypatch):
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (
            migrations.Migration(
                "synthetic-future-v2", Path("unused.sql"), (Path("unused.json"),)
            ),
        ),
    )
    cursor = Mock()
    cursor.fetchone.return_value = (VERSION,)
    with pytest.raises(ValueError, match="migration required"):
        require_input_migration(cursor, "catalogue")


@pytest.mark.parametrize("feature", ["unknown-feature", "", None])
def test_unknown_input_feature_does_not_reach_database(feature):
    cursor = Mock()
    with pytest.raises(ValueError, match="Unsupported restricted input feature"):
        require_input_migration(cursor, feature)
    cursor.execute.assert_not_called()
