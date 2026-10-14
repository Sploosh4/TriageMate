"""Deferred settings infrastructure has explicit global defaults and no side effects."""

import pytest
from .settings import parse_settings, load_settings
from .test_store import db as database_fixture

db = database_fixture


def test_agreed_defaults_do_not_require_persisted_rows():
    settings = parse_settings([], [])
    assert settings.history_retention_days == 7
    assert settings.interval_for("devices") == 86400


def test_configured_values_apply_globally_and_are_immutable():
    settings = parse_settings([("history_retention_days", 14)], [("devices", 3600)])
    assert settings.history_retention_days == 14
    assert settings.interval_for("devices") == 3600
    assert settings.interval_for("epss") == 86400
    with pytest.raises(TypeError):
        settings.collection_intervals["devices"] = 5


@pytest.mark.parametrize(
    "settings,schedules",
    [
        ([("unknown", 7)], []),
        ([("history_retention_days", False)], []),
        ([("history_retention_days", 0)], []),
        ([("history_retention_days", 7), ("history_retention_days", 8)], []),
        ([], [("devices", -1)]),
        ([], [("devices", 1.5)]),
        ([], [("", 5)]),
        ([], [("devices", 1), ("devices", 2)]),
    ],
)
def test_invalid_values_are_not_silently_defaulted(settings, schedules):
    with pytest.raises(ValueError):
        parse_settings(settings, schedules)


def test_reader_loads_defaults_without_activating_settings(db):
    with db.cursor() as cursor:
        cursor.execute("SET LOCAL SESSION AUTHORIZATION tm_mock_reader")
        settings = load_settings(cursor)
        assert settings.history_retention_days == 7
        assert settings.interval_for("devices") == 86400
        cursor.execute("SELECT count(*) FROM evidence.app_settings")
        assert cursor.fetchone() == (0,)
        cursor.execute("SELECT count(*) FROM evidence.collection_schedules")
        assert cursor.fetchone() == (0,)
