"""Typed global settings infrastructure; does not schedule work or expire records."""

from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping

DEFAULT_COLLECTION_SECONDS = 86400
DEFAULT_RETENTION_DAYS = 7


@dataclass(frozen=True)
class GlobalSettings:
    history_retention_days: int
    collection_intervals: Mapping[str, int]

    def interval_for(self, input_kind: str) -> int:
        if not isinstance(input_kind, str) or not input_kind.strip():
            raise ValueError("An input kind is required")
        return self.collection_intervals.get(input_kind, DEFAULT_COLLECTION_SECONDS)


def _positive(value):
    if type(value) is not int or value <= 0:
        raise ValueError("Settings values must be positive integers")
    return value


def parse_settings(settings, schedules):
    """Consume table-shaped key/value pairs; reject drift instead of guessing."""
    values = {}
    for key, value in settings:
        if key != "history_retention_days" or key in values:
            raise ValueError("Unknown or duplicate global setting")
        values[key] = _positive(value)
    intervals = {}
    for kind, value in schedules:
        if (
            not isinstance(kind, str)
            or not kind.strip()
            or len(kind) > 128
            or kind in intervals
        ):
            raise ValueError("Invalid or duplicate input schedule")
        intervals[kind] = _positive(value)
    return GlobalSettings(
        values.get("history_retention_days", DEFAULT_RETENTION_DAYS),
        MappingProxyType(intervals),
    )


def load_settings(cursor):
    """Read existing global tables. No writes, per-agency overrides or activation."""
    cursor.execute("SELECT key,value FROM evidence.app_settings ORDER BY key")
    settings = cursor.fetchall()
    cursor.execute(
        "SELECT input_kind,interval_seconds FROM evidence.collection_schedules ORDER BY input_kind"
    )
    return parse_settings(settings, cursor.fetchall())
