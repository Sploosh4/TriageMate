"""Compute bounded schedule occurrences without replaying every missed interval."""

from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

PERTH = ZoneInfo("Australia/Perth")


def utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("Operational timestamps must include a timezone")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class Due:
    count: int
    first: datetime
    latest: datetime


@dataclass(frozen=True)
class Interval:
    seconds: int
    anchor: datetime
    offset_seconds: int = 0

    def __post_init__(self):
        if type(self.seconds) is not int or self.seconds < 1:
            raise ValueError(
                "Collection interval must be a positive integer number of seconds"
            )
        if (
            type(self.offset_seconds) is not int
            or not 0 <= self.offset_seconds < self.seconds
        ):
            raise ValueError(
                "Collection stagger must be within the configured interval"
            )
        try:
            anchor = utc(self.anchor)
            timedelta(seconds=self.seconds)
            anchor + timedelta(seconds=self.offset_seconds)
        except OverflowError:
            raise ValueError(
                "Collection interval or stagger exceeds the supported time range"
            ) from None

    def due(self, after: datetime, now: datetime) -> Due | None:
        after, now = utc(after), utc(now)
        if now < after:
            raise ValueError("Schedule cursor cannot move backwards")
        base = utc(self.anchor) + timedelta(seconds=self.offset_seconds)
        step = timedelta(seconds=self.seconds)
        first_index = max(0, (after - base) // step + 1)
        last_index = (now - base) // step
        if last_index < first_index:
            return None
        return Due(
            last_index - first_index + 1,
            base + first_index * step,
            base + last_index * step,
        )


@dataclass(frozen=True)
class Daily:
    hour: int
    minute: int

    def __post_init__(self):
        if (
            type(self.hour) is not int
            or not 0 <= self.hour <= 23
            or type(self.minute) is not int
            or not 0 <= self.minute <= 59
        ):
            raise ValueError("Daily collection requires a valid Perth hour and minute")

    def due(self, after: datetime, now: datetime) -> Due | None:
        after, now = utc(after), utc(now)
        if now < after:
            raise ValueError("Schedule cursor cannot move backwards")
        first_day = after.astimezone(PERTH).date()
        last_day = now.astimezone(PERTH).date()
        at = time(self.hour, self.minute, tzinfo=PERTH)
        first = datetime.combine(first_day, at).astimezone(timezone.utc)
        if first <= after:
            first_day += timedelta(days=1)
            first = datetime.combine(first_day, at).astimezone(timezone.utc)
        last = datetime.combine(last_day, at).astimezone(timezone.utc)
        if last > now:
            last_day -= timedelta(days=1)
            last = datetime.combine(last_day, at).astimezone(timezone.utc)
        if last_day < first_day:
            return None
        return Due((last_day - first_day).days + 1, first, last)
