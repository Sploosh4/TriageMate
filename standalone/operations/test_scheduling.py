"""Configured cadence boundaries and Perth dates use a deterministic clock."""

from datetime import datetime, timedelta, timezone

import pytest

from .scheduling import Daily, Interval

START = datetime(2099, 9, 23, tzinfo=timezone.utc)


def test_interval_stagger_and_two_skipped_slots():
    schedule = Interval(600, START, offset_seconds=90)
    first = schedule.due(START, START + timedelta(seconds=90))
    assert first.count == 1
    assert first.latest == START + timedelta(seconds=90)
    assert schedule.due(first.latest, first.latest) is None
    missed = schedule.due(first.latest, first.latest + timedelta(seconds=1200))
    assert missed.count == 2  # configured ten-minute cadence, not hourly
    assert missed.first == first.latest + timedelta(seconds=600)
    assert missed.latest == first.latest + timedelta(seconds=1200)


def test_interval_does_not_invent_slots_before_registration_anchor():
    schedule = Interval(1, START)
    assert schedule.due(START - timedelta(days=2), START - timedelta(seconds=1)) is None
    due = schedule.due(START - timedelta(days=2), START + timedelta(days=30))
    assert due.count == 30 * 86400 + 1
    assert due.first == START
    assert due.latest == START + timedelta(days=30)


def test_daily_perth_midnight_crosses_utc_date():
    schedule = Daily(0, 0)
    first = datetime(2099, 9, 22, 16, tzinfo=timezone.utc)
    assert schedule.due(first, first + timedelta(hours=23, minutes=59)) is None
    due = schedule.due(first - timedelta(seconds=1), first + timedelta(days=2))
    assert due.count == 3
    assert due.first == first
    assert due.latest == first + timedelta(days=2)


def test_daily_leap_day_and_minute_configuration():
    schedule = Daily(8, 37)
    before = datetime(2096, 2, 28, 0, 37, tzinfo=timezone.utc)
    due = schedule.due(before, before + timedelta(days=2))
    assert due.count == 2
    assert due.first == datetime(2096, 2, 29, 0, 37, tzinfo=timezone.utc)
    assert due.latest == datetime(2096, 3, 1, 0, 37, tzinfo=timezone.utc)


@pytest.mark.parametrize("schedule", [Daily(8, 0), Interval(30, START)])
def test_naive_and_backwards_clocks_fail(schedule):
    with pytest.raises(ValueError, match="timezone"):
        schedule.due(START.replace(tzinfo=None), START)
    with pytest.raises(ValueError, match="backwards"):
        schedule.due(START, START - timedelta(seconds=1))


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Daily(24, 0),
        lambda: Daily(1, 60),
        lambda: Daily(True, 0),
        lambda: Interval(0, START),
        lambda: Interval(10, START, 10),
        lambda: Interval(10, START, -1),
        lambda: Interval(1.5, START),
    ],
)
def test_invalid_cadence_rejected(factory):
    with pytest.raises(ValueError):
        factory()


@pytest.mark.parametrize("seconds", [86400000000000, 10**100])
def test_unrepresentable_interval_is_rejected_before_tick(seconds):
    with pytest.raises(ValueError, match="time range"):
        Interval(seconds, START)


def test_unrepresentable_stagger_is_rejected_before_tick():
    with pytest.raises(ValueError, match="time range"):
        Interval(120, datetime.max.replace(tzinfo=timezone.utc), 60)


def test_largest_representable_interval_does_not_overflow_due():
    schedule = Interval(86399999999999, START)
    assert schedule.due(START, datetime.max.replace(tzinfo=timezone.utc)) is None
    due = schedule.due(START - timedelta(seconds=1), START)
    assert due.count == 1 and due.first == START
