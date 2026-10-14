"""Stopping collection does not falsely report a live worker as stopped."""

from datetime import datetime, timedelta, timezone

import pytest

from .lifecycle import Lifecycle, Mode

NOW = datetime(2099, 9, 23, tzinfo=timezone.utc)


def test_off_drains_then_cancels_once_and_waits_for_worker_acknowledgement():
    control = Lifecycle(grace_seconds=30, mode=Mode.RUNNING)
    control.started("synthetic-collection")
    control.request(Mode.OFF, NOW)
    assert control.state == "draining"
    assert not control.accepts_work
    with pytest.raises(ValueError, match="paused"):
        control.started("new-collection")
    control.request(Mode.OFF, NOW + timedelta(seconds=20))
    assert control.cancellations_due(NOW + timedelta(seconds=29)) == ()
    assert control.cancellations_due(NOW + timedelta(seconds=30)) == (
        "synthetic-collection",
    )
    assert control.state == "draining"
    assert control.cancellations_due(NOW + timedelta(seconds=31)) == ()
    control.finished("synthetic-collection")
    assert control.state == "off"
    control.request(Mode.RUNNING, NOW + timedelta(seconds=32))
    assert control.accepts_work
    control.started("new-collection")


def test_maintenance_suppresses_expected_outage_and_successful_drain_needs_no_cancel():
    control = Lifecycle(mode=Mode.RUNNING)
    control.started("synthetic-collection")
    control.request(Mode.MAINTENANCE, NOW)
    assert control.suppress_outage_notifications
    control.finished("synthetic-collection")
    assert control.state == "maintenance"
    assert control.cancellations_due(NOW + timedelta(minutes=2)) == ()
    control.request(Mode.RUNNING, NOW + timedelta(minutes=3))
    assert not control.suppress_outage_notifications
    assert control.state == "running"


def test_switching_pause_mode_does_not_extend_deadline():
    control = Lifecycle(grace_seconds=10, mode=Mode.RUNNING)
    control.started("synthetic-collection")
    control.request(Mode.MAINTENANCE, NOW)
    control.request(Mode.OFF, NOW + timedelta(seconds=9))
    assert control.cancellations_due(NOW + timedelta(seconds=10)) == (
        "synthetic-collection",
    )


def test_resume_preserves_inflight_worker_identity():
    control = Lifecycle(grace_seconds=0, mode=Mode.RUNNING)
    control.started("synthetic-collection")
    control.request(Mode.OFF, NOW)
    assert control.cancellations_due(NOW) == ("synthetic-collection",)
    control.request(Mode.RUNNING, NOW)
    with pytest.raises(ValueError, match="already active"):
        control.started("synthetic-collection")
    control.finished("synthetic-collection")
    control.started("synthetic-collection")


def test_default_starts_off_and_invalid_worker_events_fail():
    control = Lifecycle()
    assert control.state == "off"
    with pytest.raises(ValueError, match="Unknown"):
        control.finished("never-started")
    with pytest.raises(ValueError, match="grace"):
        Lifecycle(grace_seconds=-1)
