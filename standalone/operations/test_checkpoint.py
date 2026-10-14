"""Restart state cannot forget active work, pending notice delivery or pinned devices."""

from copy import deepcopy

import pytest

from .checkpoint import encode, decode
from .dispatch import Definition
from .lifecycle import Mode
from .scheduling import Interval
from .test_dispatch import dispatcher, at, NOW


def running_state():
    value = dispatcher()
    (job,) = value.tick(at(600)).start
    value.finished(
        job.run_id, success=True, snapshot_id="synthetic-committed", now=at(1801)
    )
    return value


def test_pending_notice_and_overlap_survive_restart_exactly_once():
    original = running_state()
    restored = decode(encode(original))
    assert encode(restored) == encode(original)
    (notice,) = restored.tick(at(1801)).notices
    assert notice.kind == "overlap_opened" and notice.skipped_count == 2
    assert restored.tick(at(1801)).notices == ()
    (job,) = restored.tick(at(2400)).start
    restored.finished(
        job.run_id, success=True, snapshot_id="synthetic-new", now=at(2401)
    )
    (resolved,) = restored.tick(at(2401)).notices
    assert resolved.kind == "overlap_resolved"


def test_active_drain_and_cancellation_acknowledgement_survive_restart():
    original = dispatcher()
    (job,) = original.tick(at(600)).start
    original.request_mode(Mode.OFF, at(601))
    restored = decode(encode(original))
    assert restored.control.state == "draining"
    assert restored.tick(at(661)).cancel == (job.run_id,)
    again = decode(encode(restored))
    assert again.control.state == "draining"
    assert again.tick(at(662)).cancel == ()
    again.finished(job.run_id, success=False, now=at(663))
    assert again.control.state == "off"


def test_child_keeps_original_pinned_snapshot_across_restart():
    original = dispatcher(
        Definition("devices", Interval(60, NOW)),
        Definition("software", Interval(60, NOW), ("devices",)),
    )
    (parent,) = original.tick(at(60)).start
    original.finished(
        parent.run_id, success=True, snapshot_id="committed-device", now=at(61)
    )
    (child,) = original.tick(at(61)).start
    restored = decode(encode(original))
    assert restored.inputs["software"].active == child
    assert restored.inputs["software"].active.prerequisite_snapshots == (
        ("devices", "committed-device"),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(version=True),
        lambda d: d.update(unrecognized=True),
        lambda d: d["control"].update(active=["unknown"]),
        lambda d: d["control"].update(cancel_requested=["unknown"]),
        lambda d: d["inputs"]["input"].update(latest_snapshot=None),
        lambda d: d["inputs"]["input"].update(cursor=at(9999).isoformat()),
        lambda d: d["inputs"]["input"].update(overlap_count=0),
        lambda d: d["inputs"]["input"].update(missed_count=True),
        lambda d: d["definitions"][0]["schedule"].update(kind="run-arbitrary-command"),
        lambda d: d["notices"][0].update(input_id="unknown"),
    ],
)
def test_damaged_state_has_no_empty_default_fallback(mutation):
    document = deepcopy(encode(running_state()))
    mutation(document)
    with pytest.raises(ValueError):
        decode(document)


def test_restore_rejects_unrepresentable_interval_before_tick():
    document = encode(dispatcher())
    document["definitions"][0]["schedule"]["seconds"] = 86400000000000
    with pytest.raises(ValueError, match="time range"):
        decode(document)
