"""No publication before EOF, exact replay bytes, cancellation and scratch cleanup."""

import hashlib
import io
import json

import pytest

from .staging import stage
from .test_contract import BINDING, sample


class BoundedReads(io.BytesIO):
    def read(self, size=-1):
        assert 0 <= size <= 65536
        return super().read(size)


def test_staging_preserves_fingerprint_rows_and_closes_output():
    value = sample()
    raw = json.dumps(value).encode()
    with stage(BoundedReads(raw), BINDING) as staged:
        assert staged.fingerprint == hashlib.sha256(raw).hexdigest()
        assert list(staged.records()) == value["records"]
        assert list(staged.records()) == value["records"]
        assert staged.metadata["coverage"] == value["coverage"]
        changed_metadata = staged.metadata
        changed_metadata["record_count"] = 999
        changed_metadata["coverage"]["unloaded_user_hives"] = "complete"
        assert staged.metadata["record_count"] == 2
        assert staged.metadata["coverage"]["unloaded_user_hives"] == "not-read"
        assert staged.source_file.read() == raw
        spool = staged.records_file
    assert spool.closed


def test_cancellation_during_consumer_iteration_is_retained():
    stopped = False
    with stage(
        BoundedReads(json.dumps(sample()).encode()), BINDING, cancelled=lambda: stopped
    ) as staged:
        records = staged.records()
        next(records)
        stopped = True
        with pytest.raises(ValueError, match="cancelled"):
            next(records)


@pytest.mark.parametrize(
    "failure", ["truncated", "duplicate", "count", "identity", "late-field"]
)
def test_invalid_inputs_never_publish(failure):
    value = sample()
    if failure == "duplicate":
        value["records"] *= 2
        value["record_count"] *= 2
    elif failure == "count":
        value["record_count"] += 1
    elif failure == "identity":
        value["machine_guid"] = "44444444-4444-4444-8444-444444444444"
    elif failure == "late-field":
        value["unexpected"] = True
    raw = json.dumps(value).encode()
    if failure == "truncated":
        raw = raw[:-1]
    with pytest.raises(ValueError):
        with stage(BoundedReads(raw), BINDING):
            pytest.fail("Incomplete inventory was published")


@pytest.mark.parametrize("cancel_after", [0, 2, 50, 150])
def test_cancel_before_or_during_validation_closes_all_spools(
    monkeypatch, cancel_after
):
    from . import staging

    original = staging.TemporaryFile
    opened = []

    def track(*args, **kwargs):
        result = original(*args, **kwargs)
        opened.append(result)
        return result

    monkeypatch.setattr(staging, "TemporaryFile", track)
    polls = 0

    def cancelled():
        nonlocal polls
        polls += 1
        return polls > cancel_after

    with pytest.raises(ValueError, match="cancelled"):
        with stage(
            BoundedReads(json.dumps(sample()).encode()), BINDING, cancelled=cancelled
        ):
            pytest.fail("Cancelled inventory was published")
    assert opened and all(item.closed for item in opened)


def test_consumer_interruption_closes_spools():
    with pytest.raises(KeyboardInterrupt):
        with stage(BoundedReads(json.dumps(sample()).encode()), BINDING) as staged:
            spool = staged.records_file
            raise KeyboardInterrupt
    assert spool.closed


def test_empty_complete_inventory_is_valid():
    value = sample()
    value.update(records=[], record_count=0)
    with stage(BoundedReads(json.dumps(value).encode()), BINDING) as staged:
        assert list(staged.records()) == []
