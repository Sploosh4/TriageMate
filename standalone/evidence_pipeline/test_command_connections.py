"""Connections close after successful, failed and uncertain-commit imports."""

from types import SimpleNamespace
import pytest
from . import commands, enrichment_commands


@pytest.mark.parametrize(
    "name,writer",
    (
        ("ingest", "persist_devices"),
        ("ingest_exposure", "persist_exposure"),
        ("ingest_public", "persist_public"),
    ),
)
@pytest.mark.parametrize("failure", (None, "write", "commit"))
def test_import_closes_after_transaction_outcome(monkeypatch, name, writer, failure):
    events = []

    class Connection:
        def __enter__(self):
            events.append("begin")
            return self

        def __exit__(self, kind, value, traceback):
            events.append("rollback" if kind else "commit")
            if kind is None and failure == "commit":
                raise RuntimeError("Synthetic uncertain commit")

        def close(self):
            events.append("close")

    def persist(*args):
        events.append("write")
        if failure == "write":
            raise RuntimeError("Synthetic write failure")
        return {"outcome": "success"}

    def discover(*args, **kwargs):
        events.append("discover")
        return []

    snapshot = SimpleNamespace(
        complete=False,
        scope=SimpleNamespace(source="Defender", input_kind="findings"),
        execution_id="synthetic-connection-lifecycle-test",
    )
    monkeypatch.setattr(enrichment_commands, "discover_attempt", discover)
    monkeypatch.setattr(commands, "connect", Connection)
    monkeypatch.setattr(commands, writer, persist)
    if failure:
        with pytest.raises(RuntimeError):
            getattr(commands, name)(snapshot)
    else:
        expected = {"outcome": "success"}
        if name == "ingest_exposure":
            expected["enrichment"] = dict(state="checked", queued=0, batch_limit=100)
        assert getattr(commands, name)(snapshot) == expected
    assert events == [
        "begin",
        "write",
        "rollback" if failure == "write" else "commit",
        "close",
    ] + (["discover"] if name == "ingest_exposure" and failure is None else [])
