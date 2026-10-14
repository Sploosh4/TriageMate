"""Verifier measurement must use read-only snapshot semantics and exact results."""

from pathlib import Path
from types import SimpleNamespace
import json
import os
import runpy
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ui-engine/postgres"))
from epss import baseline  # noqa: E402
from standalone.evidence_pipeline import runtime  # noqa: E402


def test_retained_mode_is_read_only_and_profiles_without_import(
    monkeypatch, tmp_path, capsys
):
    profile = tmp_path / "generated.pstats"
    events = []

    class Connection:
        def set_session(self, **options):
            assert options == {"isolation_level": "REPEATABLE READ", "readonly": True}
            events.append("read_only")

        def __enter__(self):
            assert events == ["read_only"]
            return self

        def __exit__(self, *exc):
            events.append("transaction_ended")

        def cursor(self):
            return Cursor()

        def get_backend_pid(self):
            return os.getpid()

        def close(self):
            events.append("closed")

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

    def verify(cursor):
        assert isinstance(cursor, Cursor) and events == ["read_only"]
        return {"generated_fixture_table": 3}

    monkeypatch.setattr(
        runtime, "local_database", lambda: SimpleNamespace(connect=Connection)
    )
    monkeypatch.setattr(baseline, "verify", verify)
    monkeypatch.setattr(
        sys, "argv", ["benchmark", "--verify-retained", "--profile", str(profile)]
    )
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(
            str(ROOT / "scripts/benchmark_msrc_resources.py"), run_name="__main__"
        )
    assert exc.value.code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verified_counts"] == {"generated_fixture_table": 3}
    assert output["read_only"] and output["profiled"]
    assert output["integrity_pass"] and output["error_type"] is None
    assert events == ["read_only", "transaction_ended", "closed"]
    assert profile.stat().st_mode & 0o777 == 0o600
    import pstats

    assert pstats.Stats(str(profile)).total_calls > 0


@pytest.mark.parametrize(
    "arguments",
    [
        ["--profile", "unused"],
        ["--verify-retained", "--local-http"],
        ["--verify-retained", "--records", "1"],
    ],
)
def test_incompatible_measurements_are_rejected_before_database_access(
    monkeypatch, arguments
):
    def unexpected():
        pytest.fail("Invalid arguments must not access the database")

    monkeypatch.setattr(runtime, "local_database", unexpected)
    monkeypatch.setattr(sys, "argv", ["benchmark", *arguments])
    with pytest.raises(SystemExit) as exc:
        runpy.run_path(
            str(ROOT / "scripts/benchmark_msrc_resources.py"), run_name="__main__"
        )
    assert exc.value.code == 2


@pytest.mark.parametrize("error", [AssertionError, KeyboardInterrupt])
def test_verification_failure_closes_connection_and_preserves_failure_metrics(
    monkeypatch, capsys, error
):
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.get_backend_pid.return_value = os.getpid()
    monkeypatch.setattr(
        runtime, "local_database", lambda: SimpleNamespace(connect=lambda: connection)
    )
    monkeypatch.setattr(sys, "argv", ["benchmark", "--verify-retained"])

    def corrupted(cursor):
        raise error("Synthetic corruption must fail verification")

    monkeypatch.setattr(baseline, "verify", corrupted)
    with pytest.raises(error, match="Synthetic corruption"):
        runpy.run_path(
            str(ROOT / "scripts/benchmark_msrc_resources.py"), run_name="__main__"
        )
    connection.set_session.assert_called_once_with(
        isolation_level="REPEATABLE READ", readonly=True
    )
    connection.close.assert_called_once()
    output = json.loads(capsys.readouterr().out)
    assert output["integrity_pass"] is False
    assert output["error_type"] == error.__name__
    assert output["verified_counts"] is None
    assert output["read_only"] and output["seconds"] >= 0
    assert output["peak_python_rss_kib"] > 0
    assert isinstance(output["memory"], dict)
