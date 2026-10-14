"""The browser gate owns its server and rejects ordinary operator installations."""

from contextlib import contextmanager
import importlib.util
from pathlib import Path
import signal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location(
    "browser_checks_for_tests", Path(__file__).with_name("browser_checks.py")
)
browser_checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser_checks)


@contextmanager
def cursor():
    yield object()


@pytest.fixture
def harness(monkeypatch):
    database = SimpleNamespace(
        connect=lambda: SimpleNamespace(cursor=cursor, close=lambda: None)
    )
    monkeypatch.setattr(browser_checks, "local_database", lambda: database)
    monkeypatch.setattr(browser_checks, "verify", lambda _cursor: None)
    monkeypatch.setattr(browser_checks, "fingerprint", lambda _cursor: {})
    launch = Mock()
    monkeypatch.setattr(browser_checks.subprocess, "Popen", launch)
    return launch


def test_ordinary_installation_cannot_launch_browser_server(monkeypatch, harness):
    monkeypatch.setattr(
        browser_checks, "identify_layout", lambda _actual: ("empty", False)
    )
    with pytest.raises(ValueError, match="synthetic"):
        browser_checks.main()
    harness.assert_not_called()


@pytest.mark.parametrize("profile", ["synthetic", "runner"])
@pytest.mark.parametrize("test_result", [0, 9])
def test_owned_server_url_drain_and_test_failure_are_preserved(
    monkeypatch, harness, profile, test_result
):
    monkeypatch.setattr(
        browser_checks, "identify_layout", lambda _actual: (profile, False)
    )
    monkeypatch.setenv("TRIAGEMATE_TEST_URL", "https://unrelated.invalid")
    monkeypatch.setenv("TRIAGEMATE_OPERATIONS_CONFIG", "/unused-operator-config")

    def server(_command, **kwargs):
        process = SimpleNamespace(poll=lambda: None, returncode=-signal.SIGTERM)
        process.terminate = lambda: kwargs["stdout"].write(
            "Application shutdown complete.\n"
        )
        process.wait = lambda **_kwargs: kwargs["stdout"].flush()
        return process

    harness.side_effect = server

    @contextmanager
    def ready(url, **_kwargs):
        assert url.startswith("http://127.0.0.1:") and url.endswith("/api/health")
        yield SimpleNamespace(status=200)

    monkeypatch.setattr(browser_checks, "urlopen", ready)
    execution = Mock(return_value=SimpleNamespace(returncode=test_result))
    monkeypatch.setattr(browser_checks.subprocess, "run", execution)
    assert browser_checks.main() == test_result
    environment = execution.call_args.kwargs["env"]
    assert environment["TRIAGEMATE_TEST_URL"].startswith("http://127.0.0.1:")
    assert environment["TRIAGEMATE_OPERATIONS_CONFIG"] == ""
    assert not Path(environment["TRIAGEMATE_STATE_DIR"]).exists()
    assert harness.call_count == 1
