"""Tests for bounded backend test-run construction."""

import pytest

from scripts import run_backend_tests
from scripts.run_backend_tests import PARALLEL_THREAD_CAPS, build_test_run


def test_parallel_run_uses_two_workers_and_caps_nested_threads() -> None:
    command, environment = build_test_run(
        ("tests/test_health.py", "-q"),
        source_environment={"KEEP_ME": "yes", "OMP_NUM_THREADS": "8"},
    )

    assert command[-6:] == [
        "-n",
        "2",
        "--dist",
        "loadgroup",
        "tests/test_health.py",
        "-q",
    ]
    assert environment["KEEP_ME"] == "yes"
    assert all(environment[name] == "1" for name in PARALLEL_THREAD_CAPS)


def test_empty_test_selection_defaults_to_the_complete_backend_suite() -> None:
    command, _ = build_test_run((), source_environment={})

    assert command[-1] == "tests/"


def test_launcher_returns_the_pytest_failure_status(monkeypatch) -> None:
    observed = {}

    def fail(command, *, env):
        observed["command"] = command
        observed["environment"] = env
        return 7

    monkeypatch.setattr(run_backend_tests.subprocess, "call", fail)

    assert run_backend_tests.main(["tests/test_health.py"]) == 7
    assert observed["command"][-1] == "tests/test_health.py"
    assert observed["command"][3:7] == ["-n", "2", "--dist", "loadgroup"]


@pytest.mark.parametrize(
    "arguments",
    (
        ("-n", "4"),
        ("-n4",),
        ("--numprocesses", "4"),
        ("--numprocesses=4",),
        ("--dist", "worksteal"),
        ("--dist=worksteal",),
        ("--maxprocesses", "4"),
        ("--maxprocesses=4",),
        ("-d",),
        ("-dvalue",),
        ("-f",),
        ("-fvalue",),
        ("--tx", "2*popen"),
        ("--tx=2*popen",),
        ("--px", "id=proxy//popen"),
        ("--px=id=proxy//popen",),
        ("--maxschedchunk", "1"),
        ("--maxschedchunk=1",),
        ("--max-worker-restart", "0"),
        ("--max-worker-restart=0",),
        ("--loadscope-reorder",),
        ("--no-loadscope-reorder",),
        ("--looponfail",),
        ("--looponfail=true",),
        ("-qd",),
        ("-qdn4",),
    ),
)
def test_parallel_run_rejects_xdist_control_overrides(arguments) -> None:
    with pytest.raises(ValueError, match="options are fixed"):
        build_test_run(arguments, source_environment={})


@pytest.mark.parametrize(
    "arguments",
    (
        ("plain-dfn-text",),
        ("--", "-qdn4"),
        ("-kqdn4",),
        ("-k", "-qdn4"),
        ("-qk", "-qdn4"),
        ("-rfn",),
    ),
)
def test_parallel_run_does_not_treat_values_or_text_as_short_clusters(
    arguments,
) -> None:
    command, _ = build_test_run(arguments, source_environment={})

    assert command[-len(arguments) :] == list(arguments)


@pytest.mark.parametrize("addopts", ("--maxprocesses=1", "-d", "-qd", "-qdn4"))
def test_parallel_run_rejects_xdist_controls_from_pytest_addopts(addopts) -> None:
    with pytest.raises(ValueError, match="options are fixed"):
        build_test_run(
            ("tests/test_health.py",),
            source_environment={"PYTEST_ADDOPTS": addopts},
        )


def test_parallel_run_rejects_invalid_pytest_addopts_quoting() -> None:
    with pytest.raises(ValueError, match="invalid shell quoting"):
        build_test_run(
            ("tests/test_health.py",),
            source_environment={"PYTEST_ADDOPTS": "'unterminated"},
        )


@pytest.mark.parametrize("addopts", ("--", "-q -- -qdn4"))
def test_parallel_run_rejects_pytest_addopts_option_terminator(addopts) -> None:
    with pytest.raises(ValueError, match="cannot contain --"):
        build_test_run(
            ("tests/test_health.py",),
            source_environment={"PYTEST_ADDOPTS": addopts},
        )


@pytest.mark.parametrize(
    "arguments",
    (
        ("-d",),
        ("--tx=2*popen",),
        ("--maxschedchunk", "1"),
        ("--looponfail",),
        ("--dist=worksteal",),
        ("-qd",),
        ("-qdn4",),
    ),
)
def test_launcher_rejects_parallel_override_before_starting_pytest(
    monkeypatch, arguments
) -> None:
    def unexpected_call(*args, **kwargs):
        pytest.fail("pytest must not start when parallel controls conflict")

    monkeypatch.setattr(run_backend_tests.subprocess, "call", unexpected_call)

    with pytest.raises(SystemExit) as error:
        run_backend_tests.main(["--parallel", *arguments, "tests/test_health.py"])

    assert error.value.code == 2


@pytest.mark.parametrize("addopts", ("--maxprocesses=1", "-d", "-qd", "-qdn4"))
def test_launcher_rejects_pytest_addopts_override_before_starting_pytest(
    monkeypatch, addopts
) -> None:
    def unexpected_call(*args, **kwargs):
        pytest.fail("pytest must not start when PYTEST_ADDOPTS changes concurrency")

    monkeypatch.setenv("PYTEST_ADDOPTS", addopts)
    monkeypatch.setattr(run_backend_tests.subprocess, "call", unexpected_call)

    with pytest.raises(SystemExit) as error:
        run_backend_tests.main(["--parallel", "tests/test_health.py"])

    assert error.value.code == 2


@pytest.mark.parametrize("addopts", ("--", "-q -- -qdn4"))
def test_launcher_rejects_pytest_addopts_option_terminator_before_starting_pytest(
    monkeypatch, addopts
) -> None:
    def unexpected_call(*args, **kwargs):
        pytest.fail("pytest must not start after PYTEST_ADDOPTS terminates options")

    monkeypatch.setenv("PYTEST_ADDOPTS", addopts)
    monkeypatch.setattr(run_backend_tests.subprocess, "call", unexpected_call)

    with pytest.raises(SystemExit) as error:
        run_backend_tests.main(["--parallel", "tests/test_health.py"])

    assert error.value.code == 2


@pytest.mark.parametrize(
    "argument,sensitive_text",
    (
        (
            "--tx=ssh=synthetic-user:synthetic-password@example.invalid",
            "synthetic-password",
        ),
        ("-nsynthetic-sensitive-worker-value", "synthetic-sensitive-worker-value"),
    ),
)
def test_parallel_rejection_does_not_disclose_conflicting_values(
    argument, sensitive_text
) -> None:
    with pytest.raises(ValueError) as error:
        build_test_run((argument,), source_environment={})

    assert sensitive_text not in str(error.value)
    assert argument not in str(error.value)


def test_parallel_rejection_does_not_disclose_pytest_addopts_tx_value() -> None:
    addopts = "--tx=ssh=synthetic-user:synthetic-password@example.invalid"

    with pytest.raises(ValueError) as error:
        build_test_run(
            ("tests/test_health.py",),
            source_environment={"PYTEST_ADDOPTS": addopts},
        )

    assert "synthetic-password" not in str(error.value)
    assert addopts not in str(error.value)


def test_launcher_rejection_does_not_disclose_tx_value_or_start_pytest(
    monkeypatch, capsys
) -> None:
    argument = "--tx=ssh=synthetic-user:synthetic-password@example.invalid"

    def unexpected_call(*args, **kwargs):
        pytest.fail("pytest must not start after a fixed-control override")

    monkeypatch.setattr(run_backend_tests.subprocess, "call", unexpected_call)

    with pytest.raises(SystemExit) as error:
        run_backend_tests.main(["--parallel", argument, "tests/test_health.py"])

    stderr = capsys.readouterr().err
    assert error.value.code == 2
    assert "synthetic-password" not in stderr
    assert argument not in stderr


def test_launcher_rejection_does_not_disclose_pytest_addopts_tx_value(
    monkeypatch, capsys
) -> None:
    addopts = "--tx=ssh=synthetic-user:synthetic-password@example.invalid"

    def unexpected_call(*args, **kwargs):
        pytest.fail("pytest must not start after a fixed-control override")

    monkeypatch.setenv("PYTEST_ADDOPTS", addopts)
    monkeypatch.setattr(run_backend_tests.subprocess, "call", unexpected_call)

    with pytest.raises(SystemExit) as error:
        run_backend_tests.main(["--parallel", "tests/test_health.py"])

    stderr = capsys.readouterr().err
    assert error.value.code == 2
    assert "synthetic-password" not in stderr
    assert addopts not in stderr


def test_launcher_rejects_retired_serial_mode_before_starting_pytest(
    monkeypatch, capsys
) -> None:
    def unexpected_call(*args, **kwargs):
        pytest.fail("pytest must not start in retired serial mode")

    monkeypatch.setattr(run_backend_tests.subprocess, "call", unexpected_call)

    with pytest.raises(SystemExit) as error:
        run_backend_tests.main(["--serial", "tests/test_health.py"])

    stderr = capsys.readouterr().err
    assert error.value.code == 2
    assert "serial execution is retired" in stderr
