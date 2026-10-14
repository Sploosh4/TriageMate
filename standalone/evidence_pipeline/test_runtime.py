"""Explicit current lifecycle commands; historical upgrade routes stay retired."""

from unittest.mock import Mock

import pytest

from . import runtime


@pytest.mark.parametrize("profile", ["empty", "synthetic", "runner"])
@pytest.mark.parametrize("changed", [False, True])
def test_setup_dispatches_only_explicit_profile(monkeypatch, capsys, profile, changed):
    setup = Mock(return_value=changed)
    monkeypatch.setattr(runtime, "setup", setup)
    monkeypatch.setattr("sys.argv", ["pipeline", "setup", "--profile", profile])
    runtime.main()
    setup.assert_called_once_with(profile=profile)
    assert capsys.readouterr().out.strip() == (
        "Evidence baseline installed."
        if changed
        else "Evidence baseline verified; unchanged."
    )


@pytest.mark.parametrize("changed", [False, True])
def test_upgrade_dispatches_central_registry(monkeypatch, capsys, changed):
    target = object()
    monkeypatch.setattr(runtime, "local_database", lambda: target)
    upgrade = Mock(return_value=changed)
    monkeypatch.setattr(runtime, "upgrade_existing", upgrade)
    monkeypatch.setattr("sys.argv", ["pipeline", "upgrade"])
    runtime.main()
    upgrade.assert_called_once_with(target)
    assert capsys.readouterr().out.strip() == (
        "Registered database revisions applied."
        if changed
        else "Database is current; unchanged."
    )


@pytest.mark.parametrize(
    "command",
    [
        "upgrade-edge-inventory",
        "upgrade-msrc-native-completeness",
        "upgrade-windows-os-native-facts",
    ],
)
def test_historical_routes_are_refused_without_schema_work(monkeypatch, command):
    setup, upgrade = Mock(), Mock()
    monkeypatch.setattr(runtime, "setup", setup)
    monkeypatch.setattr(runtime, "upgrade_existing", upgrade)
    monkeypatch.setattr("sys.argv", ["pipeline", command])
    with pytest.raises(SystemExit) as error:
        runtime.main()
    assert error.value.code == 2
    setup.assert_not_called()
    upgrade.assert_not_called()


def test_failed_setup_does_not_report_success_or_expose_credentials(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        runtime, "setup", Mock(side_effect=ValueError("private diagnostic"))
    )
    monkeypatch.setattr("sys.argv", ["pipeline", "setup"])
    with pytest.raises(
        SystemExit, match="explicit baseline adoption requirements"
    ) as error:
        runtime.main()
    assert "private diagnostic" not in str(error.value)
    assert not capsys.readouterr().out
