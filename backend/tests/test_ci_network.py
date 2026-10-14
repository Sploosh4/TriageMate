"""Network enforcement must fail closed and cannot be bypassed by run flags."""

import importlib.util
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "ci_network", ROOT / "scripts/ci_network.py"
)
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


@pytest.mark.parametrize(
    "links, expected",
    [
        ('[{"ifname":"lo"}]', True),
        ('[{"ifname":"lo"},{"ifname":"eth0"}]', False),
        ("[]", False),
    ],
)
def test_actual_interfaces_determine_isolation(links, expected):
    with patch.object(network.subprocess, "check_output", return_value=links):
        assert network.isolated() is expected


def test_missing_launcher_never_executes_online_fallback():
    with (
        patch.object(network, "isolated", return_value=False),
        patch.object(network.Path, "is_file", return_value=False),
        patch.object(sys, "argv", ["ci_network.py", "bash", "test.sh"]),
        patch.object(network.os, "execvp") as execute,
    ):
        assert network.main() == 1
        execute.assert_not_called()


def test_isolated_process_executes_original_command():
    with (
        patch.object(network, "isolated", return_value=True),
        patch.object(sys, "argv", ["ci_network.py", "bash", "test.sh"]),
        patch.object(network.os, "execvp", side_effect=RuntimeError("exec")) as execute,
    ):
        with pytest.raises(RuntimeError, match="exec"):
            network.main()
        execute.assert_called_once_with("bash", ["bash", "test.sh"])
