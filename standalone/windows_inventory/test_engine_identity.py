"""Exact source aliases preserve predecessor identities, never arbitrary edits."""

from pathlib import Path

import pytest

from .component_store import engine_fingerprint as component_fingerprint
from .selected_component_store import engine_fingerprint as selected_fingerprint

COMPONENT = "4e17ffed6bfd432cae79790a8b4004d352fb2f1a68478d32817ebedef6d15d91"
SELECTED = "16b2207a6d3aabaf5ada1a5415e608bdd9141681e61448e835a89ea694b26569"


def test_refactor_preserves_independently_measured_predecessor_identities():
    assert component_fingerprint() == COMPONENT
    assert selected_fingerprint() == SELECTED


@pytest.mark.parametrize(
    "name",
    [
        "component_check.py",
        "component_assessment.py",
        "component_store.py",
        "contract.py",
        "staging.py",
        "selected_component_store.py",
        "component_snapshot.py",
        "servicing_manifest.py",
    ],
)
def test_any_engine_source_change_keeps_a_new_identity(monkeypatch, name):
    read = Path.read_bytes
    target = Path(__file__).with_name(name)

    def changed(path):
        data = read(path)
        return data + b"\n# synthetic source mutation\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert selected_fingerprint() != SELECTED
    if name not in {
        "selected_component_store.py",
        "component_snapshot.py",
        "servicing_manifest.py",
    }:
        assert component_fingerprint() != COMPONENT
    else:
        assert component_fingerprint() == COMPONENT
