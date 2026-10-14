"""Synthetic multi-pass scans retain progress and never silently refetch."""

import pytest

from standalone.evidence_pipeline.collection import github_discovery_collection
from .test_github_discovery import fixture
from .test_github_advisories import COMMIT


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(
        github_discovery_collection,
        "download_github_object",
        lambda *a: pytest.fail("Unexpected network"),
    )


def objects():
    commit, trees, _, _ = fixture()
    return {
        ("commits", COMMIT): commit,
        **{("trees", key): value for key, value in trees.items()},
    }
