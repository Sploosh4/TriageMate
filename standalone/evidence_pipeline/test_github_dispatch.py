"""End-to-end synthetic discovery, file verification, import and replay."""

import hashlib
import json

import pytest

from standalone.evidence_pipeline.collection import public_collection
from standalone.evidence_pipeline.collection.github_scan import scan
from .test_github_advisories import COMMIT, IDENTITY
from .test_github_discovery import fixture
from .test_osv import document


def setup(tmp_path):
    commit, trees, ids, _ = fixture()
    raw = json.dumps(dict(document(), id=IDENTITY, aliases=[])).encode()
    leaf = json.loads(trees[ids[-1]])
    leaf["tree"][0].update(
        size=len(raw),
        sha=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    )
    trees[ids[-1]] = json.dumps(leaf).encode()
    fixtures = {
        ("commits", COMMIT): commit,
        **{("trees", key): value for key, value in trees.items()},
    }
    result = scan(
        COMMIT, tmp_path / "scan", origin="synthetic", synthetic_objects=fixtures
    )
    assert result.complete
    return raw, result.discovery.files[0]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(
        public_collection,
        "download",
        lambda *a, **k: pytest.fail("Synthetic/replay dispatch fetched HTTP"),
    )
