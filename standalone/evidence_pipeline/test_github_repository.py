"""Bounded partition coordination uses synthetic metadata and advisory bytes."""

import hashlib
import json


from .test_github_discovery import fixture
from .test_github_advisories import COMMIT, IDENTITY, PATH
from .test_osv import document


def fixtures():
    commit, trees, ids, _ = fixture()
    raw = json.dumps(dict(document(), id=IDENTITY, aliases=[])).encode()
    leaf = json.loads(trees[ids[-1]])
    leaf["tree"][0].update(
        size=len(raw),
        sha=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    )
    trees[ids[-1]] = json.dumps(leaf).encode()
    return {
        ("commits", COMMIT): commit,
        **{("trees", key): value for key, value in trees.items()},
    }, {PATH: raw}
