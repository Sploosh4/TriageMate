"""Committed synthetic repository import, exact reader URLs and offline replay."""

import json
from uuid import uuid4

from standalone.evidence_pipeline.collection.github_dispatch import source_scope
from .test_ubuntu_repository import fixtures
from .test_ubuntu_discovery import COMMIT
from standalone.evidence_pipeline.parsing.ubuntu_discovery import plan


def isolated_repository():
    metadata, payloads = fixtures()
    commit = uuid4().hex + "a" * 8
    commit_wire = json.loads(metadata.pop(("commits", COMMIT)))
    commit_wire["sha"] = commit
    metadata["commits", commit] = json.dumps(commit_wire).encode()
    metadata["ref", "heads/main"] = json.dumps(
        dict(ref="refs/heads/main", object=dict(type="commit", sha=commit))
    ).encode()
    trees = {
        identity: wire for (kind, identity), wire in metadata.items() if kind == "trees"
    }
    scopes = [
        source_scope(record, "synthetic")
        for partition in ("cve/2099", "lsn", "usn")
        for record in plan(
            commit, metadata["commits", commit], trees, partition=partition
        ).files
    ]
    return metadata, payloads, scopes
