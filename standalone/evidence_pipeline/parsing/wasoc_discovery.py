"""Pinned complete WA SOC tree planning; duplicate native IDs stay separate files.

A recursive GitHub response is usable only when explicitly untruncated. Contents
API directory listings can stop at 1,000 entries and are not accepted here.
"""

from dataclasses import dataclass
from standalone.evidence_pipeline.parsing.github_discovery import (
    AdvisoryFile as GitFile,
    decode,
    object_id,
)
from standalone.evidence_pipeline.parsing.wasoc_advisories import (
    PATH,
    repository_endpoint,
)

API = "https://api.github.com/repos/wagov/wasocshared/git/"


def object_url(kind, identity):
    if (kind, identity) == ("ref", "heads/main"):
        return API + "ref/heads/main"
    if kind not in {"commits", "trees"}:
        raise ValueError("Unsupported WA SOC discovery object")
    return (
        API
        + kind
        + "/"
        + object_id(identity)
        + ("?recursive=1" if kind == "trees" else "")
    )


@dataclass(frozen=True)
class AdvisoryFile(GitFile):
    @property
    def advisory_id(self):
        return PATH.fullmatch(self.path)["id"]

    @property
    def url(self):
        return repository_endpoint(self.commit, self.path, self.advisory_id)


@dataclass(frozen=True)
class Discovery:
    commit: str
    partition: str | None
    partitions: tuple[str, ...]
    files: tuple[AdvisoryFile, ...]
    pending_trees: tuple[str, ...]

    @property
    def complete(self):
        return not self.pending_trees


def scan_plan(commit, commit_payload, trees, *, partition=None):
    """Fit the complete recursive tree into the existing resumable scanner."""
    object_id(commit)
    if partition not in (None, "advisories"):
        raise ValueError("WA SOC supports the advisories partition only")
    document = decode(commit_payload)
    if document.get("sha") != commit or not isinstance(document.get("tree"), dict):
        raise ValueError("WA SOC commit response differs from pinned commit")
    root = object_id(document["tree"].get("sha"))
    if not isinstance(trees, dict):
        raise ValueError("WA SOC tree cache requires a mapping")
    if root not in trees:
        return Discovery(commit, partition, (), (), (root,))
    files = plan(commit, commit_payload, trees[root])
    return Discovery(commit, partition, ("advisories",), files if partition else (), ())


def plan(commit, commit_payload, tree_payload):
    object_id(commit)
    document = decode(commit_payload)
    if document.get("sha") != commit or not isinstance(document.get("tree"), dict):
        raise ValueError("WA SOC commit response differs from pinned commit")
    tree_id = object_id(document["tree"].get("sha"))
    tree = decode(tree_payload)
    if (
        tree.get("sha") != tree_id
        or tree.get("truncated") is not False
        or not isinstance(tree.get("tree"), list)
    ):
        raise ValueError("WA SOC tree is truncated, incomplete or mismatched")
    paths = set()
    files = []
    directory = False
    for item in tree["tree"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("Malformed WA SOC tree item")
        path = item["path"]
        if path in paths:
            raise ValueError("Duplicate WA SOC tree path")
        paths.add(path)
        if path == "docs/advisories":
            if item.get("type") != "tree" or item.get("mode") != "040000":
                raise ValueError("WA SOC advisory directory is not a tree")
            directory = True
        elif path.startswith("docs/advisories/"):
            match = PATH.fullmatch(path)
            size = item.get("size")
            if (
                match is None
                or item.get("type") != "blob"
                or item.get("mode") != "100644"
                or type(size) is not int
                or size <= 0
            ):
                raise ValueError("Unsupported WA SOC advisory path or object")
            files.append(AdvisoryFile(commit, path, object_id(item.get("sha")), size))
    if not directory:
        raise ValueError("WA SOC tree lacks its advisory directory")
    return tuple(sorted(files, key=lambda f: f.path))
