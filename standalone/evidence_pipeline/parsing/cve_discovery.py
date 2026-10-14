"""Discover CVE record files from non-recursive, commit-pinned repository trees.

An index lists year/bucket partitions without loading every record. A selected
partition is bounded independently. Missing trees are pending, never empty data.
This module plans work only; it performs no network or database operations.
"""

from collections import deque
from dataclasses import dataclass
import hashlib
import re

from standalone.evidence_pipeline.parsing.github_discovery import decode, object_id

REPOSITORIES = {
    "CVE": ("CVEProject/cvelistV5", "cves/"),
    "CISA": ("cisagov/vulnrichment", ""),
}
PARTITION = re.compile(r"[0-9]{4}/[0-9]{1,16}xxx")
RECORD = re.compile(r"CVE-([0-9]{4})-([0-9]{4,19})\.json")
MAX_ENTRIES = 100_000


def object_url(source, kind, identity):
    if source not in REPOSITORIES:
        raise ValueError("Unsupported CVE discovery source")
    repository, _ = REPOSITORIES[source]
    branch = "main" if source == "CVE" else "develop"
    if (kind, identity) != ("ref", "heads/" + branch):
        if kind not in {"commits", "trees"}:
            raise ValueError("Unsupported CVE discovery object")
        object_id(identity)
    return f"https://api.github.com/repos/{repository}/git/{kind}/{identity}"


def current_commit(source, payload):
    object_url(source, "ref", "heads/main" if source == "CVE" else "heads/develop")
    document = decode(payload)
    branch = "main" if source == "CVE" else "develop"
    obj = document.get("object")
    if (
        document.get("ref") != "refs/heads/" + branch
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
    ):
        raise ValueError("CVE reference must identify its supported branch and commit")
    return object_id(obj.get("sha"))


def record_url(source, commit, path, cve_id):
    if source not in REPOSITORIES:
        raise ValueError("Unsupported CVE discovery source")
    object_id(commit)
    if not isinstance(cve_id, str) or not RECORD.fullmatch(cve_id + ".json"):
        raise ValueError("Invalid CVE record identifier")
    repository, base = REPOSITORIES[source]
    _, year, sequence = cve_id.split("-")
    expected = f"{base}{year}/{sequence[:-3]}xxx/{cve_id}.json"
    if path != expected:
        raise ValueError("CVE record path differs from requested identifier")
    return f"https://raw.githubusercontent.com/{repository}/{commit}/{expected}"


@dataclass(frozen=True)
class RecordFile:
    source: str
    commit: str
    path: str
    cve_id: str
    blob: str
    size: int

    @property
    def url(self):
        return record_url(self.source, self.commit, self.path, self.cve_id)

    def verify_payload(self, payload):
        if not isinstance(payload, bytes) or len(payload) != self.size:
            raise ValueError("CVE bytes differ from indexed size")
        digest = hashlib.sha1(
            b"blob " + str(len(payload)).encode() + b"\0" + payload
        ).hexdigest()
        if digest != self.blob:
            raise ValueError("CVE bytes differ from indexed Git blob")


@dataclass(frozen=True)
class Discovery:
    source: str
    commit: str
    partition: str | None
    partitions: tuple[str, ...]
    files: tuple[RecordFile, ...]
    pending_trees: tuple[str, ...]

    @property
    def complete(self):
        return not self.pending_trees


def plan(source, commit, commit_payload, trees, *, partition=None):
    """With no partition, enumerate buckets; otherwise enumerate that bucket.

    Callers retain exact tree responses between bounded passes. API-provided URLs
    are ignored. Returned file URLs use only the fixed repository and validated
    commit/path. Completeness describes metadata, not collection or database state.
    """
    if source not in REPOSITORIES:
        raise ValueError("Unsupported CVE discovery source")
    if partition is not None and (
        not isinstance(partition, str) or not PARTITION.fullmatch(partition)
    ):
        raise ValueError("CVE partition requires YYYY/Nxxx")
    object_id(commit)
    document = decode(commit_payload)
    if document.get("sha") != commit or not isinstance(document.get("tree"), dict):
        raise ValueError("CVE commit response identity mismatch")
    root = object_id(document["tree"].get("sha"))
    if not isinstance(trees, dict) or len(trees) > MAX_ENTRIES:
        raise ValueError("Invalid CVE tree cache")
    for identity, payload in trees.items():
        object_id(identity)
        if not isinstance(payload, bytes):
            raise ValueError("CVE tree cache requires bytes")
    _, base = REPOSITORIES[source]
    selected = base + partition if partition is not None else None
    queue = deque([("", root, ())])
    pending, partitions, files = set(), set(), []
    count = 0
    while queue:
        prefix, identity, ancestors = queue.popleft()
        if identity in ancestors or len(ancestors) > 3:
            raise ValueError("Cyclic or overly deep CVE tree")
        if identity not in trees:
            pending.add(identity)
            continue
        tree = decode(trees[identity])
        if (
            tree.get("sha") != identity
            or tree.get("truncated") is not False
            or not isinstance(tree.get("tree"), list)
        ):
            raise ValueError("Incomplete or mismatched CVE tree")
        required = "cves" if base and not prefix else None
        if (
            selected is not None
            and selected.startswith(prefix)
            and selected != prefix.rstrip("/")
        ):
            required = selected[len(prefix) :].split("/", 1)[0]
        seen = set()
        directories = set()
        for item in tree["tree"]:
            count += 1
            if count > MAX_ENTRIES or not isinstance(item, dict):
                raise ValueError("Invalid or oversized CVE inventory")
            name = item.get("path")
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 255
                or name in {".", ".."}
                or "/" in name
                or "\\" in name
                or any(ord(c) < 32 for c in name)
                or name in seen
            ):
                raise ValueError("Unsafe or duplicate CVE tree path")
            seen.add(name)
            path = prefix + name
            if item.get("type") == "tree":
                directories.add(name)
            # Ignore unrelated repository metadata, but never malformed records
            # inside a selected bucket or malformed directories below a year.
            if selected is not None and prefix == selected + "/":
                match = RECORD.fullmatch(name)
                if (
                    match is None
                    or partition != f"{match[1]}/{match[2][:-3]}xxx"
                    or item.get("type") != "blob"
                    or item.get("mode") != "100644"
                ):
                    raise ValueError("Invalid CVE record path or mode")
                size = item.get("size")
                if type(size) is not int or size <= 0:
                    raise ValueError("Invalid CVE record size")
                files.append(
                    RecordFile(
                        source,
                        commit,
                        path,
                        name[:-5],
                        object_id(item.get("sha")),
                        size,
                    )
                )
                continue
            if base and not prefix:
                relevant = name == "cves"
            elif prefix == base:
                relevant = re.fullmatch(r"[0-9]{4}", name) is not None
            else:
                relative = path.removeprefix(base)
                if PARTITION.fullmatch(relative) is None:
                    raise ValueError("Invalid CVE bucket path")
                relevant = True
            if not relevant:
                continue
            if item.get("type") != "tree" or item.get("mode") != "040000":
                raise ValueError("Invalid CVE directory mode")
            child = object_id(item.get("sha"))
            if (
                selected is not None
                and path != selected
                and not selected.startswith(path + "/")
            ):
                continue
            relative = path.removeprefix(base)
            if PARTITION.fullmatch(relative) and selected is None:
                partitions.add(relative)
            else:
                queue.append((path + "/", child, ancestors + (identity,)))
        if required is not None and required not in directories:
            raise ValueError("CVE discovery is missing its requested directory")
    return Discovery(
        source,
        commit,
        partition,
        tuple(sorted(partitions)),
        tuple(sorted(files, key=lambda file: file.path)),
        tuple(sorted(pending)),
    )
