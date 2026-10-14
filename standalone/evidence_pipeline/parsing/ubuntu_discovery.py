"""Bounded Canonical OSV inventory from exact non-recursive Git tree responses.

The index discovers USN, LSN and CVE-year partitions without loading records.
Missing trees remain pending. Metadata completion does not imply collection.
Publisher layout/licence: https://github.com/canonical/ubuntu-security-notices
"""

from collections import deque
from dataclasses import dataclass
import re

from standalone.evidence_pipeline.parsing.github_discovery import (
    AdvisoryFile,
    decode,
    object_id,
)
from standalone.evidence_pipeline.parsing.github_discovery import (
    current_commit as current_commit,
)
from standalone.evidence_pipeline.parsing.ubuntu_advisories import repository_endpoint

REPOSITORY = "canonical/ubuntu-security-notices"
PARTITION = re.compile(r"(?:usn|lsn|cve/[0-9]{4})\Z")
MAX_ENTRIES = 100_000


def object_url(kind, identity):
    if (kind, identity) != ("ref", "heads/main"):
        if kind not in {"commits", "trees"}:
            raise ValueError("Unsupported Ubuntu discovery object")
        object_id(identity)
    return f"https://api.github.com/repos/{REPOSITORY}/git/{kind}/{identity}"


@dataclass(frozen=True)
class UbuntuFile(AdvisoryFile):
    @property
    def advisory_id(self):
        return self.path.rsplit("/", 1)[-1].removesuffix(".json")

    @property
    def url(self):
        return repository_endpoint(self.commit, self.path, self.advisory_id)


@dataclass(frozen=True)
class Discovery:
    commit: str
    partition: str | None
    partitions: tuple[str, ...]
    files: tuple[UbuntuFile, ...]
    pending_trees: tuple[str, ...]

    @property
    def complete(self):
        return not self.pending_trees


def plan(commit, commit_payload, trees, *, partition=None):
    """Index partitions, or list one partition with immutable file identities.

    Response URLs are ignored. The caller retains the exact metadata bytes and
    fetches pending objects using object_url, subject to a shared request budget.
    """
    object_id(commit)
    if partition is not None and (
        not isinstance(partition, str) or not PARTITION.fullmatch(partition)
    ):
        raise ValueError("Ubuntu partition requires usn, lsn or cve/YYYY")
    doc = decode(commit_payload)
    if doc.get("sha") != commit or not isinstance(doc.get("tree"), dict):
        raise ValueError("Ubuntu commit response identity mismatch")
    root = object_id(doc["tree"].get("sha"))
    if not isinstance(trees, dict) or len(trees) > MAX_ENTRIES:
        raise ValueError("Invalid Ubuntu tree cache")
    for identity, wire in trees.items():
        object_id(identity)
        if not isinstance(wire, bytes):
            raise ValueError("Ubuntu tree cache requires bytes")
    selected = "osv/" + partition if partition is not None else None
    queue = deque([("", root, ())])
    pending, partitions, files = set(), set(), []
    count = 0
    while queue:
        prefix, identity, ancestors = queue.popleft()
        if identity in ancestors or len(ancestors) > 3:
            raise ValueError("Cyclic or overly deep Ubuntu tree")
        if identity not in trees:
            pending.add(identity)
            continue
        tree = decode(trees[identity])
        if (
            tree.get("sha") != identity
            or tree.get("truncated") is not False
            or not isinstance(tree.get("tree"), list)
        ):
            raise ValueError("Incomplete or mismatched Ubuntu tree")
        required = (
            {"osv"}
            if not prefix
            else ({"cve", "usn", "lsn"} if prefix == "osv/" else set())
        )
        if selected and selected.startswith(prefix) and selected != prefix.rstrip("/"):
            required = {selected[len(prefix) :].split("/", 1)[0]}
        seen, directories = set(), set()
        for item in tree["tree"]:
            count += 1
            if count > MAX_ENTRIES or not isinstance(item, dict):
                raise ValueError("Invalid or oversized Ubuntu inventory")
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
                raise ValueError("Unsafe or duplicate Ubuntu tree path")
            seen.add(name)
            path = prefix + name
            if item.get("type") == "tree":
                directories.add(name)
            if selected and prefix == selected + "/":
                if (
                    not name.endswith(".json")
                    or item.get("type") != "blob"
                    or item.get("mode") != "100644"
                ):
                    raise ValueError("Invalid Ubuntu advisory file or mode")
                size = item.get("size")
                if type(size) is not int or size <= 0:
                    raise ValueError("Invalid Ubuntu advisory size")
                record = UbuntuFile(commit, path, object_id(item.get("sha")), size)
                record.url  # Validate publisher family/year against native identity.
                files.append(record)
                continue
            if not prefix:
                relevant = name == "osv"
            elif prefix == "osv/":
                relevant = name in {"cve", "lsn", "usn"}
            else:
                if prefix != "osv/cve/" or not re.fullmatch(r"[0-9]{4}", name):
                    raise ValueError("Invalid Ubuntu CVE year directory")
                relevant = True
            if not relevant:
                continue
            if item.get("type") != "tree" or item.get("mode") != "040000":
                raise ValueError("Invalid Ubuntu directory mode")
            child = object_id(item.get("sha"))
            if selected and path != selected and not selected.startswith(path + "/"):
                continue
            relative = path.removeprefix("osv/")
            if PARTITION.fullmatch(relative) and selected is None:
                partitions.add(relative)
            else:
                queue.append((path + "/", child, ancestors + (identity,)))
        if not required <= directories:
            raise ValueError("Ubuntu discovery is missing a required directory")
    return Discovery(
        commit,
        partition,
        tuple(sorted(partitions)),
        tuple(sorted(files, key=lambda row: row.path)),
        tuple(sorted(pending)),
    )
