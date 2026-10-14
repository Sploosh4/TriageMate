"""Plan resumable advisory discovery from pinned GitHub commit/tree responses.

Uses non-recursive trees: recursive GitHub listings can truncate at 100,000
entries/7 MB. This module does not fetch URLs or write to the database.
"""

from collections import deque
from dataclasses import dataclass
import hashlib
import re

from standalone.evidence_pipeline.parsing.github_advisories import PATH, endpoint
from standalone.evidence_pipeline.parsing.public_inputs import _json

API = "https://api.github.com/repos/github/advisory-database/git/"
MAX_ENTRIES = 100_000
PARTITION_SIZE = 128


def object_id(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[0-9a-f]{40}", value)
        or value == "0" * 40
    ):
        raise ValueError("GitHub discovery requires a nonzero full object ID")
    return value


def object_url(kind, identity):
    if (kind, identity) == ("ref", "heads/main"):
        return API + "ref/heads/main"
    if kind not in {"commits", "trees"}:
        raise ValueError("Unsupported GitHub discovery object")
    return API + kind + "/" + object_id(identity)


def current_commit(payload):
    document = decode(payload)
    obj = document.get("object")
    if (
        document.get("ref") != "refs/heads/main"
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
    ):
        raise ValueError("GitHub current reference must identify main and a commit")
    return object_id(obj.get("sha"))


def decode(payload):
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Invalid GitHub discovery payload size")
    return _json(payload.decode("utf-8-sig"))


@dataclass(frozen=True)
class AdvisoryFile:
    commit: str
    path: str
    blob: str
    size: int

    @property
    def url(self):
        return endpoint(self.commit, self.path)

    def verify_payload(self, payload):
        if not isinstance(payload, bytes) or len(payload) != self.size:
            raise ValueError("Advisory bytes differ from discovered size")
        # Git object identity, not a signature or a substitute for HTTPS.
        digest = hashlib.sha1(
            b"blob " + str(len(payload)).encode() + b"\0" + payload
        ).hexdigest()
        if digest != self.blob:
            raise ValueError("Advisory bytes differ from discovered Git blob")


@dataclass(frozen=True)
class Discovery:
    commit: str
    files: tuple[AdvisoryFile, ...]
    pending_trees: tuple[str, ...]
    partition: str | None = None
    index_only: bool = False
    partitions: tuple[str, ...] = ()

    @property
    def complete(self):
        return not self.pending_trees


def relevant_directory(path):
    parts = path.split("/")
    if parts[0] != "advisories":
        return False
    if len(parts) == 1:
        return True
    if parts[1] not in {"github-reviewed", "unreviewed"}:
        return False
    # Descend through the publisher's supported families; malformed leaf paths
    # are errors below rather than silently disappearing from a complete result.
    return True


def partition_prefix(partition):
    if partition is None:
        return None
    if not isinstance(partition, str) or not re.fullmatch(
        r"(github-reviewed|unreviewed)/[0-9]{4}/(0[1-9]|1[0-2])(?:@[0-9]{6})?",
        partition,
    ):
        raise ValueError("Discovery partition requires family/YYYY/MM")
    if "@" in partition and int(partition.rsplit("@", 1)[1]) % PARTITION_SIZE:
        raise ValueError("Discovery chunk offset must align with its partition size")
    return "advisories/" + partition.split("@", 1)[0]


def plan(commit, commit_payload, trees, *, partition=None, index_only=False):
    """Return discovered files plus missing tree IDs; no partial completeness.

    `trees` contains exact non-recursive response bytes keyed by object SHA.
    Persist responses between bounded network passes; a missing subtree is pending.
    Tree URLs in response bodies are never used as request destinations.
    """
    selected = partition_prefix(partition)
    if type(index_only) is not bool or (
        index_only and partition is not None and "@" in partition
    ):
        raise ValueError("Partition index cannot select an individual partition")
    offset = (
        int(partition.rsplit("@", 1)[1]) if partition and "@" in partition else None
    )
    object_id(commit)
    document = decode(commit_payload)
    if document.get("sha") != commit or not isinstance(document.get("tree"), dict):
        raise ValueError("GitHub commit response differs from requested commit")
    root = object_id(document["tree"].get("sha"))
    if not isinstance(trees, dict) or len(trees) > MAX_ENTRIES:
        raise ValueError("Invalid GitHub tree cache")
    for identity, wire in trees.items():
        object_id(identity)
        if not isinstance(wire, bytes):
            raise ValueError("GitHub tree cache requires response bytes")
    queue = deque([("", root, ())])
    files = []
    partitions = set()
    pending = set()
    count = 0
    while queue:
        prefix, identity, ancestors = queue.popleft()
        if identity in ancestors or len(ancestors) > 10:
            raise ValueError("Cyclic or overly deep GitHub tree")
        if identity not in trees:
            pending.add(identity)
            continue
        tree = decode(trees[identity])
        if (
            tree.get("sha") != identity
            or tree.get("truncated") is not False
            or not isinstance(tree.get("tree"), list)
        ):
            raise ValueError("Incomplete or mismatched GitHub tree response")
        required = (
            {"advisories"}
            if not prefix
            else (
                {"github-reviewed", "unreviewed"} if prefix == "advisories/" else set()
            )
        )
        if selected and (not prefix or selected.startswith(prefix)):
            remaining = selected[len(prefix) :]
            if remaining:
                required |= {remaining.split("/", 1)[0]}
        directories = {
            item.get("path")
            for item in tree["tree"]
            if isinstance(item, dict)
            and item.get("type") == "tree"
            and isinstance(item.get("path"), str)
        }
        if not required <= directories:
            raise ValueError(
                "GitHub discovery is missing a required advisory directory"
            )
        chunk_names = None
        if selected and prefix == selected + "/" and (index_only or offset is not None):
            names = sorted(directories)
            if any(
                PATH.fullmatch(prefix + name + "/" + name + ".json") is None
                for name in names
            ):
                raise ValueError("Unsupported advisory directory in monthly index")
            if offset is not None:
                if offset >= len(names):
                    raise ValueError("Discovery chunk is outside its month")
                chunk_names = set(names[offset : offset + PARTITION_SIZE])
            elif names:
                partitions.update(
                    partition + "@" + f"{start:06d}"
                    for start in range(0, len(names), PARTITION_SIZE)
                )
        leaf_parts = prefix.rstrip("/").split("/")
        if len(leaf_parts) == 5 and relevant_directory(prefix.rstrip("/")):
            expected_file = leaf_parts[-1] + ".json"
            if not any(
                isinstance(item, dict)
                and item.get("path") == expected_file
                and item.get("type") == "blob"
                for item in tree["tree"]
            ):
                raise ValueError(
                    "GitHub advisory directory is missing its native record"
                )
        seen = set()
        for item in tree["tree"]:
            count += 1
            if count > MAX_ENTRIES or not isinstance(item, dict):
                raise ValueError("Invalid or oversized GitHub tree inventory")
            name = item.get("path")
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 255
                or "/" in name
                or "\\" in name
                or name in {".", ".."}
                or any(ord(c) < 32 for c in name)
                or name in seen
            ):
                raise ValueError("Unsafe, recursive or duplicate GitHub tree path")
            seen.add(name)
            path = prefix + name
            if item.get("type") == "tree":
                if relevant_directory(path) and (
                    selected is None
                    or selected == path
                    or selected.startswith(path + "/")
                    or path.startswith(selected + "/")
                ):
                    if item.get("mode") != "040000":
                        raise ValueError("Invalid GitHub directory mode")
                    if index_only and selected is None and len(path.split("/")) == 4:
                        candidate = path.removeprefix("advisories/")
                        partition_prefix(candidate)
                        object_id(item.get("sha"))
                        partitions.add(candidate)
                        continue
                    if selected and prefix == selected + "/":
                        if index_only or (
                            chunk_names is not None and name not in chunk_names
                        ):
                            object_id(item.get("sha"))
                            continue
                    queue.append(
                        (
                            path + "/",
                            object_id(item.get("sha")),
                            ancestors + (identity,),
                        )
                    )
            elif path.startswith(
                ("advisories/github-reviewed/", "advisories/unreviewed/")
            ):
                if (
                    PATH.fullmatch(path) is None
                    or item.get("type") != "blob"
                    or item.get("mode") != "100644"
                ):
                    raise ValueError("Unsupported file in GitHub advisory inventory")
                size = item.get("size")
                if type(size) is not int or size <= 0:
                    raise ValueError("Invalid GitHub advisory blob size")
                files.append(
                    AdvisoryFile(commit, path, object_id(item.get("sha")), size)
                )
    return Discovery(
        commit,
        tuple(sorted(files, key=lambda item: item.path)),
        tuple(sorted(pending)),
        partition,
        index_only,
        tuple(sorted(partitions)),
    )
