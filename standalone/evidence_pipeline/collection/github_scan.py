"""Bounded GitHub discovery passes over immutable, replayable object bundles."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat

from standalone.evidence_pipeline.parsing.github_discovery import (
    Discovery,
    object_id,
    partition_prefix,
    plan,
)
from standalone.evidence_pipeline.collection.github_discovery_collection import prepare
from standalone.evidence_pipeline.collection.osv_query_collection import _read, _sync
from standalone.evidence_pipeline.collection.public_collection import _write
from standalone.evidence_pipeline.collection.public_pacing import PublicSourceBusy
from standalone.evidence_pipeline.parsing import (
    cve_discovery,
    ubuntu_discovery,
    wasoc_discovery,
)
from standalone.evidence_pipeline.collection.collection_scope import (
    require_active_collection,
)


def _partition(source, partition, index_only):
    if source == "GitHub":
        partition_prefix(partition)
    elif source == "WA SOC":
        if index_only or partition not in (None, "advisories"):
            raise ValueError("WA SOC scans use no partition or advisories")
    elif source == "Ubuntu":
        if index_only or (
            partition is not None
            and (
                not isinstance(partition, str)
                or not ubuntu_discovery.PARTITION.fullmatch(partition)
            )
        ):
            raise ValueError(
                "Ubuntu scans use no partition for an index or usn, lsn, cve/YYYY"
            )
    elif source in cve_discovery.REPOSITORIES:
        if index_only or (
            partition is not None
            and (
                not isinstance(partition, str)
                or not cve_discovery.PARTITION.fullmatch(partition)
            )
        ):
            raise ValueError(
                "CVE scans use no partition for an index or YYYY/Nxxx for records"
            )
    else:
        raise ValueError("Unsupported repository discovery source")


@dataclass(frozen=True)
class ScanResult:
    discovery: (
        Discovery
        | cve_discovery.Discovery
        | ubuntu_discovery.Discovery
        | wasoc_discovery.Discovery
        | None
    )
    collected_objects: int
    failures: tuple[tuple[str, str], ...]
    pending_objects: tuple[tuple[str, str], ...]

    @property
    def complete(self):
        return (
            self.discovery is not None and self.discovery.complete and not self.failures
        )


def scan(
    commit,
    bundle,
    *,
    origin,
    limit=10,
    synthetic_objects=None,
    allow_network=False,
    replay_only=False,
    partition=None,
    index_only=False,
    object_cache=None,
    source="GitHub",
):
    """Resume one explicit commit; never treat missing/failed objects as empty.

    Synthetic fixtures map (kind, SHA) to bytes. Limit counts only new objects;
    replayed objects consume no network budget. Failed bundles remain inspectable
    and are not automatically retried. No advisory import or latest-ref lookup.
    """
    require_active_collection(source)
    object_id(commit)
    _partition(source, partition, index_only)
    if type(index_only) is not bool or (
        index_only and partition is not None and "@" in partition
    ):
        raise ValueError("Partition index cannot select an individual partition")
    if (
        origin not in {"synthetic", "public"}
        or type(limit) is not int
        or not 0 <= limit <= 100
    ):
        raise ValueError("Invalid discovery origin or object budget")
    if (
        type(allow_network) is not bool
        or type(replay_only) is not bool
        or (allow_network and (origin != "public" or replay_only))
    ):
        raise ValueError("Invalid discovery scan mode")
    if synthetic_objects is not None and (
        origin != "synthetic" or not isinstance(synthetic_objects, dict)
    ):
        raise ValueError("Synthetic object fixtures require synthetic origin")
    bundle = Path(bundle)
    expected = dict(commit=commit, origin=origin, version=1)
    if source != "GitHub":
        expected["source"] = source
    if partition is not None:
        expected["partition"] = partition
    if index_only:
        expected["index_only"] = True
    if bundle.is_symlink():
        raise ValueError("Discovery scan directory cannot be a symlink")
    if not bundle.exists():
        if replay_only:
            raise ValueError("Discovery scan does not exist")
        bundle.mkdir(mode=0o700)
        _sync(bundle.parent)
        _write(bundle / "scan.json", json.dumps(expected, sort_keys=True).encode())
        _sync(bundle)
    info = bundle.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError("Discovery scan requires an owner-only directory")
    if json.loads(_read(bundle / "scan.json", 4096)) != expected:
        raise ValueError("Discovery scan belongs to another commit or origin")
    cache = Path(object_cache) if object_cache is not None else bundle
    if cache.is_symlink():
        raise ValueError("Discovery object cache cannot be a symlink")
    if not cache.exists():
        if replay_only:
            raise ValueError("Discovery replay cache does not exist")
        cache.mkdir(mode=0o700)
        _sync(cache.parent)
    cache_info = cache.lstat()
    if (
        not stat.S_ISDIR(cache_info.st_mode)
        or cache_info.st_mode & 0o077
        or cache_info.st_uid != os.getuid()
    ):
        raise ValueError("Discovery object cache requires an owner-only directory")
    collected = 0
    failures = {}
    pending = set()

    def load(kind, identity):
        nonlocal collected
        key = (kind, identity)
        path = cache / (kind + "-" + identity)
        cached = path.exists() or path.is_symlink()
        fixture = (synthetic_objects or {}).get(key)
        if not cached and (
            replay_only
            or collected >= limit
            or (origin == "public" and not allow_network)
            or (origin == "synthetic" and fixture is None)
        ):
            pending.add(key)
            return None
        try:
            value = prepare(
                kind,
                identity,
                path,
                origin=origin,
                synthetic_payload=fixture,
                replay_only=cached,
                allow_network=allow_network and not cached,
                source=source,
            )
        except PublicSourceBusy:
            pending.add(key)
            return None
        if not cached:
            collected += 1
        if not value.complete:
            failures[kind + "/" + identity] = value.error_code
            pending.add(key)
            return None
        return value.payload

    commit_payload = load("commits", commit)
    if commit_payload is None:
        return ScanResult(
            None, collected, tuple(sorted(failures.items())), tuple(sorted(pending))
        )
    trees = {}
    while True:
        if source == "GitHub":
            result = plan(
                commit,
                commit_payload,
                trees,
                partition=partition,
                index_only=index_only,
            )
        elif source == "Ubuntu":
            result = ubuntu_discovery.plan(
                commit, commit_payload, trees, partition=partition
            )
        elif source == "WA SOC":
            result = wasoc_discovery.scan_plan(
                commit, commit_payload, trees, partition=partition
            )
        else:
            result = cve_discovery.plan(
                source, commit, commit_payload, trees, partition=partition
            )
        added = False
        for identity in result.pending_trees:
            if ("trees", identity) in pending:
                continue
            payload = load("trees", identity)
            if payload is not None:
                trees[identity] = payload
                added = True
        if not added:
            return ScanResult(
                result,
                collected,
                tuple(sorted(failures.items())),
                tuple(sorted(pending)),
            )


def scan_current(
    bundle,
    *,
    origin,
    limit=10,
    synthetic_objects=None,
    allow_network=False,
    replay_only=False,
    partition=None,
    index_only=False,
    object_cache=None,
    source="GitHub",
):
    from standalone.evidence_pipeline.parsing.github_discovery import current_commit

    require_active_collection(source)
    if (
        origin not in {"public", "synthetic"}
        or type(limit) is not int
        or not 0 <= limit <= 100
    ):
        raise ValueError("Invalid current scan origin or request budget")
    _partition(source, partition, index_only)
    branch_ref = "heads/develop" if source == "CISA" else "heads/main"
    if (
        any(type(flag) is not bool for flag in (allow_network, replay_only, index_only))
        or (allow_network and (origin != "public" or replay_only))
        or (partition is not None and index_only and "@" in partition)
    ):
        raise ValueError("Invalid current scan mode")
    if synthetic_objects is not None and (
        origin != "synthetic" or not isinstance(synthetic_objects, dict)
    ):
        raise ValueError("Invalid current scan synthetic fixtures")
    bundle = Path(bundle)
    if bundle.is_symlink():
        raise ValueError("Current scan cannot be a symlink")
    if not bundle.exists():
        if replay_only:
            raise ValueError("Current scan replay does not exist")
        bundle.mkdir(mode=0o700)
        _sync(bundle.parent)
    info = bundle.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
    ):
        raise ValueError("Current scan requires an owner-only directory")
    head = bundle / "head"
    cached = head.exists() or head.is_symlink()
    raw = (synthetic_objects or {}).get(("ref", branch_ref))
    if not cached and (
        limit == 0
        or replay_only
        or (origin == "public" and not allow_network)
        or (origin == "synthetic" and raw is None)
    ):
        return ScanResult(None, 0, (), (("ref", branch_ref),))
    try:
        reference = prepare(
            "ref",
            branch_ref,
            head,
            origin=origin,
            synthetic_payload=raw,
            allow_network=allow_network and not cached,
            replay_only=cached,
            source=source,
        )
    except PublicSourceBusy:
        return ScanResult(None, 0, (), (("ref", branch_ref),))
    used = int(not cached)
    if not reference.complete:
        return ScanResult(
            None,
            used,
            (("ref/" + branch_ref, reference.error_code),),
            (("ref", branch_ref),),
        )
    result = scan(
        current_commit(reference.payload)
        if source in {"GitHub", "Ubuntu", "WA SOC"}
        else cve_discovery.current_commit(source, reference.payload),
        bundle / "scan",
        origin=origin,
        limit=limit - used,
        synthetic_objects=synthetic_objects,
        allow_network=allow_network,
        replay_only=replay_only,
        partition=partition,
        index_only=index_only,
        object_cache=object_cache,
        source=source,
    )
    return ScanResult(
        result.discovery,
        result.collected_objects + used,
        result.failures,
        result.pending_objects,
    )


def main(argv=None):
    import argparse
    from dataclasses import asdict
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        choices=("GitHub", "CVE", "CISA", "Ubuntu", "WA SOC"),
        default="GitHub",
    )
    revision = parser.add_mutually_exclusive_group(required=True)
    revision.add_argument("--commit")
    revision.add_argument(
        "--current",
        action="store_true",
        help="Resolve and retain the current main commit once per bundle",
    )
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--object-cache", help="Shared owner-only metadata cache")
    parser.add_argument("--origin", choices=("public", "synthetic"), required=True)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--partition",
        help="GitHub family/YYYY/MM, CVE YYYY/Nxxx, Ubuntu usn/lsn/cve/YYYY, or WA SOC advisories",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-network", action="store_true")
    mode.add_argument("--replay-only", action="store_true")
    mode.add_argument(
        "--synthetic-manifest",
        help="JSON list of kind, identity and synthetic response file",
    )
    parser.add_argument(
        "--list-partitions",
        action="store_true",
        help="Discover publication months only; does not collect advisories",
    )
    args = parser.parse_args(argv)
    try:
        fixtures = None
        if args.synthetic_manifest:
            from standalone.evidence_pipeline.parsing.github_discovery import (
                decode,
                object_url,
            )

            if args.origin != "synthetic":
                raise ValueError("Synthetic manifest requires synthetic origin")
            manifest = Path(args.synthetic_manifest)
            with manifest.open("rb") as stream:
                document = decode(stream.read())
            records = document.get("objects")
            if not isinstance(records, list) or len(records) > 100_000:
                raise ValueError("Invalid synthetic discovery manifest")
            fixtures = {}
            for item in records:
                if not isinstance(item, dict) or set(item) != {
                    "kind",
                    "identity",
                    "file",
                }:
                    raise ValueError("Invalid synthetic discovery object")
                if args.source == "GitHub":
                    object_url(item["kind"], item["identity"])
                elif args.source == "Ubuntu":
                    ubuntu_discovery.object_url(item["kind"], item["identity"])
                elif args.source == "WA SOC":
                    wasoc_discovery.object_url(item["kind"], item["identity"])
                else:
                    cve_discovery.object_url(
                        args.source, item["kind"], item["identity"]
                    )
                key = (item["kind"], item["identity"])
                if key in fixtures or not isinstance(item["file"], str):
                    raise ValueError("Duplicate or invalid synthetic object file")
                with (manifest.parent / item["file"]).open("rb") as stream:
                    fixtures[key] = stream.read()
        run = scan_current if args.current else scan
        positional = (args.bundle,) if args.current else (args.commit, args.bundle)
        result = run(
            *positional,
            origin=args.origin,
            limit=args.limit,
            synthetic_objects=fixtures,
            allow_network=args.allow_network,
            replay_only=args.replay_only,
            partition=args.partition,
            index_only=args.list_partitions,
            object_cache=args.object_cache,
            source=args.source,
        )
        print(
            json.dumps(dict(asdict(result), complete=result.complete), sort_keys=True)
        )
        return 0 if not result.failures else 1
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"GitHub discovery scan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
