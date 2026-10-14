"""Collect and optionally import bounded files from a complete saved GitHub scan."""

from dataclasses import dataclass
from pathlib import Path

import os

import psycopg2

from standalone.evidence_pipeline.commands import register, ingest_public
from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.github_scan import scan
from standalone.evidence_pipeline.collection.osv_query_collection import _sync
from standalone.evidence_pipeline.collection.public_collection import prepare


@dataclass(frozen=True)
class DispatchResult:
    outcomes: tuple[dict, ...]
    next_after: str | None
    remaining: int


def source_scope(file, origin):
    from standalone.evidence_pipeline.parsing.cve_discovery import RecordFile
    from standalone.evidence_pipeline.parsing.ubuntu_discovery import UbuntuFile
    from standalone.evidence_pipeline.parsing.wasoc_discovery import (
        AdvisoryFile as WasocFile,
    )

    if isinstance(file, WasocFile):
        return SourceScope(
            stable_id("wasoc-discovered-source", origin, file.url),
            "WA SOC",
            "advisories",
            file.url,
            origin,
            "WA SOC public advisory repository, Apache-2.0; https://github.com/wagov/wasocshared"
            if origin == "public"
            else "TriageMate generated synthetic WA SOC repository fixtures",
        )

    if isinstance(file, UbuntuFile):
        return SourceScope(
            stable_id("ubuntu-discovered-source", origin, file.url),
            "Ubuntu",
            "advisories",
            file.url,
            origin,
            "Canonical Ubuntu Vulnerability Data, CC-BY-SA-4.0; https://github.com/canonical/ubuntu-security-notices"
            if origin == "public"
            else "TriageMate generated synthetic Ubuntu repository fixtures",
        )

    if isinstance(file, RecordFile):
        return SourceScope(
            stable_id("cve-discovered-source", origin, file.url),
            file.source,
            "records" if file.source == "CVE" else "vulnrichment",
            file.url,
            origin,
            (
                "CVE Program Terms of Use; https://www.cve.org/Legal/TermsOfUse"
                if file.source == "CVE"
                else "CISA Vulnrichment public-domain US Government work; https://github.com/cisagov/vulnrichment"
            )
            if origin == "public"
            else "TriageMate generated synthetic CVE repository fixtures",
        )
    return SourceScope(
        stable_id("github-discovered-source", origin, file.url),
        "GitHub",
        "advisories",
        file.url,
        origin,
        "GitHub Advisory Database, CC-BY-4.0; https://github.com/github/advisory-database"
        if origin == "public"
        else "TriageMate generated synthetic GitHub discovery/advisory fixtures",
    )


def dispatch(
    commit,
    scan_bundle,
    output,
    *,
    origin,
    execution_id,
    partition=None,
    limit=10,
    after=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
    object_cache=None,
    source="GitHub",
):
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(source)
    execution_id = identifier(execution_id)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("GitHub dispatch limit must be 1 through 100")
    if any(
        type(flag) is not bool for flag in (allow_network, replay_only, import_records)
    ) or (allow_network and (origin != "public" or replay_only)):
        raise ValueError("Invalid GitHub dispatch mode")
    if synthetic_payloads is not None and (
        origin != "synthetic" or not isinstance(synthetic_payloads, dict)
    ):
        raise ValueError("Synthetic advisory fixtures require synthetic origin")
    discovered = scan(
        commit,
        scan_bundle,
        origin=origin,
        partition=partition,
        replay_only=True,
        object_cache=object_cache,
        source=source,
    )
    if not discovered.complete or (
        discovered.discovery.index_only if source == "GitHub" else partition is None
    ):
        raise ValueError("Advisory dispatch requires a complete advisory scan")
    files = discovered.discovery.files
    paths = [file.path for file in files]
    if after is not None and after not in paths:
        raise ValueError("Dispatch continuation must name a discovered file")
    start = paths.index(after) + 1 if after is not None else 0
    selected = files[start : start + limit]
    output = Path(output)
    if output.is_symlink():
        raise ValueError("Dispatch output cannot be a symlink")
    if not output.exists():
        if replay_only:
            raise ValueError("Dispatch replay output does not exist")
        output.mkdir(mode=0o700)
        _sync(output.parent)
    # Object bundles enforce ownership, immutable scope and bounded file replay.
    if (
        not output.is_dir()
        or output.stat().st_mode & 0o077
        or output.stat().st_uid != os.getuid()
    ):
        raise ValueError("Dispatch output requires an owner-only directory")
    outcomes = []
    for file in selected:
        scope = source_scope(file, origin)
        attempt = stable_id(
            "github-discovered-attempt", execution_id, scope.connection_id
        )
        bundle = output / attempt
        payload = (synthetic_payloads or {}).get(file.path)
        cached = bundle.exists() or bundle.is_symlink()
        result = dict(
            path=file.path,
            connection_id=scope.connection_id,
            execution_id=attempt,
            database_imported=False,
        )
        if not cached and (
            replay_only
            or (origin == "public" and not allow_network)
            or (origin == "synthetic" and payload is None)
        ):
            result["outcome"] = "pending"
            outcomes.append(result)
            continue
        try:
            snapshot = prepare(
                scope,
                attempt,
                bundle,
                **(
                    {}
                    if source == "WA SOC"
                    else dict(repository_commit=file.commit, repository_path=file.path)
                ),
                synthetic_payload=payload,
                replay_only=cached,
                **record_options(file, source),
            )
            if not snapshot.complete:
                result["outcome"] = snapshot.error_code
            else:
                file.verify_payload(snapshot.payload)
                result["outcome"] = "success"
            if import_records:
                # A valid OSV document with different Git bytes is rejected above,
                # before registration/import. Transport failures remain attempts.
                register(scope)
                imported = ingest_public(snapshot)
                result.update(database_imported=True, replayed=imported["replayed"])
        except psycopg2.Error:
            result["outcome"] = "database_outcome_uncertain"
        except ValueError:
            result["outcome"] = "invalid_or_mismatched_advisory_bundle"
        outcomes.append(result)
    remaining = max(0, len(files) - start - len(selected))
    return DispatchResult(
        tuple(outcomes),
        selected[-1].path if remaining and selected else None,
        remaining,
    )


def record_options(file, source):
    if source in {"GitHub", "WA SOC"}:
        return {}
    if source == "Ubuntu":
        return {"advisory_id": file.advisory_id}
    return {"cve": file.cve_id}


def main(argv=None):
    import argparse
    from dataclasses import asdict
    import json
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("commit", "scan-bundle", "output", "execution-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--origin", choices=("public", "synthetic"), required=True)
    parser.add_argument("--partition")
    parser.add_argument("--object-cache")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--after")
    parser.add_argument("--import", dest="import_records", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-network", action="store_true")
    mode.add_argument("--replay-only", action="store_true")
    mode.add_argument(
        "--synthetic-manifest",
        help="JSON object mapping advisory paths to synthetic files",
    )
    args = parser.parse_args(argv)
    try:
        fixtures = None
        if args.synthetic_manifest:
            from standalone.evidence_pipeline.parsing.github_discovery import decode
            from standalone.evidence_pipeline.parsing.github_advisories import endpoint

            if args.origin != "synthetic":
                raise ValueError("Synthetic manifest requires synthetic origin")
            manifest = Path(args.synthetic_manifest)
            with manifest.open("rb") as stream:
                mapping = decode(stream.read())
            fixtures = {}
            for path, filename in mapping.items():
                endpoint(args.commit, path)
                if not isinstance(filename, str):
                    raise ValueError("Synthetic manifest file must be a string")
                with (manifest.parent / filename).open("rb") as stream:
                    fixtures[path] = stream.read()
        result = dispatch(
            args.commit,
            args.scan_bundle,
            args.output,
            origin=args.origin,
            execution_id=args.execution_id,
            partition=args.partition,
            limit=args.limit,
            after=args.after,
            synthetic_payloads=fixtures,
            allow_network=args.allow_network,
            replay_only=args.replay_only,
            import_records=args.import_records,
            object_cache=args.object_cache,
        )
        print(json.dumps(asdict(result), sort_keys=True))
        return 0 if all(item["outcome"] == "success" for item in result.outcomes) else 1
    except (ValueError, OSError, TypeError) as exc:
        print(f"GitHub advisory dispatch failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
