"""Durable OSV package-query evidence; existing bundles never refetch.

A receipt is written last. A crash leaving an incomplete directory requires
explicit investigation; it never silently starts another collection.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import sys
import psycopg2

from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.parsing.osv_query import MAX_PAGES, QueryResult
from standalone.evidence_pipeline.contracts import PublicDownload

MAX_RECEIPT_BYTES = 128_000


@dataclass(frozen=True)
class QueryCollection:
    snapshot: Snapshot
    result: QueryResult | None
    responses: tuple[PublicDownload, ...]


def _sync(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read(path, limit=None):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o077
        or info.st_uid != os.getuid()
        or (limit is not None and info.st_size > limit)
    ):
        raise ValueError("Query replay requires bounded owner-only regular files")
    with path.open("rb") as stream:
        data = stream.read() if limit is None else stream.read(limit + 1)
    if limit is not None and len(data) > limit:
        raise ValueError("Query replay file exceeds its byte limit")
    return data


def prepare(
    scope,
    execution_id,
    bundle,
    *,
    name=None,
    ecosystem=None,
    purl=None,
    version=None,
    synthetic_pages=None,
    replay_only=False,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("OSV")


def main(argv=None):
    from standalone.evidence_pipeline.commands import load_scope

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--name")
    parser.add_argument("--ecosystem")
    parser.add_argument("--purl")
    parser.add_argument("--version")
    parser.add_argument(
        "--import",
        dest="import_evidence",
        action="store_true",
        help="Import into a previously registered query connection",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-network", action="store_true")
    mode.add_argument("--replay-only", action="store_true")
    mode.add_argument(
        "--synthetic-page",
        action="append",
        help="Synthetic page file, repeated in response order",
    )
    args = parser.parse_args(argv)
    try:
        fixtures = None
        if args.synthetic_page is not None:
            if len(args.synthetic_page) > MAX_PAGES:
                raise ValueError("Too many synthetic pages")
            fixtures = []

            for filename in args.synthetic_page:
                path = Path(filename)
                if not path.is_file():
                    raise ValueError("Synthetic input must be a regular file")
                with path.open("rb") as stream:
                    wire = stream.read()

                fixtures.append(wire)
        outcome = prepare(
            load_scope(args.scope),
            args.execution_id,
            args.bundle,
            name=args.name,
            ecosystem=args.ecosystem,
            purl=args.purl,
            version=args.version,
            synthetic_pages=fixtures,
            replay_only=args.replay_only,
        )
        imported = {}
        if args.import_evidence:
            from standalone.evidence_pipeline.osv_query_commands import ingest

            imported = ingest(outcome)
        from standalone.evidence_pipeline.assessment.osv_applicability import (
            evaluate_query,
        )

        print(
            json.dumps(
                dict(
                    execution_id=outcome.snapshot.execution_id,
                    outcome=outcome.snapshot.outcome,
                    error_code=outcome.snapshot.error_code,
                    page_count=len(outcome.responses),
                    advisory_count=sum(
                        len(page.records) for page in outcome.result.pages
                    )
                    if outcome.result
                    else 0,
                    database_imported=bool(args.import_evidence),
                    version_assessment=evaluate_query(outcome.result)
                    if outcome.result
                    else None,
                    **({"replayed": imported["replayed"]} if imported else {}),
                ),
                sort_keys=True,
            )
        )
        return 0 if outcome.snapshot.complete else 2
    except (ValueError, OSError, TypeError, psycopg2.Error):
        print("OSV query collection or replay could not be verified", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
