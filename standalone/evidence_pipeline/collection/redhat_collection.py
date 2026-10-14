"""Bounded Red Hat index-to-advisory collection with immutable local continuation."""

import json
from pathlib import Path


def collect(
    output,
    *,
    origin,
    execution_id,
    limit=10,
    after=None,
    synthetic_index=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Red Hat")


def main(argv=None):
    import argparse
    import sys
    import psycopg2
    from standalone.evidence_pipeline.parsing.redhat_discovery import advisory_file

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--origin", choices=("public", "synthetic"), required=True)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--after")
    parser.add_argument("--import", dest="import_records", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--allow-network", action="store_true")
    mode.add_argument("--replay-only", action="store_true")
    mode.add_argument("--synthetic-index")
    parser.add_argument(
        "--synthetic-manifest", help="JSON object mapping index paths to fixture files"
    )
    args = parser.parse_args(argv)
    try:
        index, fixtures = None, None
        if args.synthetic_index:
            if args.origin != "synthetic":
                raise ValueError("Synthetic index requires synthetic origin")
            with Path(args.synthetic_index).open("rb") as stream:
                index = stream.read()
        if args.synthetic_manifest:
            if args.origin != "synthetic":
                raise ValueError("Synthetic manifest requires synthetic origin")
            from standalone.evidence_pipeline.parsing.public_inputs import _json

            manifest = Path(args.synthetic_manifest)
            with manifest.open("rb") as stream:
                raw = stream.read()
            mapping = _json(raw.decode())
            fixtures = {}
            for path, filename in mapping.items():
                advisory_file(path)
                if not isinstance(filename, str):
                    raise ValueError("Fixture filename must be text")
                with (manifest.parent / filename).open("rb") as stream:
                    fixtures[path] = stream.read()
        result = collect(
            args.output,
            origin=args.origin,
            execution_id=args.execution_id,
            limit=args.limit,
            after=args.after,
            synthetic_index=index,
            synthetic_payloads=fixtures,
            allow_network=args.allow_network,
            replay_only=args.replay_only,
            import_records=args.import_records,
        )
        print(json.dumps(result, sort_keys=True))
        return (
            0 if all(row["outcome"] == "success" for row in result["outcomes"]) else 1
        )
    except (ValueError, OSError, TypeError, psycopg2.Error):
        print(
            "Red Hat batch did not confirm completion. Preserve its output directory and execution ID before investigating or replaying.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
