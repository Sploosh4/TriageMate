"""Bounded enrichment processing with committed claims and durable offline replay."""

import argparse
from contextlib import closing
import json
from pathlib import Path

from .commands import register, ingest_public
from .contracts import identifier
from standalone.evidence_pipeline.persistence.enrichment_store import (
    discover,
    discover_remaining,
    request_scope,
    start_request,
    SOURCES,
)
from standalone.evidence_pipeline.collection.public_collection import prepare
from standalone.evidence_pipeline.collection.public_pacing import (
    paced,
    PublicSourceBusy,
)
from .runtime import connect


def discover_attempt(attempt_id, *, sources, limit=100):
    with closing(connect()) as conn, conn:
        result = discover(conn, attempt_id, sources=sources, limit=limit)
    return result


def continue_discovery(*, origin, sources, limit=100):
    with closing(connect()) as conn, conn:
        result = discover_remaining(conn, origin=origin, sources=sources, limit=limit)
    return result


def after_findings_commit(snapshot, result):
    """Queue needs only after a successful import commits; never undo that outcome."""
    if (
        result["outcome"] != "success"
        or snapshot.scope.source != "Defender"
        or snapshot.scope.input_kind
        not in ("findings", "vulnerability_baseline", "vulnerability_events")
    ):
        return result
    try:
        ids = discover_attempt(snapshot.execution_id, sources=list(SOURCES), limit=100)
        discovery = dict(state="checked", queued=len(ids), batch_limit=100)
    except Exception:
        discovery = dict(
            state="unconfirmed", error_code="enrichment_discovery_unconfirmed"
        )
    return {**result, "enrichment": discovery}


def status(request_id):
    with closing(connect()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "SELECT state,execution_id::text,error_code FROM evidence_pipeline.enrichment_request_status WHERE id=%s",
            (identifier(request_id),),
        )
        row = cur.fetchone()
    if row is None:
        raise ValueError("Unknown enrichment request")
    return dict(
        request_id=request_id, state=row[0], execution_id=row[1], error_code=row[2]
    )


def _root(path, *, create=True):
    root = Path(path)
    if root.is_symlink():
        raise ValueError("Enrichment bundle root cannot be a symlink")
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    if not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("Enrichment bundle root must be an owner-only directory")
    return root


def process_pending(
    bundle_root,
    *,
    limit=10,
    allow_network=False,
    synthetic_inputs=None,
    sources=None,
    request_ids=None,
):
    """Process at most one bounded selection; competing workers claim each item once.

    Public collection requires the network flag. Synthetic requests require exact
    fixture bytes keyed by request ID and can never enter the network path. A lost
    import acknowledgement remains unconfirmed until an explicit offline replay.
    """
    if (
        type(limit) is not int
        or not 1 <= limit <= 100
        or type(allow_network) is not bool
    ):
        raise ValueError(
            "Use a request limit from 1 to 100 and an explicit network flag"
        )
    sources = list(SOURCES) if sources is None else sources
    if (
        not isinstance(sources, (list, tuple))
        or not sources
        or any(not isinstance(s, str) or s not in SOURCES for s in sources)
        or len(set(sources)) != len(sources)
    ):
        raise ValueError("Choose unique supported enrichment sources")
    selected = None
    if request_ids is not None:
        if not isinstance(request_ids, (list, tuple)) or len(request_ids) > limit:
            raise ValueError("Explicit enrichment batch exceeds its request limit")
        selected = [identifier(key) for key in request_ids]
        if len(set(selected)) != len(selected):
            raise ValueError("Duplicate explicit enrichment request")
        if not selected:
            return []
    fixtures = {} if synthetic_inputs is None else synthetic_inputs
    if (
        not isinstance(fixtures, dict)
        or len(fixtures) > 100
        or (allow_network and fixtures)
        or (not allow_network and not fixtures)
        or any(not isinstance(payload, bytes) for payload in fixtures.values())
    ):
        raise ValueError(
            "Choose public network collection or explicitly synthetic fixtures"
        )
    normalized = {identifier(key): payload for key, payload in fixtures.items()}
    if len(normalized) != len(fixtures):
        raise ValueError("Duplicate synthetic request identities")
    fixtures = normalized
    root = _root(bundle_root)
    if allow_network and selected is None:
        # Bounded continuation discovers omitted needs from stored findings;
        # it does not recollect a failed input or reclaim a failed request.
        continue_discovery(origin="public", sources=sources, limit=100)
    with closing(connect()) as conn, conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id::text FROM evidence_pipeline.enrichment_request_status "
            "WHERE state='queued' AND source_name=ANY(%s) AND ((%s AND origin='public') OR "
            "(origin='synthetic' AND id=ANY(%s::uuid[]))) "
            "AND (%s OR id=ANY(%s::uuid[])) "
            "ORDER BY requested_at,id LIMIT %s",
            (
                list(sources),
                allow_network,
                list(fixtures),
                selected is None,
                selected or [],
                limit,
            ),
        )
        pending = [row[0] for row in cur.fetchall()]
    results = []
    for request in pending:
        try:
            with closing(connect()) as conn, conn, conn.cursor() as cur:
                scope, cve = request_scope(cur, request)
            register(scope)
            with paced(scope.source, origin=scope.origin):
                with closing(connect()) as conn, conn:
                    execution = start_request(conn, request)
                if execution is not None:
                    snapshot = prepare(
                        scope,
                        execution,
                        root / request,
                        cve=cve,
                        synthetic_payload=fixtures.get(request),
                    )
                    ingest_public(snapshot)
            results.append(status(request))
        except PublicSourceBusy:
            results.append(
                dict(
                    request_id=request,
                    state="deferred",
                    error_code="public_source_busy",
                )
            )
        except Exception:
            # Do not assert that an uncertain commit failed, or start a new
            # request. Other independently queued work can still proceed.
            results.append(
                dict(
                    request_id=request,
                    state="unconfirmed",
                    error_code="enrichment_processing_unconfirmed",
                )
            )
    return results


def replay_request(bundle_root, request_id):
    """Only replay a previously claimed immutable bundle; never download or reclaim."""
    request_id = identifier(request_id)
    with closing(connect()) as conn, conn, conn.cursor() as cur:
        scope, cve = request_scope(cur, request_id)
        cur.execute(
            "SELECT execution_id::text FROM evidence_pipeline.enrichment_runs WHERE request_id=%s",
            (request_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise ValueError("Replay requires a previously claimed enrichment request")
    snapshot = prepare(
        scope,
        row[0],
        _root(bundle_root, create=False) / request_id,
        cve=cve,
        replay_only=True,
    )
    ingest_public(snapshot)
    return status(request_id)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    discovery = sub.add_parser("discover")
    discovery.add_argument("--finding-attempt", required=True)
    discovery.add_argument(
        "--source", choices=list(SOURCES), action="append", required=True
    )
    discovery.add_argument("--limit", type=int, default=100)
    remaining = sub.add_parser("discover-remaining")
    remaining.add_argument("--origin", required=True, choices=["synthetic", "public"])
    remaining.add_argument(
        "--source", choices=list(SOURCES), action="append", required=True
    )
    remaining.add_argument("--limit", type=int, default=100)
    process = sub.add_parser("process")
    process.add_argument("--bundle-root", required=True)
    process.add_argument("--limit", type=int, default=10)
    process.add_argument("--allow-network", action="store_true")
    process.add_argument("--source", choices=list(SOURCES), action="append")
    process.add_argument(
        "--synthetic-input", action="append", default=[], metavar="REQUEST_ID=FILE"
    )
    replay = sub.add_parser("replay")
    replay.add_argument("--bundle-root", required=True)
    replay.add_argument("--request-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            result = discover_attempt(
                args.finding_attempt, sources=args.source, limit=args.limit
            )
        elif args.command == "discover-remaining":
            result = continue_discovery(
                origin=args.origin, sources=args.source, limit=args.limit
            )
        elif args.command == "replay":
            result = replay_request(args.bundle_root, args.request_id)
        else:
            fixtures = {}

            if len(args.synthetic_input) > 100:
                raise ValueError("Too many synthetic fixtures")
            for item in args.synthetic_input:
                key, path = item.split("=", 1)
                key = identifier(key)
                if key in fixtures:
                    raise ValueError("Duplicate synthetic request")
                with Path(path).open("rb") as stream:
                    payload = stream.read()

                fixtures[key] = payload
            result = process_pending(
                args.bundle_root,
                limit=args.limit,
                allow_network=args.allow_network,
                synthetic_inputs=fixtures,
                sources=args.source,
            )
        print(json.dumps(result, sort_keys=True))
        states = (
            [item.get("state") for item in result if isinstance(item, dict)]
            if isinstance(result, list)
            else [result.get("state")]
        )
        if any(
            state in {"unconfirmed", "invalid", "failed", "unavailable"}
            for state in states
        ):
            raise SystemExit(2)
    except Exception:
        raise SystemExit(
            "Enrichment did not confirm completion. Preserve existing request IDs and bundles; inspect request status before explicit offline replay."
        ) from None


if __name__ == "__main__":
    main()
