"""Bounded Catalog search-to-detail collection with immutable local continuation."""

from datetime import datetime, timezone
import hashlib
import json
import os
import stat
from pathlib import Path

from standalone.evidence_pipeline.commands import register, ingest_public
from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.osv_query_collection import _sync
from standalone.evidence_pipeline.collection.public_collection import _write, prepare
from standalone.evidence_pipeline.collection.public_transport import _download_url
from standalone.evidence_pipeline.parsing.catalog_discovery import (
    search_url,
    parse_search,
)


def catalog_scope(origin, url):
    return SourceScope(
        stable_id("catalog-discovered-source", origin, url),
        "Microsoft Update Catalog",
        "updates",
        url,
        origin,
        "Public Microsoft Update Catalog metadata; https://www.catalog.update.microsoft.com/Faq.aspx; no update packages"
        if origin == "public"
        else "TriageMate generated synthetic Catalog discovery/advisory fixtures",
    )


def collect(
    output,
    *,
    origin,
    kb,
    execution_id,
    limit=10,
    after=None,
    synthetic_index=None,
    synthetic_payloads=None,
    synthetic_pages=None,
    page_limit=10,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    execution_id = identifier(execution_id)
    index_url = search_url(kb)

    def parse_index(payload):
        return parse_search(payload, kb=kb)

    if (
        origin not in {"public", "synthetic"}
        or type(limit) is not int
        or not 1 <= limit <= 100
        or type(page_limit) is not int
        or not 1 <= page_limit <= 100
    ):
        raise ValueError("Invalid Catalog collection origin or batch limit")
    if any(
        type(flag) is not bool for flag in (allow_network, replay_only, import_records)
    ) or (allow_network and (origin != "public" or replay_only)):
        raise ValueError("Invalid Catalog collection mode")
    if (
        synthetic_index is not None
        or synthetic_payloads is not None
        or synthetic_pages is not None
    ) and origin != "synthetic":
        raise ValueError("Synthetic input cannot be relabelled public")
    if synthetic_payloads is not None and not isinstance(synthetic_payloads, dict):
        raise ValueError("Advisory fixtures must map index paths to bytes")
    root = Path(output)
    if root.is_symlink():
        raise ValueError("Collection output cannot be a symlink")
    request = dict(origin=origin, execution_id=execution_id, source_url=index_url)
    if not root.exists():
        if (
            replay_only
            or (origin == "public" and not allow_network)
            or (origin == "synthetic" and synthetic_index is None)
        ):
            raise ValueError("Fresh collection requires explicit source input")
        if synthetic_index is not None:
            parse_index(synthetic_index)
        root.mkdir(mode=0o700)
        _sync(root.parent)
        _write(root / "request.json", json.dumps(request, sort_keys=True).encode())
        _sync(root)
        payload = (
            synthetic_index
            if origin == "synthetic"
            else _download_url(index_url).payload
        )
        _write(root / "search.html", payload)
        # Save response bytes before parsing so invalid responses remain inspectable.
        _write(
            root / "receipt.json",
            json.dumps(
                dict(
                    request,
                    fingerprint=hashlib.sha256(payload).hexdigest(),
                    collected_at=datetime.now(timezone.utc).isoformat(),
                ),
                sort_keys=True,
            ).encode(),
        )
        _sync(root)
    if (
        not root.is_dir()
        or root.stat().st_mode & 0o077
        or root.stat().st_uid != os.getuid()
    ):
        raise ValueError("Collection output requires an owner-only directory")

    def read(name, maximum=None):
        path = root / name
        if (
            not stat.S_ISREG(path.lstat().st_mode)
            or path.is_symlink()
            or path.stat().st_mode & 0o077
            or path.stat().st_uid != os.getuid()
        ):
            raise ValueError("Unsafe collection bundle file")
        with path.open("rb") as stream:
            result = stream.read() if maximum is None else stream.read(maximum + 1)
        if maximum is not None and len(result) > maximum:
            raise ValueError("Oversized collection bundle file")
        return result

    if json.loads(read("request.json", 16384)) != request:
        raise ValueError("Collection bundle belongs to another execution or origin")
    receipt = json.loads(read("receipt.json", 16384))
    payload = read("search.html")
    collected_at = receipt.get("collected_at")
    if (
        not isinstance(collected_at, str)
        or datetime.fromisoformat(collected_at).utcoffset() is None
    ):
        raise ValueError("Search receipt requires an explicit collection date")
    if receipt != dict(
        request,
        fingerprint=hashlib.sha256(payload).hexdigest(),
        collected_at=collected_at,
    ) or (synthetic_index is not None and synthetic_index != payload):
        raise ValueError("Collection index differs from receipt")
    from standalone.evidence_pipeline.collection.catalog_pages import saved_pages

    search, search_digest = saved_pages(
        root,
        request=request,
        kb=kb,
        first_payload=payload,
        download=_download_url if allow_network and not replay_only else None,
        synthetic_pages=None if replay_only else synthetic_pages,
        page_limit=page_limit,
    )
    files = search.hits
    paths = [file.update_id for file in files]
    if after is not None and after not in paths:
        raise ValueError("Continuation must name a saved index path")
    start = paths.index(after) + 1 if after is not None else 0
    outcomes = []
    selected = files[start : start + limit]
    for file in selected:
        scope = catalog_scope(origin, file.url)
        attempt = stable_id(
            "catalog-discovered-attempt", execution_id, scope.connection_id
        )
        bundle = root / attempt
        fixture = (synthetic_payloads or {}).get(file.update_id)
        if not bundle.exists() and (
            replay_only
            or (origin == "public" and not allow_network)
            or (origin == "synthetic" and fixture is None)
        ):
            outcomes.append(
                dict(path=file.update_id, outcome="pending", database_imported=False)
            )
            continue
        snapshot = prepare(
            scope,
            attempt,
            bundle,
            synthetic_payload=fixture,
            replay_only=bundle.exists(),
        )
        result = dict(
            path=file.update_id,
            outcome="success" if snapshot.complete else snapshot.error_code,
            execution_id=attempt,
            database_imported=False,
        )
        if import_records:
            register(scope)
            imported = ingest_public(snapshot)
            result.update(database_imported=True, replayed=imported["replayed"])
        outcomes.append(result)
    remaining = max(0, len(files) - start - len(selected))
    return dict(
        source_url=index_url,
        collected_at=collected_at,
        search_fingerprint=search_digest,
        search_complete=search.complete,
        total_search_results=search.total,
        undiscovered_results=search.total - len(files),
        outcomes=outcomes,
        remaining=remaining,
        next_after=selected[-1].update_id if selected and remaining else None,
    )


def main(argv=None):
    import argparse
    import sys
    import psycopg2
    from standalone.evidence_pipeline.parsing.update_catalog import update_id

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kb", required=True)
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
                update_id(path)
                if not isinstance(filename, str):
                    raise ValueError("Fixture filename must be text")
                with (manifest.parent / filename).open("rb") as stream:
                    fixtures[path] = stream.read()
        result = collect(
            args.output,
            origin=args.origin,
            kb=args.kb,
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
            0
            if result["search_complete"]
            and result["remaining"] == 0
            and all(row["outcome"] == "success" for row in result["outcomes"])
            else 1
        )
    except (ValueError, OSError, TypeError, psycopg2.Error):
        print(
            "Catalog batch did not confirm completion. Preserve its output directory and execution ID before investigating or replaying.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
