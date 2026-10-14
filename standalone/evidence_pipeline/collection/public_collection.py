"""Explicit public collection with local immutable retry bundles; no scheduler.

The bundle persists before database ingestion. Retry the same path/execution ID
following an uncertain commit; a new collection requires a new ID and path.
"""

import argparse
from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from standalone.evidence_pipeline.commands import ingest_public, load_scope
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.public_snapshot import (
    PARSERS,
    PublicSnapshot,
)
from standalone.evidence_pipeline.file_payload import FilePayload

from standalone.evidence_pipeline.collection.public_transport import (
    PublicDownload,
    PublicHTTPError,
    download,
    endpoint,
)
from standalone.evidence_pipeline.collection.public_pacing import paced

STREAMED_SOURCES = frozenset(
    {("Debian", "tracker"), ("MSRC", "security_updates"), ("FIRST", "epss")}
)


def _write(path, payload):
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        if isinstance(payload, FilePayload):
            with payload.open() as source:
                while chunk := source.read(65536):
                    stream.write(chunk)
        else:
            stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def prepare(
    scope,
    execution_id,
    bundle,
    *,
    cve=None,
    month=None,
    score_date=None,
    advisory_id=None,
    repository_commit=None,
    repository_path=None,
    vendor_path=None,
    synthetic_payload=None,
    replay_only=False,
):
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection(scope.source, score_date=score_date)
    execution_id = identifier(execution_id)

    if type(replay_only) is not bool or (
        synthetic_payload is not None
        and (
            not isinstance(synthetic_payload, (bytes, FilePayload))
            or scope.origin != "synthetic"
        )
    ):
        raise ValueError("Synthetic payload requires a bounded synthetic source")
    if (
        isinstance(synthetic_payload, FilePayload)
        and (
            scope.source,
            scope.input_kind,
        )
        not in STREAMED_SOURCES
    ):
        raise ValueError("Source does not yet support streamed synthetic files")
    record_input = (scope.source, scope.input_kind) in {
        ("CVE", "records"),
        ("CISA", "vulnrichment"),
    }
    route = (
        {"input_kind": scope.input_kind}
        if record_input
        or scope.source
        in {"OSV", "GitHub", "Exploit-DB", "CTID", "MITRE ATT&CK", "Ubuntu", "Red Hat"}
        else {}
    )
    if score_date is not None:
        route["score_date"] = score_date
    if vendor_path is not None:
        route["vendor_path"] = vendor_path
    if advisory_id is not None:
        route["advisory_id"] = advisory_id
    if repository_commit is not None or repository_path is not None:
        route.update(
            repository_commit=repository_commit, repository_path=repository_path
        )
    from standalone.evidence_pipeline.parsing.advisory_feeds import (
        SOURCES as ADVISORY_SOURCES,
        validate_scope,
    )

    if (scope.source, scope.input_kind) in ADVISORY_SOURCES:
        validate_scope(scope)
        if any(
            value is not None
            for value in (
                cve,
                month,
                score_date,
                advisory_id,
                repository_commit,
                repository_path,
                vendor_path,
            )
        ):
            raise ValueError(
                "Synthetic vendor advisory uses only its validated scope reference"
            )
        url = scope.scope_reference
    else:
        url = endpoint(scope.source, cve, month=month, **route)
    if (
        (scope.source, scope.input_kind) not in PARSERS
        or (scope.input_kind == "security_updates") != (month is not None)
        or not (
            scope.origin == "public"
            or (
                scope.origin == "synthetic"
                and (synthetic_payload is not None or replay_only)
            )
        )
        or scope.tenant_id is not None
        or scope.scope_reference != url
    ):
        raise ValueError(
            "Collection requires a public scope matching the fixed source endpoint"
        )
    bundle = Path(bundle)
    if bundle.is_symlink():
        raise ValueError("Retry bundle cannot be a symlink")
    with ExitStack() as stack:
        if scope.origin == "public" and not replay_only and not bundle.exists():
            stack.enter_context(paced(scope.source))
        created = False
        if replay_only:
            if not bundle.is_dir():
                raise ValueError("Replay requires an existing durable bundle")
        else:
            try:
                bundle.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
        if created:
            started = datetime.now(timezone.utc)
            metadata = dict(
                scope=asdict(scope),
                execution_id=execution_id,
                started_at=started.isoformat(),
                request_url=url,
            )
            try:
                if month is not None:
                    route["month"] = month
                if synthetic_payload is not None:
                    result = PublicDownload(
                        url, started, started, synthetic_payload, synthetic_payload
                    )
                else:
                    if (scope.source, scope.input_kind) in ADVISORY_SOURCES:
                        from standalone.evidence_pipeline.collection.public_transport import (
                            download_vendor,
                        )

                        result = download_vendor(
                            scope,
                            **(
                                {"save_to": bundle / "wire.bin"}
                                if (scope.source, scope.input_kind)
                                == ("Debian", "tracker")
                                else {}
                            ),
                        )
                    else:
                        result = download(
                            scope.source,
                            cve=cve,
                            **route,
                            **(
                                {"save_to": bundle / "wire.bin"}
                                if (scope.source, scope.input_kind) in STREAMED_SOURCES
                                else {}
                            ),
                        )
                payload = result.payload
                metadata.update(
                    finished_at=result.finished_at.isoformat(),
                    resolved_url=result.url,
                    wire_fingerprint=result.wire_fingerprint,
                )
                if (
                    not isinstance(result.wire, FilePayload)
                    or result.wire.path != (bundle / "wire.bin").resolve()
                ):
                    _write(bundle / "wire.bin", result.wire)
                del result
                error = None
            except ValueError as exc:
                payload = b""
                error = (
                    exc.code
                    if isinstance(exc, PublicHTTPError)
                    else "public_transport_failed"
                )
                metadata.update(
                    finished_at=datetime.now(timezone.utc).isoformat(),
                    resolved_url=None,
                    wire_fingerprint=None,
                )
            metadata["payload_fingerprint"] = (
                payload.fingerprint
                if isinstance(payload, FilePayload)
                else hashlib.sha256(payload).hexdigest()
            )
            if (
                not isinstance(payload, FilePayload)
                or payload.path != (bundle / "payload.bin").resolve()
            ):
                _write(bundle / "payload.bin", payload)
            if (scope.source, scope.input_kind) in STREAMED_SOURCES:
                payload = FilePayload(
                    (bundle / "payload.bin").resolve(), metadata["payload_fingerprint"]
                )
            if error is None:
                try:
                    checked = PublicSnapshot(
                        scope,
                        execution_id,
                        started,
                        datetime.fromisoformat(metadata["finished_at"]),
                        "success",
                        True,
                        payload,
                    )
                    if cve is not None and any(
                        record.cve_id != cve for record in checked.records()
                    ):
                        raise ValueError("Public response contains a different CVE")
                    if advisory_id is not None and any(
                        record.advisory_id != advisory_id
                        for record in checked.records()
                    ):
                        raise ValueError(
                            "Public response contains a different advisory"
                        )
                except ValueError:
                    error = "invalid_public_payload"
                checked = None
            metadata.update(error_code=error)
            _write(
                bundle / "receipt.json", json.dumps(metadata, sort_keys=True).encode()
            )
            # Directory durability is separate from file content durability.
            descriptor = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            # Replay verification reads the durable payload below. Release the
            # downloaded representation first instead of retaining two copies.
            payload = b""
        if not bundle.is_dir() or bundle.stat().st_mode & 0o077:
            raise ValueError("Retry bundle must be an owner-only directory")
        receipt = bundle / "receipt.json"
        payload_file = bundle / "payload.bin"
        if receipt.is_symlink() or payload_file.is_symlink():
            raise ValueError("Retry files cannot be symlinks")
        with receipt.open("rb") as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError("Oversized retry receipt")
        metadata = json.loads(raw)
        if (
            metadata["scope"] != asdict(scope)
            or metadata["execution_id"] != execution_id
            or metadata["request_url"] != url
        ):
            raise ValueError("Retry bundle belongs to a different source or execution")
        if (scope.source, scope.input_kind) in STREAMED_SOURCES:
            payload = FilePayload(
                payload_file.resolve(), metadata["payload_fingerprint"]
            )
            payload.verify()
            matches = (
                synthetic_payload is None
                or (
                    synthetic_payload.fingerprint
                    if isinstance(synthetic_payload, FilePayload)
                    else hashlib.sha256(synthetic_payload).hexdigest()
                )
                == payload.fingerprint
            )
        else:
            with payload_file.open("rb") as stream:
                payload = stream.read()
            matches = hashlib.sha256(payload).hexdigest() == metadata[
                "payload_fingerprint"
            ] and (synthetic_payload is None or synthetic_payload == payload)
        if not matches:
            raise ValueError("Retry payload differs from its receipt")
        if metadata["wire_fingerprint"] is not None:
            wire_file = bundle / "wire.bin"
            if wire_file.is_symlink():
                raise ValueError("Wire file cannot be a symlink")
            with wire_file.open("rb") as stream:
                wire_fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
            if wire_fingerprint != metadata["wire_fingerprint"]:
                raise ValueError("Retry wire differs from its receipt")
        error = metadata["error_code"]
        return PublicSnapshot(
            scope,
            execution_id,
            datetime.fromisoformat(metadata["started_at"]),
            datetime.fromisoformat(metadata["finished_at"]),
            "failure" if error else "success",
            not bool(error),
            payload,
            error,
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--cve")
    parser.add_argument("--score-date", help="FIRST historical score date, YYYY-MM-DD")
    parser.add_argument("--advisory-id", help="OSV native advisory identifier")
    parser.add_argument(
        "--repository-commit", help="Pinned GitHub advisory database commit"
    )
    parser.add_argument("--repository-path", help="Exact GitHub advisory export path")
    parser.add_argument("--vendor-path", help="Exact Red Hat advisory index path")
    parser.add_argument(
        "--synthetic-input",
        help="Explicit synthetic response file; never sent to a source",
    )
    parser.add_argument(
        "--replay-only",
        action="store_true",
        help="Read an existing bundle without network access",
    )
    parser.add_argument("--month", help="MSRC CVRF publication month, e.g. 2026-Sep")
    parser.add_argument(
        "--upstream-output",
        help="Follow Ubuntu upstream links after import, saving child bundles here",
    )
    parser.add_argument("--upstream-limit", type=int, default=10)
    parser.add_argument("--upstream-max-nodes", type=int, default=1000)
    args = parser.parse_args(argv)
    try:
        scope = load_scope(args.scope)
        if args.upstream_output and (
            (scope.source, scope.input_kind) != ("Ubuntu", "advisories")
            or not 1 <= args.upstream_limit <= 100
            or not 1 <= args.upstream_max_nodes <= 10000
        ):
            raise ValueError("Upstream traversal requires Ubuntu and bounded limits")

        synthetic_payload = None
        if args.synthetic_input:
            with Path(args.synthetic_input).open("rb") as stream:
                synthetic_payload = stream.read()
        snapshot = prepare(
            scope,
            args.execution_id,
            args.bundle,
            cve=args.cve,
            month=args.month,
            score_date=args.score_date,
            advisory_id=args.advisory_id,
            repository_commit=args.repository_commit,
            repository_path=args.repository_path,
            vendor_path=args.vendor_path,
            synthetic_payload=synthetic_payload,
            replay_only=args.replay_only,
        )
        result = ingest_public(snapshot)
        upstream_incomplete = False
        if args.upstream_output and result["outcome"] == "success":
            from standalone.evidence_pipeline.collection.ubuntu_upstream import (
                collect_tree,
            )

            result["upstream"] = collect_tree(
                snapshot,
                args.upstream_output,
                limit=args.upstream_limit,
                max_nodes=args.upstream_max_nodes,
                allow_network=scope.origin == "public" and not args.replay_only,
                replay_only=args.replay_only,
                import_records=True,
            )
            upstream = result["upstream"]
            upstream_incomplete = bool(
                upstream["traversal_limited"]
                or upstream["unresolved"]
                or any(row["outcome"] != "success" for row in upstream["outcomes"])
            )
        print(json.dumps(result, sort_keys=True))
        if result["outcome"] != "success" or upstream_incomplete:
            raise SystemExit(2)
    except Exception:
        raise SystemExit(
            "Collection/import did not confirm success. Preserve the bundle and execution ID; inspect local configuration before retrying."
        ) from None


if __name__ == "__main__":
    main()
