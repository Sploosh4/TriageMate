"""Explicit source registration and offline device ingestion for the local workspace."""

import argparse
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import uuid4

from standalone.evidence_pipeline.persistence.authority import authorize_connection
from .contracts import Snapshot, SourceScope, identifier
from backend.database.schema import verify as verify_schema
from standalone.evidence_pipeline.parsing.devices import normalize_devices
from standalone.evidence_pipeline.persistence.exposure_store import persist_exposure
from standalone.evidence_pipeline.parsing.public_snapshot import PARSERS
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.public_store import persist_public
from .runtime import connect, local_database
from standalone.evidence_pipeline.persistence.store import (
    persist_devices,
    source_connection,
    ReplayConflict,
)


def load_scope(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate scope field")
            result[key] = value
        return result

    with Path(path).open("rb") as stream:
        raw = stream.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("Scope file exceeds 16KB")
    fields = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(fields, dict):
        raise ValueError("Scope must be an object")
    return SourceScope(**fields)


def register(scope, device_connection_id=None, baseline_connection_id=None):
    if scope.input_kind in ("vulnerability_baseline", "vulnerability_events"):
        from .assessment_commands import register as register_assessment

        return register_assessment(scope, device_connection_id, baseline_connection_id)
    if baseline_connection_id is not None:
        raise ValueError("Baseline binding is only for assessment sources")
    if scope.input_kind == "recommendations":
        from .recommendation_commands import register as register_recommendations

        return register_recommendations(scope, device_connection_id)
    catalogue = (scope.source, scope.input_kind) == (
        "Defender",
        "vulnerability_catalogue",
    )
    exposure = device_connection_id is not None
    from standalone.evidence_pipeline.parsing.advisory_feeds import (
        SOURCES as ADVISORY_SOURCES,
        validate_scope,
    )

    if (scope.source, scope.input_kind) in ADVISORY_SOURCES:
        validate_scope(scope)
    public_input = (scope.source, scope.input_kind) in PARSERS
    if public_input and (exposure or scope.tenant_id is not None):
        raise ValueError("Public input cannot bind a Microsoft device or tenant")
    if exposure:
        device_connection_id = identifier(device_connection_id)
        if (scope.source, scope.input_kind) not in (
            ("Intune", "software"),
            ("Defender", "findings"),
            ("Defender", "missing_patches"),
            ("Defender", "antivirus"),
            ("Intune", "update_status"),
        ):
            raise ValueError("Unsupported exposure input")
    elif (
        not public_input
        and not catalogue
        and (
            scope.source not in ("Entra", "Intune", "Defender")
            or scope.input_kind != "devices"
        )
    ):
        raise ValueError("This registration command supports device inputs only")
    if (
        scope.origin != "synthetic"
        and not (public_input and scope.origin == "public")
        and not (not public_input and scope.origin == "lab")
    ):
        raise ValueError("Unsupported source origin")
    now = datetime.now(timezone.utc)
    envelope = Snapshot(scope, str(uuid4()), now, now, "success", True, b"[]")
    with closing(local_database().connect()) as conn, conn, conn.cursor() as cursor:
        verify_schema(cursor)
        # Registration and device writes share the tenant/source identity lock.
        # Take it before checking absence so competing workers cannot both enrol.
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        cursor.execute(
            "SELECT origin FROM evidence_pipeline.authorized_connections WHERE connection_id=%s",
            (scope.connection_id,),
        )
        existing = cursor.fetchone()
        if existing:
            if existing != (scope.origin,):
                raise ReplayConflict("Registered origin differs")
            source_connection(cursor, envelope)  # verifies all immutable scope fields
            if exposure:
                cursor.execute(
                    "SELECT device_connection_id::text FROM evidence_pipeline.input_device_scopes WHERE input_connection_id=%s",
                    (scope.connection_id,),
                )
                if cursor.fetchone() != (device_connection_id,):
                    raise ReplayConflict("Existing exposure binding differs")
            return False
        authorize_connection(cursor, envelope)
        if exposure:
            cursor.execute(
                "INSERT INTO evidence_pipeline.input_device_scopes VALUES(%s,%s)",
                (scope.connection_id, device_connection_id),
            )
    return True


def ingest(snapshot):
    if snapshot.complete:
        try:
            normalize_devices(snapshot)
        except ValueError:
            snapshot = replace(
                snapshot,
                outcome="failure",
                complete=False,
                error_code="invalid_source_records",
            )
    # A return from persist_devices means staged, not durable. This context must
    # exit successfully before returning a result to the operator.
    with closing(connect()) as conn, conn:
        result = persist_devices(conn, snapshot)
    return result


def ingest_catalogue(snapshot):
    from standalone.evidence_pipeline.persistence.catalogue_store import (
        persist_catalogue,
    )

    if snapshot.complete:
        from standalone.evidence_pipeline.parsing.vulnerability_catalogue import (
            normalize_catalogue,
        )

        try:
            normalize_catalogue(snapshot)
        except ValueError:
            snapshot = replace(
                snapshot,
                outcome="failure",
                complete=False,
                error_code="invalid_catalogue_input",
            )
    with closing(connect()) as conn, conn:
        return persist_catalogue(conn, snapshot)


def ingest_exposure(snapshot, device_attempt_id=None, association_payload=None):
    with closing(connect()) as conn, conn:
        try:
            result = persist_exposure(
                conn, snapshot, device_attempt_id, association_payload
            )
        except ReplayConflict:
            raise
        except ValueError:
            if not snapshot.complete:
                raise
            failed = replace(
                snapshot,
                outcome="failure",
                complete=False,
                error_code="invalid_exposure_input",
            )
            result = persist_exposure(conn, failed)
    from .enrichment_commands import after_findings_commit

    return after_findings_commit(snapshot, result)


def ingest_public(snapshot):
    # Transaction context commits before a successful result reaches the caller.
    with closing(connect()) as conn, conn:
        result = persist_public(conn, snapshot)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register")
    reg.add_argument("--scope", required=True)
    reg.add_argument("--device-connection")
    reg.add_argument("--baseline-connection")
    imp = sub.add_parser("import-devices")
    pub = sub.add_parser("import-public")
    cat = sub.add_parser("import-catalogue")
    recommendations = sub.add_parser("import-recommendations")
    recommendations.add_argument("--device-attempt", required=True)
    recommendations.add_argument("--associations")
    assessment = sub.add_parser("import-assessment")
    assessment.add_argument("--device-attempt", required=True)
    assessment.add_argument("--predecessor")
    assessment.add_argument("--since")
    exp = sub.add_parser("import-exposure")
    exp.add_argument("--device-attempt")
    exp.add_argument("--associations")
    for command in (imp, exp, pub, cat, assessment, recommendations):
        command.add_argument("--scope", required=True)
        command.add_argument("--input", required=True)
        command.add_argument("--execution-id", required=True)
        command.add_argument("--started-at", required=True)
        command.add_argument("--finished-at", required=True)
        command.add_argument(
            "--outcome", choices=["success", "partial", "failure"], default="success"
        )
        command.add_argument("--error-code")
    args = parser.parse_args(argv)
    try:
        scope = load_scope(args.scope)
        if args.command == "register":
            print(
                "Source registered."
                if register(scope, args.device_connection, args.baseline_connection)
                else "Source registration verified; unchanged."
            )
            return
        with Path(args.input).open("rb") as stream:
            payload = stream.read()
        snapshot_type = PublicSnapshot if args.command == "import-public" else Snapshot
        snapshot = snapshot_type(
            scope,
            args.execution_id,
            datetime.fromisoformat(args.started_at),
            datetime.fromisoformat(args.finished_at),
            args.outcome if args.outcome != "success" else "failure",
            False,
            payload,
            args.error_code,
        )
        if args.outcome == "success":
            try:
                snapshot = replace(snapshot, outcome="success", complete=True)
            except ValueError:
                if args.error_code is not None:
                    raise
                snapshot = replace(snapshot, error_code="invalid_source_payload")
        if args.command == "import-public":
            result = ingest_public(snapshot)
        elif args.command == "import-recommendations":
            from .recommendation_commands import ingest as ingest_recommendations

            associated = None
            if args.associations:
                with Path(args.associations).open("rb") as stream:
                    associated = stream.read()
            result = ingest_recommendations(snapshot, args.device_attempt, associated)
        elif args.command == "import-assessment":
            from .assessment_commands import ingest as ingest_assessment

            result = ingest_assessment(
                snapshot,
                args.device_attempt,
                args.predecessor,
                datetime.fromisoformat(args.since) if args.since else None,
            )
        elif args.command == "import-catalogue":
            result = ingest_catalogue(snapshot)
        elif args.command == "import-exposure":
            related = None
            if args.associations:
                with Path(args.associations).open("rb") as stream:
                    related = stream.read()
            result = ingest_exposure(snapshot, args.device_attempt, related)
        else:
            result = ingest(snapshot)
        print(json.dumps(result, sort_keys=True))
        # A durably recorded failure is useful evidence, but it is not a
        # successful collection. Preserve the receipt on stdout for automation
        # while returning a distinct unsuccessful collection status.
        if result["outcome"] != "success":
            raise SystemExit(2)
    except (ValueError, TypeError) as exc:
        # Validation text never includes credential values or raw source records.
        if isinstance(exc, ReplayConflict):
            raise SystemExit(
                "Import rejected: execution or source scope conflicts with existing evidence."
            ) from None
        raise SystemExit(
            "Invalid input or unsupported source configuration; no successful import reported."
        ) from None
    except Exception:
        raise SystemExit(
            "Database import did not confirm success. Preserve the execution ID and retry the same input after checking local configuration."
        ) from None


if __name__ == "__main__":
    main()
