"""Explicit offline EPSS importer. Fixed role/database; no arbitrary SQL interface."""

import argparse
import json
from pathlib import Path
import uuid

import psycopg2
from standalone.synthetic_epss import parse_payload, ValidationError
from backend.database.target import load_target
from backend.database.connections import connect_epss_importer

TARGET = load_target()
CONFIG = TARGET.credential_directory / "epss-importer.json"


class OutcomeUnknown(RuntimeError):
    """Do not report success or a persisted failure without stored-state confirmation."""


def connect():
    return connect_epss_importer(TARGET, CONFIG)


def _call(function, execution, raw):
    conn = connect()
    try:
        with conn.cursor() as cur:
            # Function selected only by internal callers, never a CLI/user argument.
            if function == "submit":
                cur.execute(
                    "SELECT epss_import.submit(%s::uuid,%s::bytea)",
                    (str(execution), raw),
                )
            else:
                cur.execute(
                    "SELECT epss_import.resolve(%s::uuid,%s::bytea)",
                    (str(execution), raw),
                )
            result = cur.fetchone()[0]
        conn.commit()
        return result
    finally:
        conn.close()


def import_payload(execution, raw):
    execution = uuid.UUID(str(execution))
    # Reuse the accepted pure parser. Invalid bytes still reach the independently
    # validating database function, which records the failed attempt atomically.
    try:
        parse_payload(raw)
    except ValidationError:
        pass
    try:
        return _call("submit", execution, raw)
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        try:
            recorded = _call("resolve", execution, raw)
            if recorded is not None:
                return recorded
            # Resolver waited for the source lock: the previous transaction ended
            # without a committed outcome. Retry the same execution, never replace it.
            return _call("submit", execution, raw)
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as error:
            raise OutcomeUnknown(
                "Import outcome could not be confirmed. Retry the same execution ID and exact file; no replacement failure was recorded."
            ) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--execution-id", required=True, type=uuid.UUID)
    args = parser.parse_args()
    try:
        result = import_payload(args.execution_id, args.fixture.read_bytes())
        print(json.dumps(result, sort_keys=True))
        return 0 if result["outcome"] == "success" else 1
    except (OSError, ValueError, psycopg2.Error, OutcomeUnknown) as error:
        message = (
            str(error)
            if isinstance(error, OutcomeUnknown)
            else "Import rejected or storage unavailable; do not assume a persisted outcome."
        )
        print(message)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
