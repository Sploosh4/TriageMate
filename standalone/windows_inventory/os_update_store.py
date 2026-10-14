"""Atomic, idempotent offline OS evidence import through the existing writer."""

import argparse
import hashlib
import json
from pathlib import Path
from uuid import UUID, uuid5

from backend.database.schema import require_current_version
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.persistence.store import atomic, ReplayConflict

from .contract import DeviceBinding
from .os_update_evidence import canonical, evaluate, MAX_BYTES


def persist(connection, inventory_attempt_id, raw, *, binding, origin):
    if connection.autocommit:
        raise ValueError("OS review requires an explicit transaction")
    inventory_attempt_id = identifier(inventory_attempt_id)
    report = evaluate(raw, binding=binding, origin=origin)
    fingerprint = hashlib.sha256(raw).hexdigest()
    engine = hashlib.sha256(
        Path(__file__).with_name("os_update_evidence.py").read_bytes()
    ).hexdigest()
    review_id = str(uuid5(UUID(inventory_attempt_id), fingerprint + engine))
    with connection.cursor() as cur, atomic(cur):
        cur.execute("SELECT pg_advisory_xact_lock(731904217)")
        require_current_version(cur)
        cur.execute(
            "SELECT inventory_attempt_id::text,input_fingerprint,engine_fingerprint,original_bytes,report FROM evidence_pipeline.windows_os_reviews WHERE id=%s",
            (review_id,),
        )
        previous = cur.fetchone()
        if previous:
            if (
                previous[:3] != (inventory_attempt_id, fingerprint, engine)
                or bytes(previous[3]) != raw
                or previous[4] != report
            ):
                raise ReplayConflict("OS review differs from retained interpretation")
        else:
            cur.execute(
                "INSERT INTO evidence_pipeline.windows_os_reviews(id,inventory_attempt_id,input_fingerprint,engine_fingerprint,original_bytes,report) VALUES(%s,%s,%s,%s,%s,%s::jsonb)",
                (
                    review_id,
                    inventory_attempt_id,
                    fingerprint,
                    engine,
                    raw,
                    canonical(report),
                ),
            )
    return {
        "review_id": review_id,
        "replayed": previous is not None,
        "identity_state": report["identity_state"],
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Requires the current registered database baseline/revision. Legacy "
            "installations need explicit verified adoption; this import command "
            "does not install or migrate databases."
        ),
    )
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--inventory-attempt", required=True)
    parser.add_argument(
        "--binding",
        type=Path,
        required=True,
        help="Independent local DeviceBinding JSON; never credentials",
    )
    parser.add_argument("--origin", choices=("lab", "synthetic"), required=True)
    args = parser.parse_args()
    binding = DeviceBinding(**json.loads(args.binding.read_text()))
    with args.bundle.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    from standalone.evidence_pipeline.runtime import connect

    with connect() as connection:
        result = persist(
            connection, args.inventory_attempt, raw, binding=binding, origin=args.origin
        )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
