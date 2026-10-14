"""Collect Catalog searches selected from pinned local missing-patch evidence.

The private manifest is written before network access. Public child bundles contain
only public Catalog evidence; local source/device scope bindings stay in this
owner-only parent. Scheduling activation and active-job proof belong to the caller.
"""

from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path

from standalone.evidence_pipeline.collection.catalog_targets import select_targets
from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.runtime import connect
from standalone.evidence_pipeline.collection.snapshot_bundle import (
    _private_directory,
    _read,
    _write,
    _sync_directory,
)
from .catalog_worker import collect_batch
from .catalog_proof import CatalogProof


def collect_targets(
    root,
    *,
    run_id,
    snapshots,
    origin,
    allow_network=False,
    fixtures=None,
    target_limit=100,
    record_limit=10,
    pass_limit=10,
):
    run_id = identifier(run_id)
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("Catalog target storage must be absolute")
    _private_directory(root)
    if type(allow_network) is not bool or origin not in {"synthetic", "lab"}:
        raise ValueError("Invalid target collection authority")
    if origin == "synthetic":
        if allow_network or not isinstance(fixtures, dict):
            raise ValueError("Synthetic target collection requires offline fixtures")
    elif not allow_network or fixtures is not None:
        raise ValueError(
            "Lab-derived public searches require explicit network authority"
        )
    for value in (record_limit, pass_limit):
        if type(value) is not int or not 1 <= value <= 100:
            raise ValueError("Invalid Catalog request budget")
    with closing(connect()) as conn, conn, conn.cursor() as cursor:
        selection = select_targets(
            cursor, snapshots, origin=origin, maximum=target_limit
        )
    if not selection.complete:
        raise ValueError(
            "Missing-patch references remain unresolved; target selection is incomplete"
        )
    if fixtures is not None and set(fixtures) != set(selection.kbs):
        raise ValueError("Synthetic fixture membership differs from selected KBs")
    child_origin = "synthetic" if origin == "synthetic" else "public"
    manifest = json.loads(
        json.dumps(
            dict(
                run_id=run_id,
                origin=origin,
                selection=asdict(selection),
                target_limit=target_limit,
                record_limit=record_limit,
                pass_limit=pass_limit,
            )
        )
    )
    bundle = root / run_id
    if not bundle.exists():
        bundle.mkdir(mode=0o700)
        _sync_directory(root)
        _write(bundle / "targets.json", json.dumps(manifest, sort_keys=True).encode())
        (bundle / "searches").mkdir(mode=0o700)
        _sync_directory(bundle)
    _private_directory(bundle)
    if json.loads(_read(bundle / "targets.json")) != manifest:
        raise ValueError("Catalog targets or execution settings changed")
    searches = bundle / "searches"
    _private_directory(searches)
    outcomes = []
    for kb in selection.kbs:
        child_run = stable_id("catalog-target-search", run_id, kb)
        fixture = None if fixtures is None else fixtures[kb]
        result = collect_batch(
            searches,
            origin=child_origin,
            kb=kb,
            execution_id=child_run,
            allow_network=allow_network,
            synthetic_index=None if fixture is None else fixture[0],
            synthetic_payloads=None if fixture is None else fixture[1],
            synthetic_pages=fixture[2]
            if fixture is not None and len(fixture) == 3
            else None,
            record_limit=record_limit,
            pass_limit=pass_limit,
        )
        verified = False
        if result.reason == "finished":
            proof = CatalogProof(kb)
            child, _, entries = proof.saved_index(searches, child_origin, child_run)
            with closing(connect()) as conn, conn, conn.cursor() as cursor:
                verified = proof.imports_committed(
                    cursor, child, child_origin, child_run, entries
                )
        outcomes.append(
            dict(kb=kb, run_id=child_run, reason=result.reason, verified=verified)
        )
        if not verified:
            break
    return dict(
        selection=manifest["selection"],
        outcomes=outcomes,
        complete=len(outcomes) == len(selection.kbs)
        and all(row["verified"] for row in outcomes),
    )
