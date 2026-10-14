"""Bounded monthly collection from one immutable MSRC publication index.

Each new execution considers every eligible publication. A previous discovery
index alone never suppresses a child import. Scheduler completion still requires
an exact committed-receipt proof; this collector does not advance a checkpoint.
"""

import json
from pathlib import Path

from standalone.evidence_pipeline.collection import msrc_index_collection
from standalone.evidence_pipeline.commands import register, ingest_public
from standalone.evidence_pipeline.contracts import SourceScope, identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.msrc_publication_selection import (
    select_changed,
)
from standalone.evidence_pipeline.parsing.msrc_publications import period
from standalone.evidence_pipeline.collection.osv_query_collection import _read, _sync
from standalone.evidence_pipeline.collection.public_collection import prepare, _write
from standalone.evidence_pipeline.collection.snapshot_bundle import _private_directory


def source_scope(origin, item):
    return SourceScope(
        stable_id("msrc-discovered-publication", origin, item.url),
        "MSRC",
        "security_updates",
        item.url,
        origin,
        "Microsoft Security Response Center public CVRF; original source notices retained"
        if origin == "public"
        else "TriageMate generated synthetic MSRC publication fixtures",
    )


def collect(
    root,
    *,
    origin,
    execution_id,
    starting_month,
    retained_ids,
    limit=10,
    after=None,
    allow_network=False,
    replay_only=False,
    synthetic_index=None,
    synthetic_payloads=None,
    import_records=False,
    cancelled=lambda: False,
):
    execution_id = identifier(execution_id)
    if (
        origin not in {"public", "synthetic"}
        or any(
            type(v) is not bool for v in (allow_network, replay_only, import_records)
        )
        or (allow_network and (origin != "public" or replay_only))
    ):
        raise ValueError("Invalid MSRC discovery authority")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Invalid MSRC child request budget")
    # Validate the explicit range without writing files or requesting data.
    list(
        select_changed((), (), starting_month=starting_month, retained_ids=retained_ids)
    )
    if after is not None:
        period(after)
    if synthetic_index is not None and (
        origin != "synthetic" or not isinstance(synthetic_index, bytes)
    ):
        raise ValueError("MSRC fixture requires synthetic origin")
    if synthetic_payloads is not None and (
        origin != "synthetic"
        or not isinstance(synthetic_payloads, dict)
        or any(
            not isinstance(k, str) or not isinstance(v, bytes)
            for k, v in synthetic_payloads.items()
        )
    ):
        raise ValueError("MSRC child fixtures require synthetic identities and bytes")
    if cancelled():
        raise ValueError("MSRC discovery cancelled")
    root = Path(root)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("MSRC discovery requires an absolute private bundle")
    declaration = dict(
        origin=origin,
        execution_id=execution_id,
        starting_month=starting_month,
        retained_ids=sorted(retained_ids),
    )
    wire = json.dumps(declaration, sort_keys=True).encode()
    if not root.exists():
        if replay_only or (origin == "public" and not allow_network):
            raise ValueError("Fresh MSRC discovery requires input authority")
        root.mkdir(mode=0o700)
        _write(root / "selection.json", wire)
        _sync(root)
        _sync(root.parent)
    _private_directory(root)
    if _read(root / "selection.json") != wire:
        raise ValueError("MSRC discovery selection differs from saved run")
    index = msrc_index_collection.prepare(
        root / "index",
        execution_id,
        origin=origin,
        allow_network=allow_network,
        replay_only=replay_only,
        synthetic_payload=synthetic_index,
        cancelled=cancelled,
    )
    if not index.complete:
        return dict(
            index_complete=False,
            index_error=index.error_code,
            outcomes=(),
            remaining=None,
            next_after=None,
        )
    selected, remaining, found = [], 0, after is None
    fixture_ids = set(synthetic_payloads or {})
    for item in select_changed(
        index.items(cancelled=cancelled),
        (),
        starting_month=starting_month,
        retained_ids=retained_ids,
        cancelled=cancelled,
    ):
        fixture_ids.discard(item.publication_id)
        if not found:
            found = item.publication_id == after
            continue
        if len(selected) < limit:
            selected.append(item)
        else:
            remaining += 1
    if not found or fixture_ids:
        raise ValueError(
            "MSRC continuation or fixture is outside selected index membership"
        )
    outcomes = []
    for item in selected:
        if cancelled():
            raise ValueError("MSRC discovery cancelled")
        scope = source_scope(origin, item)
        attempt = stable_id(
            "msrc-discovered-attempt", execution_id, scope.connection_id
        )
        bundle = root / attempt
        fixture = (synthetic_payloads or {}).get(item.publication_id)
        if not bundle.exists() and (
            replay_only
            or (origin == "public" and not allow_network)
            or (origin == "synthetic" and fixture is None)
        ):
            outcomes.append(
                dict(
                    native_id=item.publication_id,
                    outcome="pending",
                    database_imported=False,
                )
            )
            continue
        snapshot = prepare(
            scope,
            attempt,
            bundle,
            month=item.publication_id,
            synthetic_payload=fixture,
            replay_only=bundle.exists(),
        )
        result = dict(
            native_id=item.publication_id,
            execution_id=attempt,
            outcome="success" if snapshot.complete else snapshot.error_code,
            database_imported=False,
        )
        if import_records:
            register(scope)
            imported = ingest_public(snapshot)
            result.update(
                database_imported=imported["outcome"] == "success",
                replayed=imported["replayed"],
            )
        outcomes.append(result)
    return dict(
        index_complete=True,
        index_error=None,
        outcomes=tuple(outcomes),
        remaining=remaining,
        next_after=selected[-1].publication_id if selected and remaining else None,
    )
