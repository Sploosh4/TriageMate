"""Provider age for exact sealed discovery membership and its document inputs."""

from types import SimpleNamespace

from standalone.evidence_pipeline.collection.catalog_collection import catalog_scope
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.public_collection import prepare
from .catalog_proof import CatalogProof
from .provider_age import provider_clock
from . import store


def read_clock(cursor, key, recipe):
    """No network, partial-search fallback, or substitution of newer child inputs."""
    result = dict(
        attempt_id=None,
        collected_at=None,
        provider_time=None,
        basis=None,
        precision=None,
    )
    if recipe.scope.source == "Microsoft Update Catalog":
        result.update(health_time=None, health_basis="sealed_collection_journal")
    saved = store.load(cursor, key)
    if saved is None:
        return result
    _, state = saved
    definition = state.definitions.get(recipe.scope.connection_id)
    if definition is None:
        return result
    cisco = recipe.scope.source == "Cisco"
    kind = "cisco_rss" if cisco else "catalog_search"
    cursor.execute(
        "SELECT event,recorded_at FROM evidence_pipeline.operation_events "
        "WHERE service_key=%s AND event->>'input_id'=%s "
        "AND event->>'kind'=%s ORDER BY id DESC LIMIT 1",
        (key, recipe.scope.connection_id, kind),
    )
    row = cursor.fetchone()
    if row is None:
        return result
    declaration, sealed_at = row
    run = declaration.get("run_id")
    # A sealed search is recorded only after all exact child imports commit.
    # Retain its identity when verification fails so the monitor reports unknown.
    from standalone.evidence_pipeline.contracts import identifier

    run = identifier(run)
    result.update(attempt_id=run, collected_at=sealed_at.isoformat())
    if cisco:
        from .cisco_proof import CiscoProof
        from standalone.evidence_pipeline.collection.cisco_collection import (
            source_scope,
        )

        proof = CiscoProof()
    else:
        proof = CatalogProof(recipe.kb)
    try:
        bundle, digest, entries = proof.saved_index(
            recipe.bundle_root, recipe.scope.origin, run
        )
        job = SimpleNamespace(input_id=recipe.scope.connection_id, run_id=run)
        if declaration != proof.event(
            job, recipe.scope.origin, definition.worker_contract, digest
        ) or not proof.imports_committed(
            cursor, bundle, recipe.scope.origin, run, entries
        ):
            return result
        if not cisco:
            result["health_time"] = sealed_at.isoformat()
        oldest = None
        for entry in entries:
            scope = (
                source_scope(recipe.scope.origin, entry)
                if cisco
                else catalog_scope(recipe.scope.origin, entry.url)
            )
            attempt = stable_id(
                "cisco-discovered-attempt" if cisco else "catalog-discovered-attempt",
                run,
                scope.connection_id,
            )
            snapshot = prepare(scope, attempt, bundle / attempt, replay_only=True)
            clock, basis, precision = provider_clock(snapshot.feed())
            if clock is None:
                return result
            oldest = clock if oldest is None else min(oldest, clock)
        if oldest is not None:
            result.update(
                provider_time=oldest.isoformat(), basis=basis, precision=precision
            )
    except (ValueError, OSError):
        if "health_time" in result:
            result["health_time"] = None
    return result


def read_target_clock(cursor, key, recipe):
    """Revalidate pinned prerequisites and every search in a sealed target batch."""
    import json
    from standalone.evidence_pipeline.contracts import identifier
    from standalone.evidence_pipeline.collection.snapshot_bundle import _read

    result = dict(
        attempt_id=None,
        collected_at=None,
        provider_time=None,
        basis=None,
        precision=None,
    )
    if recipe.scope.source == "Microsoft Update Catalog":
        result.update(health_time=None, health_basis="sealed_collection_journal")
    saved = store.load(cursor, key)
    if saved is None:
        return result
    _, state = saved
    definition = state.definitions.get(recipe.scope.connection_id)
    if definition is None:
        return result
    cursor.execute(
        "SELECT event,recorded_at FROM evidence_pipeline.operation_events "
        "WHERE service_key=%s AND event->>'input_id'=%s "
        "AND event->>'kind'='catalog_targets' ORDER BY id DESC LIMIT 1",
        (key, recipe.scope.connection_id),
    )
    row = cursor.fetchone()
    if row is None:
        return result
    declaration, recorded_at = row
    run = identifier(declaration.get("run_id"))
    result.update(attempt_id=run, collected_at=recorded_at.isoformat())
    try:
        if definition.worker_contract != recipe.worker_contract or set(
            definition.dependencies
        ) != set(recipe.dependencies):
            return result
        manifest = json.loads(_read(recipe.bundle_root / run / "targets.json"))
        bindings = manifest.get("selection", {}).get("snapshots")
        if (
            not isinstance(bindings, list)
            or len(bindings) != len(recipe.dependencies)
            or any(not isinstance(pair, list) or len(pair) != 2 for pair in bindings)
        ):
            return result
        snapshots = tuple(
            (identifier(scope), identifier(attempt)) for scope, attempt in bindings
        )
        if {scope for scope, _ in snapshots} != set(recipe.dependencies):
            return result
        job = SimpleNamespace(
            input_id=recipe.scope.connection_id,
            run_id=run,
            prerequisite_snapshots=snapshots,
        )
        # evidence() re-selects KBs from these exact database snapshots and checks
        # manifest hash, complete membership and every committed child receipt.
        if recipe.binding().evidence(cursor, job) != declaration:
            return result
        result["health_time"] = recorded_at.isoformat()
        oldest = None
        origin = "synthetic" if recipe.scope.origin == "synthetic" else "public"
        for search in declaration["indexes"]:
            bundle, _, entries = CatalogProof(search["kb"]).saved_index(
                recipe.bundle_root / run / "searches", origin, search["run_id"]
            )
            if not entries:
                return result
            for entry in entries:
                scope = catalog_scope(origin, entry.url)
                attempt = stable_id(
                    "catalog-discovered-attempt", search["run_id"], scope.connection_id
                )
                snapshot = prepare(scope, attempt, bundle / attempt, replay_only=True)
                clock, basis, precision = provider_clock(snapshot.feed())
                if clock is None:
                    return result
                oldest = clock if oldest is None else min(oldest, clock)
        if oldest is not None:
            result.update(
                provider_time=oldest.isoformat(), basis=basis, precision=precision
            )
    except (ValueError, OSError, TypeError, AttributeError):
        # Malformed or missing local manifests do not establish healthy evidence.
        result["health_time"] = None
    return result
