"""Verified collection health and separate MSRC publication-age evidence."""

from contextlib import closing
from types import SimpleNamespace

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.collection.msrc_discovered_collection import (
    source_scope,
)
from standalone.evidence_pipeline.collection.public_collection import prepare
from .msrc_proof import MsrcProof
from .provider_age import provider_clock
from .proof_cache import tree_state
from . import store


def read_clock(cursor, key, recipe, *, cache=None):
    result = dict(
        attempt_id=None,
        collected_at=None,
        provider_time=None,
        basis=None,
        precision=None,
        health_time=None,
        health_basis="sealed_collection_journal",
    )
    saved = store.load(cursor, key)
    if saved is None:
        return result
    definition = saved[1].definitions.get(recipe.scope.connection_id)
    if definition is None:
        return result
    cursor.execute(
        "SELECT event,recorded_at FROM evidence_pipeline.operation_events "
        "WHERE service_key=%s AND event->>'input_id'=%s "
        "AND event->>'kind'='msrc_index' ORDER BY id DESC LIMIT 1",
        (key, recipe.scope.connection_id),
    )
    row = cursor.fetchone()
    if row is None:
        return result
    declaration, sealed_at = row
    run = identifier(declaration.get("run_id"))
    result.update(attempt_id=run, collected_at=sealed_at.isoformat())
    proof = MsrcProof(recipe.starting_month, recipe.retained_ids)
    cache_key = (
        "msrc",
        recipe.scope,
        str(recipe.bundle_root),
        definition.worker_contract,
        recipe.starting_month,
        recipe.retained_ids,
    )
    try:
        storage = tree_state(recipe.bundle_root / run)
    except OSError:
        if cache is not None:
            cache.pop(cache_key, None)
        return result
    identity = (
        run,
        sealed_at,
        storage,
        definition.worker_contract,
        tuple(sorted(declaration.items())),
    )
    if cache is not None and cache.get(cache_key, (None,))[0] == identity:
        return dict(cache[cache_key][1])
    if cache is not None:
        cache.pop(cache_key, None)
    try:
        bundle, digest, entries = proof.saved_index(
            recipe.bundle_root, recipe.scope.origin, run
        )
        with closing(entries):
            job = SimpleNamespace(input_id=recipe.scope.connection_id, run_id=run)
            if declaration != proof.event(
                job, recipe.scope.origin, definition.worker_contract, digest
            ) or not proof.imports_committed(
                cursor, bundle, recipe.scope.origin, run, entries
            ):
                return result
        # Proof consumes its iterator. Reopen the same pinned index; never use
        # current child snapshots or substitute newly discovered publications.
        _, repeated_digest, entries = proof.saved_index(
            recipe.bundle_root, recipe.scope.origin, run
        )
        with closing(entries):
            if repeated_digest != digest:
                return result
            oldest = None
            for entry in entries:
                scope = source_scope(recipe.scope.origin, entry)
                attempt = stable_id("msrc-discovered-attempt", run, scope.connection_id)
                snapshot = prepare(
                    scope,
                    attempt,
                    bundle / attempt,
                    month=entry.publication_id,
                    replay_only=True,
                )
                if not snapshot.complete:
                    return result
                clock, _, _ = provider_clock(snapshot.feed())
                if clock is None:
                    # Verified missing publisher clocks remain unknown. This
                    # does not replace the earlier exact full-membership proof.
                    break
                oldest = clock if oldest is None else min(oldest, clock)
            else:
                if oldest is not None:
                    result.update(
                        provider_time=oldest.isoformat(),
                        basis="oldest_document_release",
                        precision="timestamp",
                    )
        # The seal exists only after the complete selected imports. Its scheduler
        # journal clock is a conservative collection-health anchor, never a
        # publisher timestamp or a replacement for per-document provenance.
        if tree_state(recipe.bundle_root / run) != storage:
            result.update(provider_time=None, basis=None, precision=None)
            return result
        result["health_time"] = sealed_at.isoformat()
        if cache is not None:
            cache[cache_key] = (identity, dict(result))
    except (ValueError, OSError):
        pass  # Missing/corrupt bundles remain unknown and are retried next tick.
    return result
