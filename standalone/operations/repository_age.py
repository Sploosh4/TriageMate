"""Health of a completed active Git repository collection, with separate dates."""

from psycopg2 import sql

from standalone.evidence_pipeline.verification_spool import streamed_rows
from .proof_cache import tree_state
from . import store
from .provider_age import record_clock
from .repository_proof import published_run

SOURCES = frozenset({"CVE", "CISA", "WA SOC"})
HEALTH_BASIS = "verified_repository_checkpoint"


def read_clock(cursor, key, recipe, *, cache=None):
    """Require scheduler success and exact saved membership; never collect here.

    A failed latest run does not fall back to an older healthy publication. The
    ordinary collection-failure and overdue policies remain independent. WA SOC
    has no validated aggregate publication timestamp; its document dates remain
    available in the original evidence rather than inferred from filenames.
    """
    if recipe.scope.source not in SOURCES or recipe.scope.input_kind != "repository":
        raise ValueError("Unsupported repository collection-health source")
    result = dict(
        attempt_id=None,
        collected_at=None,
        provider_time=None,
        basis=None,
        precision=None,
        health_time=None,
        health_basis=HEALTH_BASIS,
    )
    saved = store.load(cursor, key)
    if saved is None:
        return result
    state = saved[1]
    definition = state.definitions.get(recipe.scope.connection_id)
    observed = state.inputs.get(recipe.scope.connection_id)
    if (
        definition is None
        or observed is None
        or not observed.latest_success
        or observed.latest_snapshot is None
        or observed.last_success_at is None
    ):
        return result
    run, finished = observed.latest_snapshot, observed.last_success_at
    result.update(attempt_id=run, collected_at=finished.isoformat())
    cache_key = (
        "repository",
        key,
        recipe.scope,
        str(recipe.bundle_root),
        definition.worker_contract,
    )
    try:
        storage = tree_state(recipe.bundle_root / run)
    except OSError:
        if cache is not None:
            cache.pop(cache_key, None)
        return result
    identity = (run, finished, storage)
    if cache is not None and cache.get(cache_key, (None,))[0] == identity:
        return dict(cache[cache_key][1])
    if cache is not None:
        cache.pop(cache_key, None)
    try:
        if not published_run(
            cursor,
            recipe.scope.source,
            recipe.bundle_root,
            origin=recipe.scope.origin,
            execution_id=run,
        ):
            return result
        if recipe.scope.source in {"CVE", "CISA"}:
            # Select every member of this exact publication, including missing
            # clocks. A newer unrelated scope or record cannot replace it.
            with streamed_rows(
                cursor,
                sql.SQL(
                    "SELECT o.source_metadata->>'dateUpdated' "
                    "FROM evidence_pipeline.cve_repository_snapshots s "
                    "CROSS JOIN LATERAL jsonb_array_elements(s.members) m(member) "
                    "LEFT JOIN evidence.cve_record_observations o "
                    "ON o.receipt_id=(m.member->>'receipt_id')::uuid "
                    "WHERE s.source_name=%s AND s.origin=%s AND s.run_id=%s"
                ),
                (recipe.scope.source, recipe.scope.origin, run),
            ) as rows:
                stamp, basis, precision = record_clock(
                    (row[0] for row in rows), cve_times=True
                )
            if stamp is not None:
                result.update(
                    provider_time=stamp.isoformat(), basis=basis, precision=precision
                )
        if tree_state(recipe.bundle_root / run) != storage:
            result.update(provider_time=None, basis=None, precision=None)
            return result
        result["health_time"] = finished.isoformat()
        if cache is not None:
            cache[cache_key] = (identity, dict(result))
    except (ValueError, OSError):
        pass  # Recheck missing/corrupt proof next tick; never cache it as healthy.
    return result
