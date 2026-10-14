"""Journal provider-clock age episodes separately from missed collection runs."""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import time
from uuid import uuid4

from standalone.evidence_pipeline.contracts import utc
from standalone.evidence_pipeline.runtime import connect
from .provider_age import SUPPORTED, classify, read_clock
from .store import service_key


@dataclass(frozen=True)
class ProviderPolicy:
    recipe: object
    max_age_seconds: int

    def __post_init__(self):
        from .process_worker import PublicRecipe
        from .repository_recipe import RepositoryRecipe
        from .catalog_target_recipe import CatalogTargetRecipe

        if (
            not (
                isinstance(self.recipe, CatalogTargetRecipe)
                and self.recipe.scope.source == "Microsoft Update Catalog"
                and self.recipe.scope.input_kind == "catalog_targets"
                and self.recipe.scope.origin in {"synthetic", "lab"}
            )
            and not (
                isinstance(self.recipe, PublicRecipe)
                and (self.recipe.scope.source, self.recipe.scope.input_kind)
                in SUPPORTED
            )
            and not (
                isinstance(self.recipe, RepositoryRecipe)
                and (self.recipe.scope.source, self.recipe.scope.input_kind)
                in {
                    ("Microsoft Update Catalog", "catalog_search"),
                    ("Cisco", "repository"),
                    ("MSRC", "repository"),
                    ("CVE", "repository"),
                    ("CISA", "repository"),
                    ("WA SOC", "repository"),
                }
            )
        ):
            raise ValueError("Provider-age policy requires a supported public feed")
        classify(None, datetime.now(timezone.utc), max_age_seconds=self.max_age_seconds)


def record(cursor, key, policy, observation, now, revision):
    scope = policy.recipe.scope
    cursor.execute(
        "SELECT event FROM evidence_pipeline.operation_events WHERE service_key=%s "
        "AND event->>'input_id'=%s AND event->>'kind' LIKE 'provider_age_%%' ORDER BY id DESC LIMIT 1",
        (key, scope.connection_id),
    )
    row = cursor.fetchone()
    previous = row[0] if row else None
    if previous is None and observation["attempt_id"] is None:
        return False  # Initial absence is covered by the overdue-collection policy.
    clock = (
        observation.get("health_time")
        if "health_time" in observation
        else observation["provider_time"]
    )
    condition = classify(
        None if clock is None else datetime.fromisoformat(clock),
        now,
        max_age_seconds=policy.max_age_seconds,
    )
    healthy = condition == "healthy"
    active = previous is not None and previous["kind"] != "provider_age_resolved"
    if healthy and not active:
        return False
    details = dict(
        source=scope.source,
        input_kind=scope.input_kind,
        scope_reference=scope.scope_reference,
        origin=scope.origin,
        max_age_seconds=policy.max_age_seconds,
        condition=condition,
        **observation,
    )
    if previous is not None and all(
        previous.get(field) == value for field, value in details.items()
    ):
        return False
    event = dict(
        kind="provider_age_resolved"
        if healthy
        else "provider_age_updated"
        if active
        else "provider_age_opened",
        input_id=scope.connection_id,
        episode_id=previous["episode_id"] if active else str(uuid4()),
        at=utc(now).isoformat(),
        **details,
    )
    cursor.execute(
        "INSERT INTO evidence_pipeline.operation_events(service_key,checkpoint_revision,recorded_at,event) "
        "VALUES(%s,%s,%s,%s::jsonb)",
        (key, revision, now, json.dumps(event)),
    )
    return True


class ProviderMonitor:
    def __init__(self, key, policies, *, connector=connect, clock=time.monotonic):
        self.key, self.policies = service_key(key), tuple(policies)
        self.connector, self.clock = connector, clock
        self.checked = float("-inf")
        self.cache = {}

    def check(self, now=None):
        if not self.policies or self.clock() - self.checked < 60:
            return
        now = utc(now or datetime.now(timezone.utc))
        with closing(self.connector()) as conn, conn, conn.cursor() as cursor:
            from .repository_recipe import RepositoryRecipe
            from .catalog_age import read_clock as read_catalog_clock, read_target_clock
            from .catalog_target_recipe import CatalogTargetRecipe
            from .msrc_age import read_clock as read_msrc_clock
            from .repository_age import SOURCES, read_clock as read_repository_clock

            observations = [
                (
                    policy,
                    read_target_clock(cursor, self.key, policy.recipe)
                    if isinstance(policy.recipe, CatalogTargetRecipe)
                    else read_repository_clock(
                        cursor, self.key, policy.recipe, cache=self.cache
                    )
                    if isinstance(policy.recipe, RepositoryRecipe)
                    and policy.recipe.scope.source in SOURCES
                    else read_msrc_clock(
                        cursor, self.key, policy.recipe, cache=self.cache
                    )
                    if isinstance(policy.recipe, RepositoryRecipe)
                    and policy.recipe.scope.source == "MSRC"
                    else read_catalog_clock(cursor, self.key, policy.recipe)
                    if isinstance(policy.recipe, RepositoryRecipe)
                    else read_clock(cursor, policy.recipe, cache=self.cache),
                )
                for policy in self.policies
            ]
            cursor.execute(
                "SELECT revision FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s FOR UPDATE",
                (self.key,),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError(
                    "Provider monitoring requires an operational checkpoint"
                )
            for policy, observed in observations:
                record(cursor, self.key, policy, observed, now, row[0])
        self.checked = self.clock()
