"""Immutable Cisco RSS discovery receipts; no database import or automatic retry."""

from dataclasses import dataclass
from datetime import datetime

from standalone.evidence_pipeline.parsing.cisco_rss import parse_feed


@dataclass(frozen=True)
class IndexSnapshot:
    origin: str
    execution_id: str
    started_at: datetime
    finished_at: datetime
    payload: bytes
    error_code: str | None

    @property
    def complete(self):
        return self.error_code is None

    @property
    def items(self):
        return parse_feed(self.payload) if self.complete else ()


def prepare(
    bundle,
    execution_id,
    *,
    origin,
    allow_network=False,
    replay_only=False,
    synthetic_payload=None,
):
    """Retired collector; original source/tests are preserved in the archive tag."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Cisco")
