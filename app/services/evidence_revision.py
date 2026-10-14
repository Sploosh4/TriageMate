"""Cached committed-collection watermark through the existing restricted reader."""

import hashlib
import json
import threading
import time
from uuid import uuid4

from app.services.postgres_query import QueryError

# Attempts and repository publications are immutable. Count detects new historical
# imports even when their provider timestamps predate the currently selected input.
# Replay/rollback does not change this watermark. No evidence payload is returned.
SQL = """
SELECT 'attempts' AS kind,count(*)::text AS records,max(id::text) AS newest_id
FROM evidence.collection_attempts WHERE complete AND outcome='success'
UNION ALL
SELECT 'github',count(*)::text,max(run_id::text)
FROM evidence_pipeline.github_repository_snapshots
UNION ALL
SELECT 'cve',count(*)::text,max(run_id::text)
FROM evidence_pipeline.cve_repository_snapshots
UNION ALL
SELECT 'ubuntu',count(*)::text,max(run_id::text)
FROM evidence_pipeline.ubuntu_repository_snapshots
UNION ALL
SELECT 'components',count(*)::text,max(check_id::text)
FROM (
 SELECT check_id FROM evidence_pipeline.component_check_seals
 UNION ALL
 SELECT id AS check_id FROM evidence_pipeline.selected_component_checks
 UNION ALL
 SELECT id AS check_id FROM evidence_pipeline.windows_os_reviews
) component_publications
ORDER BY kind
"""


class EvidenceRevision:
    def __init__(self, queries, *, clock=time.monotonic):
        self.queries, self.clock = queries, clock
        self.lock = threading.Lock()
        self.value = None
        self.checked = float("-inf")

    def read(self):
        if self.value is not None and self.clock() - self.checked < 5:
            return {"revision": self.value}
        if not self.lock.acquire(blocking=False):
            raise QueryError(
                "Collection refresh is being checked.", 503, "refresh_busy"
            )
        try:
            result = json.loads(
                self.queries.execute({"requestId": str(uuid4()), "sql": SQL})
            )
            rows = result["rows"]
            if result.get("truncated") or len(rows) != 5:
                raise QueryError(
                    "Collection refresh could not be confirmed.",
                    503,
                    "refresh_unconfirmed",
                )
            value = hashlib.sha256(
                json.dumps(rows, sort_keys=True).encode()
            ).hexdigest()
            self.value, self.checked = value, self.clock()
            return {"revision": value}
        finally:
            self.lock.release()
