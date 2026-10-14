"""Coordinate anonymous public requests across workers using the existing database.

NVD documents five requests per rolling 30 seconds. A shared lock and a 6.1-second
pause before each request leave a margin beyond six seconds. Holding the lock
through the request makes the spacing conservative even after a worker crashes;
no persisted clock, new role, credential or schema is required. GitHub REST uses
an independent slot and 61-second interval against its anonymous 60/hour budget.
Other applications sharing the outbound IP are outside this coordination; upstream
rate-limit responses remain authoritative. Raw advisory downloads use another host
and are not routed through the REST slot.
"""

from contextlib import closing, contextmanager
from contextvars import ContextVar
from threading import get_ident
import time

from psycopg2.errors import LockNotAvailable

from standalone.evidence_pipeline.runtime import connect

GITHUB_LOCK = 731904232
GITHUB_INTERVAL = 61.0
NVD_LOCK = 731904231
NVD_INTERVAL = 6.1
_held = ContextVar("triagemate_public_request_slots", default=None)


class PublicSourceBusy(RuntimeError):
    """Another worker owns the source slot; no request has been sent."""


@contextmanager
def paced(source, *, origin="public"):
    if origin not in ("public", "synthetic"):
        raise ValueError("Public pacing requires public or synthetic origin")
    slots = {
        "NVD": (NVD_LOCK, NVD_INTERVAL),
        "GitHub REST": (GITHUB_LOCK, GITHUB_INTERVAL),
    }
    if origin == "synthetic" or source not in slots:
        yield
        return
    previous = _held.get() or {}
    held = previous.get(source)
    if held is not None and held[0] == get_ident():
        held[1].execute("SELECT 1")
        yield
        return
    with closing(connect()) as conn, conn, conn.cursor() as cur:
        conn.set_session(readonly=True)
        cur.execute("SET LOCAL lock_timeout='100ms'")
        try:
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (slots[source][0],))
        except LockNotAvailable:
            raise PublicSourceBusy(f"{source} request slot is busy") from None
        token = _held.set({**previous, source: (get_ident(), cur)})
        try:
            remaining = slots[source][1]
            while remaining > 0:
                pause = min(30.0, remaining)
                time.sleep(pause)
                remaining -= pause
            cur.execute("SELECT 1")
            yield
        finally:
            _held.reset(token)
