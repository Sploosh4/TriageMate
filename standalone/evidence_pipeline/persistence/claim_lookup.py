"""Private, temporary claim lookup without retaining every claim body in RAM."""

from collections.abc import Mapping
from contextlib import contextmanager
import tempfile
from uuid import uuid4


class ClaimLookup(Mapping):
    """Retain row offsets; materialize only the individual claim being checked."""

    def __init__(self, stream):
        self.stream = stream
        self.offsets = {}

    def add(self, key, claim):
        if key in self.offsets:
            raise AssertionError("Duplicate public claim revision")
        self.stream.seek(0, 2)
        offset = self.stream.tell()
        # Avoid a second whole-claim UTF-8 allocation while writing the spool.
        for start in range(0, len(claim), 8192):
            self.stream.write(claim[start : start + 8192])
        self.offsets[key] = (offset, len(claim))

    def __getitem__(self, key):
        offset, length = self.offsets[key]
        self.stream.seek(offset)
        result = self.stream.read(length)
        if len(result) != length:
            raise AssertionError("Temporary public claim truncated")
        return result

    def __iter__(self):
        return iter(self.offsets)

    def __len__(self):
        return len(self.offsets)


@contextmanager
def public_claims(cursor):
    """Use one transaction snapshot and an anonymous file closed on every exit.

    A server cursor avoids libpq buffering the entire result before Python sees
    it. Small claims use batches of at most 256 rows of 64 KiB each; larger
    claims are fetched singly. Memory also includes an index proportional to the
    revision count; this does not assert constant memory for arbitrarily large
    individual claims. The anonymous spool is not a retained evidence artifact.
    """
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8", newline="") as stream:
        claims = ClaimLookup(stream)
        # These are batching thresholds, not acceptance/download size limits.
        # Both partitions are read; no claim is excluded for being large.
        for comparison, batch in (("<=", 256), (">", 1)):
            with cursor.connection.cursor(
                name="verify_claims_" + uuid4().hex
            ) as source:
                source.itersize = batch
                source.execute(
                    "SELECT source_revision_id::text,claim FROM evidence_pipeline.public_claims "
                    f"WHERE octet_length(claim) {comparison} %s",
                    (65_536,),
                )
                for key, claim in source:
                    claims.add(key, claim)
        stream.flush()
        yield claims
