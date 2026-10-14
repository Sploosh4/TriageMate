"""Private disposable row storage for complete retained-evidence verification.

The spool is an implementation detail, never evidence or a reusable cache. Values
are pickled only after they have been read as database/normal Python values; no
external pickle is accepted. All readers use this instance's private
SQLite temporary database. On the supported Linux host its backing file is
unlinked at creation, so process termination cannot leave retained data behind.
The connection is also closed on normal and exceptional exits. Individual row
size and small identity sets still contribute to memory use. Large scratch
records are losslessly compressed when smaller; cache admission uses their
uncompressed size. The encoding is never persisted as source evidence.
"""

from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from collections import OrderedDict
import pickle
import sqlite3
import zlib
from uuid import uuid4


def _pack(value):
    raw = pickle.dumps(value, protocol=5)
    compressed = zlib.compress(raw, level=1) if len(raw) >= 4096 else raw
    use_compression = len(compressed) < len(raw)
    return (
        len(raw).to_bytes(8, "big")
        + (b"z" if use_compression else b"p")
        + (compressed if use_compression else raw)
    )


def _unpack(value):
    # This is private, instance-local scratch, never an external pickle format.
    if len(value) < 9 or value[8:9] not in (b"z", b"p"):
        raise ValueError("Invalid verification spool encoding")
    raw = zlib.decompress(value[9:]) if value[8:9] == b"z" else value[9:]
    if len(raw) != int.from_bytes(value[:8], "big"):
        raise ValueError("Verification spool length changed")
    return pickle.loads(raw)


@contextmanager
def streamed_rows(cursor, query, parameters=None, *, exact_json=False):
    """Stream on the caller's transaction, including its uncommitted writes."""
    with cursor.connection.cursor(name="verify_rows_" + uuid4().hex) as source:
        if exact_json:
            # Cursor-local decoding preserves PostgreSQL numeric precision on
            # the first read without changing other consumers' JSON contracts.
            import json
            from decimal import Decimal
            from psycopg2.extras import register_default_jsonb

            register_default_jsonb(
                source, loads=lambda value: json.loads(value, parse_float=Decimal)
            )
        source.itersize = 128
        source.execute(query, parameters)
        yield source


class VerificationSpool:
    def __enter__(self):
        # Empty filename requests SQLite's private temporary database. Unlike a
        # named TemporaryDirectory, the Unix backing file is already unlinked,
        # including when SIGTERM/SIGKILL prevents Python finally blocks running.
        self.connection = sqlite3.connect("")
        try:
            self.connection.execute("PRAGMA cache_size=-8192")
            self.connection.execute("PRAGMA temp_store=FILE")
            self.connection.execute("PRAGMA journal_mode=OFF")
            self.counter = 0
            return self
        except BaseException:
            self.connection.close()
            raise

    def __exit__(self, *exc):
        self.connection.close()

    def _table(self):
        self.counter += 1
        table = "rows_" + str(self.counter)
        self.connection.execute(
            f"CREATE TABLE {table}(key TEXT PRIMARY KEY, value BLOB NOT NULL)"
        )
        return table

    def mapping(self, items):
        table = self._table()
        self.connection.executemany(
            f"INSERT INTO {table} VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ((key, _pack(value)) for key, value in items),
        )
        return SpoolMapping(self.connection, table)

    def rows(self, values):
        table = self._table()
        count = 0

        def entries():
            nonlocal count
            for count, value in enumerate(values, 1):
                yield str(count - 1), _pack(value)

        self.connection.executemany(f"INSERT INTO {table} VALUES(?,?)", entries())
        return SpoolRows(self.connection, table, count)

    def reference_mapping(self, source, field, predicate=lambda row: True):
        """Index immutable rows already in this spool without copying payloads."""
        if not isinstance(source, (SpoolRows, SpoolMapping)) or (
            source.connection is not self.connection
        ):
            raise ValueError("Reference index requires rows from this spool")
        self.counter += 1
        index = "index_" + str(self.counter)
        view = "reference_" + str(self.counter)
        # Physical spool tables have immutable SQLite row identities. Joining
        # them directly avoids a second text-key index lookup. Nested reference
        # views have no rowid, so retain their explicit source-key relationship.
        source_key = "key" if isinstance(source, SpoolReferenceMapping) else "rowid"
        key_type = "TEXT" if source_key == "key" else "INTEGER"
        self.connection.execute(
            f"CREATE TABLE {index}(key TEXT PRIMARY KEY, source_key {key_type} NOT NULL)"
        )

        def entries():
            for source_identity, payload in self.connection.execute(
                f"SELECT {source_key},value FROM {source.table}"
            ):
                row = _unpack(payload)
                if predicate(row):
                    yield row[field], source_identity

        self.connection.executemany(f"INSERT INTO {index} VALUES(?,?)", entries())
        self.connection.execute(
            f"CREATE VIEW {view} AS SELECT i.key,s.value,i.rowid AS ordinal FROM {index} i "
            f"JOIN {source.table} s ON s.{source_key}=i.source_key"
        )
        return SpoolReferenceMapping(self.connection, view, index)

    def grouped_identities(self, pairs):
        """Stream receipt/identity pairs; materialize only a requested group."""
        self.counter += 1
        table = "groups_" + str(self.counter)
        self.connection.execute(
            f"CREATE TABLE {table}(key TEXT, identity TEXT, PRIMARY KEY(key,identity)) WITHOUT ROWID"
        )
        self.connection.executemany(f"INSERT OR IGNORE INTO {table} VALUES(?,?)", pairs)
        return SpoolIdentityGroups(self.connection, table)


class SpoolIdentityGroups(Mapping):
    def __init__(self, connection, table):
        self.connection, self.table = connection, table

    def __getitem__(self, key):
        values = {
            row[0]
            for row in self.connection.execute(
                f"SELECT identity FROM {self.table} WHERE key=?", (key,)
            )
        }
        if not values:
            raise KeyError(key)
        return values

    def __iter__(self):
        for (key,) in self.connection.execute(f"SELECT DISTINCT key FROM {self.table}"):
            yield key

    def __len__(self):
        return self.connection.execute(
            f"SELECT count(DISTINCT key) FROM {self.table}"
        ).fetchone()[0]


class SpoolMapping(Mapping):
    def __init__(self, connection, table):
        self.connection, self.table = connection, table
        # Values stay immutable bytes in this bounded cache. Callers receive
        # freshly decoded values, so their date conversions cannot mutate later
        # verification reads. Repeated same-receipt checks avoid redundant SQL.
        self._cache = OrderedDict()

    def _fetch(self, key):
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        row = self.connection.execute(
            f"SELECT value FROM {self.table} WHERE key=?", (key,)
        ).fetchone()
        value = None if row is None else row[0]
        # This only limits caching, never row acceptance or verification.
        if value is None or int.from_bytes(value[:8], "big") <= 65_536:
            self._cache[key] = value
            if len(self._cache) > 64:
                self._cache.popitem(last=False)
        return value

    def __getitem__(self, key):
        value = self._fetch(key)
        if value is None:
            raise KeyError(key)
        return _unpack(value)

    def __contains__(self, key):
        return self._fetch(key) is not None

    def __iter__(self):
        for (key,) in self.connection.execute(
            f"SELECT key FROM {self.table} ORDER BY rowid"
        ):
            yield key

    def __len__(self):
        return self.connection.execute(f"SELECT count(*) FROM {self.table}").fetchone()[
            0
        ]

    def items(self):
        for key, value in self.connection.execute(
            f"SELECT key,value FROM {self.table} ORDER BY rowid"
        ):
            yield key, _unpack(value)

    def values(self):
        for (value,) in self.connection.execute(
            f"SELECT value FROM {self.table} ORDER BY rowid"
        ):
            yield _unpack(value)


class SpoolReferenceMapping(SpoolMapping):
    """Read keys/counts from the index without joining or sorting row payloads."""

    def __init__(self, connection, table, index):
        super().__init__(connection, table)
        self.index = index

    def __iter__(self):
        for (key,) in self.connection.execute(
            f"SELECT key FROM {self.index} ORDER BY rowid"
        ):
            yield key

    def __len__(self):
        return self.connection.execute(f"SELECT count(*) FROM {self.index}").fetchone()[
            0
        ]

    def items(self):
        # Views have no physical rowid. Ordering by their implicit NULL rowid
        # makes SQLite sort all payloads into another temporary file. Use the
        # reference index's real insertion order, including for nested views.
        for key, value in self.connection.execute(
            f"SELECT key,value FROM {self.table} ORDER BY ordinal"
        ):
            yield key, _unpack(value)

    def values(self):
        for _, value in self.items():
            yield value


class SpoolRows(Sequence):
    def __init__(self, connection, table, count):
        self.connection, self.table, self.count = connection, table, count

    def __len__(self):
        return self.count

    def __eq__(self, other):
        if not isinstance(other, Sequence):
            return NotImplemented
        return len(self) == len(other) and all(a == b for a, b in zip(self, other))

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self.count))]
        if index < 0:
            index += self.count
        if not 0 <= index < self.count:
            raise IndexError(index)
        row = self.connection.execute(
            f"SELECT value FROM {self.table} WHERE key=?", (str(index),)
        ).fetchone()
        if row is None:
            raise AssertionError("Verification spool lost a row")
        return _unpack(row[0])

    def __iter__(self):
        for (value,) in self.connection.execute(
            f"SELECT value FROM {self.table} ORDER BY rowid"
        ):
            yield _unpack(value)
