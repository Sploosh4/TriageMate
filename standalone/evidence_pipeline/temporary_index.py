"""Private spillable SQLite indexes with no named scratch-file lifecycle."""

from contextlib import closing, contextmanager
import sqlite3


@contextmanager
def temporary_index():
    """SQLite owns its temporary database; callers cannot name retained evidence.

    An empty filename selects a temporary database, not an in-memory database.
    Its cache is bounded to roughly 1 MiB and spills to disk. On the supported
    Linux runtime SQLite unlinks the backing file while open, so even SIGTERM
    or os._exit cannot orphan a named parser index. Normal exits close it too.
    This is scratch storage only; source bundles and PostgreSQL are untouched.
    """
    with closing(sqlite3.connect("")) as connection:
        connection.execute("PRAGMA cache_size=-1024")
        yield connection
