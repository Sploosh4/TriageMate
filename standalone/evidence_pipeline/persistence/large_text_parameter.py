"""Adapt a large UTF-8 claim without duplicating its escaped backslashes.

This is still one parameter and one INSERT under the existing row policies.
PostgreSQL dollar quoting preserves the literal text. Its delimiter must be
absent from the entire value, including boundaries between encoding chunks.
The driver still builds a complete statement; memory scales with one record.
"""

from io import BytesIO
from uuid import uuid4

from psycopg2.extensions import ISQLQuote


class LargeTextParameter:
    def __init__(self, value):
        if not isinstance(value, str):
            raise TypeError("A text claim is required")
        self.value = value
        self.prepared = False

    def __conform__(self, protocol):
        return self if protocol is ISQLQuote else None

    def prepare(self, connection):
        if connection.encoding != "UTF8":
            raise ValueError("Large text insertion requires UTF8")
        self.prepared = True

    def getquoted(self):
        if not self.prepared or "\x00" in self.value:
            raise ValueError("Invalid or unprepared text parameter")
        while True:
            delimiter = "$tm_claim_" + uuid4().hex + "$"
            if delimiter not in self.value:
                break
        marker = delimiter.encode("ascii")
        with BytesIO() as output:
            output.write(marker)
            for start in range(0, len(self.value), 16384):
                output.write(self.value[start : start + 16384].encode("utf-8"))
            output.write(marker)
            return output.getvalue()
