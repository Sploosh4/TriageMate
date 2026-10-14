"""Parse provider ISO timestamps without normalizing malformed UTC offsets."""

from datetime import datetime
import re

_OFFSET = re.compile(
    r"[+-](?:[01][0-9]|2[0-3])"
    r"(?:(?::[0-5][0-9]){1,2}|[0-5][0-9](?:[0-5][0-9])?)?"
    r"(?:[.,][0-9]+)?"
)


def source_datetime(value: str) -> datetime:
    """Keep existing ISO parsing and naive-time semantics; validate offset fields.

    datetime.fromisoformat accepts offsets such as +00:60 by carrying minutes
    into hours. Source evidence must reject that malformed value, not move it.
    """
    # ISO calendar dates contain minus signs; only inspect the time suffix.
    # Both extended YYYY-MM-DD and compact YYYYMMDD dates are accepted by Python.
    date_length = 10 if len(value) > 4 and value[4] == "-" else 8
    offset = re.search(r"[+-].*$", value[date_length + 1 :])
    if offset is not None and _OFFSET.fullmatch(offset.group()) is None:
        raise ValueError("Invalid source timestamp offset")
    return datetime.fromisoformat(value)
