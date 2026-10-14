"""Stream MSRC publication summaries; consume through EOF before acceptance."""

from dataclasses import dataclass
from datetime import datetime
import re
import sqlite3

from standalone.evidence_pipeline.parsing.source_time import source_datetime

from standalone.evidence_pipeline.json_stream import document_array
from standalone.evidence_pipeline.temporary_index import temporary_index

INDEX_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
CONTEXT = "https://api.msrc.microsoft.com/$metadata#Updates"
PUBLICATION_ID = re.compile(
    r"[0-9]{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(?:-B)?",
    re.IGNORECASE | re.ASCII,
)
FIELDS = {
    "ID",
    "Alias",
    "DocumentTitle",
    "Severity",
    "InitialReleaseDate",
    "CurrentReleaseDate",
    "CvrfUrl",
}


MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def period(identity):
    if not isinstance(identity, str) or PUBLICATION_ID.fullmatch(identity) is None:
        raise ValueError("Invalid MSRC publication identity")
    year, month, *_ = identity.split("-")
    return int(year), MONTHS.index(month.title()) + 1


@dataclass(frozen=True)
class Publication:
    publication_id: str
    url: str
    initial_release: datetime
    current_release: datetime
    source_fields: dict


def release_date(value):
    if not isinstance(value, str) or "T" not in value:
        raise ValueError("MSRC release date requires a timestamp")
    try:
        result = source_datetime(value)
    except ValueError as exc:
        raise ValueError("Invalid MSRC release date") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("MSRC release date requires an explicit timezone")
    return result


def publications(stream, *, cancelled=lambda: False):
    """Yield source summaries with bounded parser reads and disk-backed ID checks.

    A late malformed envelope or duplicate invalidates the whole index. Consumers
    must not publish a successful index or checkpoint until this iterator ends.
    Source timestamps describe publication/revision, not collection freshness.
    """
    context_seen = False
    with temporary_index() as seen:
        seen.execute("CREATE TABLE publications (id TEXT PRIMARY KEY)")
        for kind, key, value in document_array(stream, "value", cancelled=cancelled):
            if kind == "array":
                continue
            if kind == "member":
                if key != "@odata.context" or value != CONTEXT:
                    raise ValueError("Unsupported or incomplete MSRC index envelope")
                context_seen = True
                continue
            if not isinstance(value, dict) or set(value) != FIELDS:
                raise ValueError("Invalid MSRC publication fields")
            month = value["ID"]
            if not isinstance(month, str) or PUBLICATION_ID.fullmatch(month) is None:
                raise ValueError("Invalid MSRC publication ID")
            url = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + month
            if value["Alias"] != month or value["CvrfUrl"] != url:
                raise ValueError("MSRC publication identity or URL differs")
            if (
                not isinstance(value["DocumentTitle"], str)
                or not value["DocumentTitle"].strip()
            ):
                raise ValueError("Missing MSRC publication title")
            if value["Severity"] is not None and not isinstance(value["Severity"], str):
                raise ValueError("Invalid MSRC publication severity")
            initial = release_date(value["InitialReleaseDate"])
            current = release_date(value["CurrentReleaseDate"])
            if current < initial:
                raise ValueError("MSRC revision predates initial publication")
            try:
                seen.execute("INSERT INTO publications VALUES(?)", (month,))
            except sqlite3.IntegrityError as exc:
                raise ValueError("Duplicate MSRC publication ID") from exc
            yield Publication(month, url, initial, current, dict(value))
        if not context_seen:
            raise ValueError("Missing MSRC index context")
