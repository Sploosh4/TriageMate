"""Strict Red Hat CSAF index discovery; file order is not publication chronology.

Source: https://security.access.redhat.com/data/csaf/v2/advisories/index.txt
Data licence: https://access.redhat.com/security/data (CC-BY-4.0).
"""

from dataclasses import dataclass
from datetime import datetime
import csv
import io
import re

BASE = "https://security.access.redhat.com/data/csaf/v2/advisories/"
INDEX_URL = BASE + "index.txt"
CHANGES_URL = BASE + "changes.csv"
MAX_ADVISORIES = 100_000
PATH = re.compile(
    r"[0-9]{4}/(?P<kind>rhsa|rhba|rhea)-(?P<year>[0-9]{4})_(?P<number>[0-9]{3,10})\.json\Z"
)


@dataclass(frozen=True)
class AdvisoryFile:
    advisory_id: str
    path: str
    url: str


def advisory_file(path):
    match = PATH.fullmatch(path) if isinstance(path, str) else None
    if match is None:
        raise ValueError("Invalid Red Hat advisory index path")
    return AdvisoryFile(
        match["kind"].upper() + "-" + match["year"] + ":" + match["number"],
        path,
        BASE + path,
    )


def parse_index(payload):
    from standalone.evidence_pipeline.parsing.csaf_index import parse_paths

    return parse_paths(payload, advisory_file, max_records=MAX_ADVISORIES)


@dataclass(frozen=True)
class AdvisoryChange:
    advisory: AdvisoryFile
    modified_at: datetime


def parse_changes(payload):
    """Read publisher revision clocks without treating them as collection times.

    Selection/collection authority is separate. Do not infer a publication date
    from this revision clock or resolve duplicate path assertions by CSV order.
    """
    if not isinstance(payload, bytes):
        raise ValueError("Red Hat change index requires UTF-8 bytes")
    try:
        reader = csv.reader(io.StringIO(payload.decode("utf-8")), strict=True)
        changes, seen = [], set()
        for row in reader:
            if len(row) != 2:
                raise ValueError("Red Hat change index requires path and revision time")
            advisory = advisory_file(row[0])
            if advisory.path in seen:
                raise ValueError("Duplicate Red Hat change index path")
            if (
                re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
                    row[1],
                )
                is None
            ):
                raise ValueError("Red Hat revision time requires an explicit timezone")
            modified = datetime.fromisoformat(row[1].replace("Z", "+00:00"))
            seen.add(advisory.path)
            changes.append(AdvisoryChange(advisory, modified))
            if len(changes) > MAX_ADVISORIES:
                raise ValueError("Red Hat change index exceeds supported record count")
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("Invalid Red Hat change index encoding or CSV") from exc
    if not changes:
        raise ValueError("Empty Red Hat change index")
    return tuple(changes)
