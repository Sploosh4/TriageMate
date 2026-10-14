"""Fixed FIRST daily archive routes; no arbitrary URL or inferred model version."""

from datetime import date
import re

PREFIX = "https://epss.empiricalsecurity.com/epss_scores-"


def archive_date(value):
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None
    ):
        raise ValueError("EPSS archive date requires YYYY-MM-DD")
    parsed = date.fromisoformat(value)
    if parsed < date(2021, 4, 14):
        raise ValueError("EPSS scores are unavailable before 2021-04-14")
    return parsed


def archive_url(value):
    return PREFIX + archive_date(value).isoformat() + ".csv.gz"


def scope_score_date(reference):
    if not isinstance(reference, str):
        return None
    match = re.fullmatch(
        re.escape(PREFIX) + r"([0-9]{4}-[0-9]{2}-[0-9]{2})\.csv\.gz", reference
    )
    return archive_date(match[1]) if match else None
