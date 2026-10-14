"""Timestamp interpretation only for explicitly UTC-labelled Intune CSV fields."""

from datetime import datetime
import re


def update_report_timestamp(value: str | None, field: str) -> str | None:
    """Preserve raw input elsewhere; expose Microsoft's unset scan time as unknown."""
    if field not in {"EventDateTimeUTC", "LastWUScanTimeUTC"}:
        raise ValueError("Unsupported update-report timestamp field")
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"Invalid timestamp field: {field}")
    # Live CSV exports use a space and seven fractional digits without an offset.
    # Do not apply this interpretation to arbitrary naive ISO timestamps or jobs.
    if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7}", value):
        value = value.replace(" ", "T") + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp field: {field}") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{field} must be UTC")
    if field == "LastWUScanTimeUTC" and re.fullmatch(
        r"0001-01-01T00:00:00(?:\.0+)?(?:Z|\+00:00)", value
    ):
        return None
    return parsed.isoformat()
