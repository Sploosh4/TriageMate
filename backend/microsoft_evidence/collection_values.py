"""Storage-independent canonical values shared by Microsoft collectors."""

import hashlib
import json
from datetime import datetime


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        default=str,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def require_utc(name: str, value: datetime) -> None:
    if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")
