"""Explicit CTID CVE-to-ATT&CK mappings from its retained public CSV.

The publisher's converter labels this legacy mapping material as ATT&CK 9.0 but
notes that assuming an Enterprise domain for every mapping is incorrect. This
parser retains categories and phase and does not invent a domain or currentness.
"""

import csv
from dataclasses import dataclass
import io
import re

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_inputs import (
    CVE_PATTERN,
    MAX_PUBLIC_RECORDS,
    MAX_TEXT,
    PublicFeed,
)

URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/src/mapex_convert/mappings/Att&ckToCveMappings.csv"
CATEGORIES = (
    "Primary Impact",
    "Secondary Impact",
    "Exploitation Technique",
    "Uncategorized",
)
TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")


@dataclass(frozen=True)
class CtidRecord:
    cve_id: str
    mappings: tuple[tuple[str, str], ...]
    raw_rows: tuple[dict[str, str], ...]
    unresolved_mappings: tuple[tuple[str, str], ...]

    @property
    def source_record_id(self):
        return self.cve_id

    @property
    def cve_ids(self):
        return (self.cve_id,)


@dataclass(frozen=True)
class CtidFeed(PublicFeed):
    records: tuple[CtidRecord, ...]


def parse_ctid(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("CTID", "cve_mappings")
        or scope.tenant_id is not None
        or scope.origin not in {"synthetic", "public"}
        or scope.scope_reference != URL
    ):
        raise ValueError("CTID requires its fixed non-tenant mapping scope")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("Invalid CTID mapping payload size")
    try:
        text = payload.decode("utf-8-sig")
        if "\0" in text:
            raise ValueError("NUL in CTID mappings")
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        headers = reader.fieldnames
        if (
            not headers
            or len(headers) > 100
            or len(set(headers)) != len(headers)
            or not {"CVE ID", "Phase", *CATEGORIES} <= set(headers)
            or any(not name or len(name) > 200 for name in headers)
        ):
            raise ValueError("Invalid CTID mapping header")
        grouped = {}
        for index, row in enumerate(reader):
            if (
                index >= MAX_PUBLIC_RECORDS
                or None in row
                or any(value is None or len(value) > MAX_TEXT for value in row.values())
            ):
                raise ValueError("Incomplete or oversized CTID mapping row")
            if not CVE_PATTERN.fullmatch(row["CVE ID"]):
                raise ValueError("Invalid explicit CTID CVE identity")
            grouped.setdefault(row["CVE ID"], []).append(row)
        records = []
        for cve, rows in grouped.items():
            mappings = tuple(
                dict.fromkeys(
                    (category, token.strip())
                    for row in rows
                    for category in CATEGORIES
                    for token in row[category].split(";")
                    if TECHNIQUE.fullmatch(token.strip())
                )
            )
            unresolved = tuple(
                dict.fromkeys(
                    (category, token.strip())
                    for row in rows
                    for category in CATEGORIES
                    for token in row[category].split(";")
                    if token.strip() and not TECHNIQUE.fullmatch(token.strip())
                )
            )
            records.append(CtidRecord(cve, mappings, tuple(rows), unresolved))
        return CtidFeed(scope, payload, tuple(records))
    except (UnicodeError, csv.Error) as exc:
        raise ValueError("Invalid CTID CSV encoding or structure") from exc
