"""File-backed EPSS rows with exact decimals and disk-backed duplicate checks."""

from contextlib import contextmanager
import csv
import io
import sqlite3

from standalone.evidence_pipeline.temporary_index import temporary_index

from standalone.evidence_pipeline.file_payload import FilePayload
from standalone.evidence_pipeline.parsing.public_inputs import (
    EpssFeed,
    EpssRecord,
    MAX_PUBLIC_RECORDS,
    _cve,
    _number,
    parse_epss_csv,
)


class _Raw(io.RawIOBase):
    def __init__(self, verified):
        super().__init__()
        self.verified = verified

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.verified.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


@contextmanager
def _text(payload):
    with payload.open() as verified:
        with io.TextIOWrapper(
            io.BufferedReader(_Raw(verified)), encoding="utf-8-sig", newline=""
        ) as text:
            try:
                yield text
            except UnicodeError as exc:
                raise ValueError("Invalid public payload encoding") from exc


def _header(stream, scope):
    first = stream.readline()
    header = first + stream.readline() if first.startswith("#") else first
    # The existing parser remains authoritative for metadata, columns and dates.
    # A metadata-free historic file requires an explicit dated archive scope.
    return parse_epss_csv(header.encode("utf-8"), scope=scope)


def parse_epss_file(payload, *, scope):
    if not isinstance(payload, FilePayload):
        raise ValueError("Streamed EPSS requires a verified saved payload")
    with _text(payload) as stream:
        metadata = _header(stream, scope)

    def records():
        with temporary_index() as seen:
            seen.execute("CREATE TABLE cves (identity TEXT PRIMARY KEY)")
            with _text(payload) as stream:
                current = _header(stream, scope)
                if (
                    current.score_date,
                    current.model_version,
                    current.score_timestamp,
                ) != (
                    metadata.score_date,
                    metadata.model_version,
                    metadata.score_timestamp,
                ):
                    raise ValueError("EPSS header changed during processing")
                try:
                    for number, row in enumerate(csv.reader(stream, strict=True)):
                        if len(row) != 3 or number >= MAX_PUBLIC_RECORDS:
                            raise ValueError("Invalid EPSS row shape or count")
                        cve = _cve(row[0])
                        try:
                            seen.execute("INSERT INTO cves VALUES (?)", (cve,))
                        except sqlite3.IntegrityError as exc:
                            raise ValueError("Duplicate source record") from exc
                        yield EpssRecord(
                            cve,
                            _number(row[1], 1, csv_value=True),
                            _number(row[2], 1, csv_value=True),
                        )
                except csv.Error as exc:
                    raise ValueError("Malformed EPSS CSV") from exc

    return EpssFeed(
        scope,
        payload,
        metadata.score_date,
        metadata.model_version,
        records(),
        metadata.score_timestamp,
    )
