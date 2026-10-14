"""Disk-backed validation of complete Windows inventory before any publication."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import sqlite3
from tempfile import TemporaryFile

from standalone.evidence_pipeline.json_stream import document_array
from standalone.evidence_pipeline.temporary_index import temporary_index

from .contract import DeviceBinding, validate_document
from .bundle_manifest import validate_links


@dataclass
class StagedInventory:
    _metadata: bytes
    fingerprint: str
    records_file: object
    source_file: object
    cancelled: object

    @property
    def metadata(self):
        # Return a fresh value so callers cannot accidentally alter accepted
        # collection dates, coverage or counts in the shared staging object.
        return json.loads(self._metadata)

    def records(self):
        self.records_file.seek(0)
        for line in self.records_file:
            if self.cancelled():
                raise ValueError("Inventory processing cancelled")
            yield json.loads(line)


@contextmanager
def stage(stream, expected: DeviceBinding, *, cancelled=lambda: False):
    """Copy in fixed chunks, then validate metadata and rows with disk indexes.

    No backend byte ceiling. TemporaryFile is unlinked immediately on Linux;
    errors, cancellation and context exit close both spools. The source is copied
    before either pass, so a changing caller-owned file cannot alter accepted rows
    between metadata and record validation. Publication must occur inside this
    context; the iterator is not a durable bundle.
    """
    with TemporaryFile() as source, TemporaryFile(mode="w+b") as rows:
        fingerprint = hashlib.sha256()
        while True:
            if cancelled():
                raise ValueError("Inventory processing cancelled")
            chunk = stream.read(65536)
            if not chunk:
                break
            source.write(chunk)
            fingerprint.update(chunk)
        source.seek(0)
        metadata, count = {}, 0
        for kind, key, item in document_array(
            source, "records", cancelled=cancelled, materialize_items=False
        ):
            if kind == "member":
                metadata[key] = item
            elif kind == "item":
                count += 1
        if (
            type(metadata.get("record_count")) is not int
            or metadata["record_count"] != count
        ):
            raise ValueError("Inventory record count does not match complete output")
        # Metadata validated even for empty inventories. Reuse the same strict
        # envelope checks without materializing the source record array.
        envelope = dict(metadata, records=[], record_count=0)
        validate_document(envelope, expected)
        source.seek(0)
        with temporary_index() as seen:
            seen.execute(
                "CREATE TABLE identities (kind TEXT, native_id TEXT, PRIMARY KEY(kind,native_id)) WITHOUT ROWID"
            )
            for kind, key, item in document_array(
                source, "records", cancelled=cancelled
            ):
                if kind != "item":
                    continue
                validate_document(
                    dict(envelope, records=[item], record_count=1),
                    expected,
                    check_links=False,
                )
                try:
                    seen.execute(
                        "INSERT INTO identities VALUES (?,?)",
                        (item["kind"], item["native_id"]),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ValueError("Duplicate inventory native identity") from exc
                rows.write(
                    json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode()
                    + b"\n"
                )
        rows.seek(0)
        validate_links((json.loads(line) for line in rows), cancelled=cancelled)
        if cancelled():
            raise ValueError("Inventory processing cancelled")
        source.seek(0)
        yield StagedInventory(
            json.dumps(metadata).encode(),
            fingerprint.hexdigest(),
            rows,
            source,
            cancelled,
        )
