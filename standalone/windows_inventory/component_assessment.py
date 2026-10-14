"""Disk-backed component evaluation for the validated inventory import workflow.

The context manager owns its spooled results. Callers must persist them within
that lifetime and commit before advertising success. It never accepts precomputed
verdicts or supplies production rules, and performs no network collection.
"""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
from tempfile import TemporaryFile

from .component_check import CheckContext, _check_record, _validate_check
from .contract import DeviceBinding
from .staging import StagedInventory


def canonical(value):
    def encode(item):
        if isinstance(item, datetime):
            return item.isoformat()
        raise TypeError("Unsupported component evidence value")

    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, default=encode
    )


@dataclass
class StagedAssessment:
    _metadata: bytes
    results_file: object
    inventory: StagedInventory
    _supporting_sources: dict

    @property
    def metadata(self):
        return json.loads(self._metadata)

    def results(self):
        self.results_file.seek(0)
        for line in self.results_file:
            if self.inventory.cancelled():
                raise ValueError("Component processing cancelled")
            yield json.loads(line)

    def source_chunks(self):
        """Replay original inventory and supporting bytes without a full raw copy."""
        self.inventory.source_file.seek(0)
        digest = hashlib.sha256()
        number = 0
        while True:
            if self.inventory.cancelled():
                raise ValueError("Component evidence processing cancelled")
            chunk = self.inventory.source_file.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            yield self.inventory.fingerprint, number, chunk
            number += 1
        if digest.hexdigest() != self.inventory.fingerprint:
            raise ValueError("Inventory source changed after validation")
        for fingerprint, source in sorted(self._supporting_sources.items()):
            if fingerprint == self.inventory.fingerprint:
                continue
            for number, offset in enumerate(range(0, max(1, len(source)), 65536)):
                if self.inventory.cancelled():
                    raise ValueError("Component evidence processing cancelled")
                yield fingerprint, number, source[offset : offset + 65536]


class _Records:
    def __init__(self, inventory):
        self.inventory = inventory

    def __iter__(self):
        return self.inventory.records()


@contextmanager
def prepare(
    inventory, *, binding, origin, context=None, rules=(), retained_sources=None
):
    """Pin results to immutable staged bytes; absent context cannot yield a fix.

    Normal inventory imports without reviewed rule/context evidence still record
    explicit unknowns. Additional context must pass the same exact device, snapshot,
    observation-time, assembly and source validation as the offline checker.
    """
    if not isinstance(inventory, StagedInventory) or not isinstance(
        binding, DeviceBinding
    ):
        raise ValueError("Validated inventory and independent device binding required")
    if origin not in ("synthetic", "lab"):
        raise ValueError("Explicit synthetic or dedicated-lab origin required")
    metadata = inventory.metadata
    if binding != DeviceBinding(
        *(metadata[k] for k in ("machine_guid", "tenant_id", "device_id"))
    ):
        raise ValueError("Component device differs from inventory")
    rules = tuple(rules)
    anchors = []
    supporting = {}
    if context is None:
        if rules or retained_sources:
            raise ValueError("Rules and supporting evidence require pinned context")
    else:
        if not isinstance(context, CheckContext) or context.origin != origin:
            raise ValueError("Component context origin differs from inventory")
        rules, anchors = _validate_check(
            inventory.fingerprint,
            dict(metadata, records=_Records(inventory)),
            binding,
            context,
            rules,
            retained_sources or {},
        )
        # Keep only verified referenced bytes; unrelated caller data is excluded.
        supporting = {
            anchor.sha256: retained_sources[anchor.sha256] for anchor in anchors
        }
    with TemporaryFile(mode="w+b") as results:
        count = 0
        fingerprint = hashlib.sha256()
        for record in inventory.records():
            row = _check_record(record, context, rules)
            # Bind even unchanged native IDs to the exact source facts/version.
            row["facts_sha256"] = hashlib.sha256(canonical(record).encode()).hexdigest()
            line = canonical(row).encode() + b"\n"
            results.write(line)
            fingerprint.update(line)
            count += 1
        if count != metadata["record_count"] or inventory.cancelled():
            raise ValueError(
                "Component inventory count changed or processing cancelled"
            )
        assessment = dict(
            contract="triagemate-component-assessment-v1",
            inventory_sha256=inventory.fingerprint,
            origin=origin,
            binding=asdict(binding),
            observed_at=(
                context.observed_at.isoformat()
                if context
                else datetime.fromisoformat(metadata["finished_at"]).isoformat()
            ),
            context_available=context is not None,
            context=asdict(context) if context else None,
            defender_coverage="unverified",
            result_count=count,
            results_sha256=fingerprint.hexdigest(),
            rules=[asdict(rule) for rule in rules],
            sources=[
                dict(
                    sha256=inventory.fingerprint,
                    url="urn:sha256:" + inventory.fingerprint,
                    locator="complete validated Windows inventory snapshot",
                ),
                *[asdict(anchor) for anchor in dict.fromkeys(anchors)],
            ],
        )
        yield StagedAssessment(
            canonical(assessment).encode(), results, inventory, supporting
        )
