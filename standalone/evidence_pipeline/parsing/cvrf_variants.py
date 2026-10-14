"""Preserve metadata variants without selecting a conflicting publisher value."""

from collections import defaultdict
import re

from standalone.evidence_pipeline.parsing.cvrf_identity import native_identity
from standalone.evidence_pipeline.parsing.public_inputs import _array, _object

METADATA = frozenset({"CWE", "Ordinal", "RevisionHistory"})


def variants(values):
    groups = defaultdict(list)
    for value in _array(values):
        value = _object(value)
        identity, _ = native_identity(value.get("CVE"))
        groups[identity].append(value)
    for identity, entries in groups.items():
        if len(entries) == 1:
            yield identity, entries[0], None
            continue
        ordinals = [entry.get("Ordinal") for entry in entries]
        if any(
            not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value, re.ASCII)
            for value in ordinals
        ) or len({int(value) for value in ordinals}) != len(entries):
            raise ValueError(
                "Duplicate CVRF vulnerability requires distinct source ordinals"
            )
        unchanged = {k: v for k, v in entries[0].items() if k not in METADATA}
        if any(
            {k: v for k, v in entry.items() if k not in METADATA} != unchanged
            for entry in entries[1:]
        ):
            raise ValueError(
                "Duplicate CVRF vulnerability has differing operational claims"
            )
        common = {
            k: v
            for k, v in entries[0].items()
            if all(k in entry and entry[k] == v for entry in entries[1:])
        }
        yield identity, common, entries
