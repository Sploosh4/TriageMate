"""Separate publisher advisory identifiers from vulnerability identities."""

import re

from standalone.evidence_pipeline.parsing.public_inputs import _cve, _text


def native_identity(value):
    """Return exact source identity and an independently valid optional CVE."""
    value = _text(value)
    if re.fullmatch(r"ADV[0-9]{6}", value, flags=re.ASCII):
        return value, None
    if re.fullmatch(
        r"CVE-[0-9]{4}-[0-9]{4,}(?:-M| - M| mariner - do not use this one)",
        value,
        flags=re.ASCII,
    ):
        # Observed MSRC publisher identities are not standard CVE identifiers.
        # Validate the shape without making the unsuffixed value an association.
        return value, None
    return value, _cve(value)
