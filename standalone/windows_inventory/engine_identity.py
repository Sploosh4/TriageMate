"""Exact source equivalences for interpretation-preserving structural changes.

These aliases preserve existing replay IDs across Sprint 3's database-version
routing and package-import changes. Only an exact complete engine-source fingerprint qualifies.
Any other source change retains its new identity. Extend only after comparing
all source differences and proving retained replay equivalence; never use a
version label or partial source match as an equivalence claim.
"""

# Source revision and measured fingerprints are documented in engine-identity.json.
import json
from pathlib import Path


def canonical_fingerprint(kind: str, fingerprint: str) -> str:
    records = json.loads(Path(__file__).with_name("engine-identity.json").read_text())
    record = records["equivalences"][kind]
    if fingerprint == record["refactored"]:
        return str(record["predecessor"])
    return fingerprint
