"""Cisco's public CSAF directory paths, without enabling document mirroring.

Publisher metadata: https://www.cisco.com/.well-known/csaf/provider-metadata.json
Listing permitted; mirror_on_CSAF_aggregators is false in inspected metadata.
"""

from dataclasses import dataclass
import re

from standalone.evidence_pipeline.parsing.csaf_index import parse_paths

BASE = "https://www.cisco.com/.well-known/csaf/"
INDEX_URL = BASE + "index.txt"
PATH = re.compile(r"[0-9]{4}/(?P<id>cisco-sa-[a-z0-9][a-z0-9_-]{0,240})\.json\Z")


@dataclass(frozen=True)
class AdvisoryFile:
    advisory_id: str
    path: str
    url: str


def advisory_file(path):
    match = PATH.fullmatch(path) if isinstance(path, str) else None
    if match is None:
        raise ValueError("Invalid Cisco CSAF index path")
    # This is the indexed filename identity; document tracking IDs need separate validation.
    return AdvisoryFile(match["id"], path, BASE + path)


def parse_index(payload):
    return parse_paths(payload, advisory_file, max_records=100_000)
