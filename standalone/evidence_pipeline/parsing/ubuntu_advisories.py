"""Canonical OSV exports with fixed source routes and native notice identity.

Publisher format and CC-BY-SA-4.0: https://github.com/canonical/ubuntu-security-notices
Upstream identifiers remain upstream relationships, never manufactured aliases.
"""

import re

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.osv import parse_osv

BASE = "https://raw.githubusercontent.com/canonical/ubuntu-security-notices/main/osv/"


def endpoint(advisory_id):
    if not isinstance(advisory_id, str):
        raise ValueError("Ubuntu requires a native advisory identifier")
    cve = re.fullmatch(r"UBUNTU-CVE-([0-9]{4})-[0-9]{4,19}", advisory_id)
    notice = re.fullmatch(r"(USN|LSN)-[0-9]{1,10}-[0-9]{1,5}", advisory_id)
    if cve:
        return BASE + "cve/" + cve[1] + "/" + advisory_id + ".json"
    if notice:
        return BASE + notice[1].lower() + "/" + advisory_id + ".json"
    raise ValueError("Unsupported Ubuntu native advisory identifier")


def repository_endpoint(commit, path, advisory_id):
    from standalone.evidence_pipeline.parsing.github_discovery import object_id

    object_id(commit)
    expected = "osv/" + endpoint(advisory_id).removeprefix(BASE)
    if path != expected:
        raise ValueError("Ubuntu repository path differs from native advisory ID")
    return BASE.removesuffix("main/osv/") + commit + "/" + expected


def validate_url(advisory_id, url):
    if url == endpoint(advisory_id):
        return
    prefix = BASE.removesuffix("main/osv/")
    if not isinstance(url, str) or not url.startswith(prefix):
        raise ValueError("Ubuntu requires its fixed publisher URL")
    parts = url[len(prefix) :].split("/", 1)
    if len(parts) != 2 or repository_endpoint(parts[0], parts[1], advisory_id) != url:
        raise ValueError("Ubuntu source URL differs from its fixed path")


def parse_ubuntu(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("Ubuntu", "advisories")
        or scope.tenant_id is not None
        or scope.origin not in {"public", "synthetic"}
    ):
        raise ValueError("Ubuntu requires its non-tenant publisher scope")
    filename = scope.scope_reference.rsplit("/", 1)[-1]
    if not filename.endswith(".json"):
        raise ValueError("Ubuntu source URL differs from its fixed path")
    validate_url(filename[:-5], scope.scope_reference)
    feed = parse_osv(payload, scope=scope)
    if feed.records[0].advisory_id != filename[:-5]:
        raise ValueError("Ubuntu response contains a different advisory identity")
    return feed
