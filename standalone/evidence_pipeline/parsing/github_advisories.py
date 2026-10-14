"""GitHub's own OSV export, pinned to a repository commit and source path.

Format/licence: https://github.com/github/advisory-database
GitHub database_specific extensions are retained, not treated as stable APIs.
"""

import re

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.osv import parse_osv

BASE = "https://raw.githubusercontent.com/github/advisory-database/"
GHSA = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
PATH = re.compile(
    r"advisories/(github-reviewed|unreviewed)/[0-9]{4}/(?:0[1-9]|1[0-2])/"
    + r"(?P<id>"
    + GHSA
    + r")/(?P=id)\.json\Z"
)


def endpoint(commit, path):
    if (
        not isinstance(commit, str)
        or not re.fullmatch(r"[a-f0-9]{40}", commit)
        or int(commit, 16) == 0
        or not isinstance(path, str)
        or PATH.fullmatch(path) is None
    ):
        raise ValueError(
            "GitHub advisory requires a pinned commit and exact advisory path"
        )
    return BASE + commit + "/" + path


def parse_github_advisory(payload, *, scope):
    if (
        not isinstance(scope, SourceScope)
        or (scope.source, scope.input_kind) != ("GitHub", "advisories")
        or scope.tenant_id is not None
        or scope.origin not in {"synthetic", "public"}
        or not scope.scope_reference.startswith(BASE)
    ):
        raise ValueError("GitHub advisory requires its non-tenant publisher scope")
    parts = scope.scope_reference[len(BASE) :].split("/", 1)
    if len(parts) != 2 or endpoint(*parts) != scope.scope_reference:
        raise ValueError("GitHub source URL differs from its pinned path")
    feed = parse_osv(payload, scope=scope)
    if feed.records[0].advisory_id != PATH.fullmatch(parts[1]).group("id"):
        raise ValueError("GitHub response contains a different advisory identity")
    return feed
