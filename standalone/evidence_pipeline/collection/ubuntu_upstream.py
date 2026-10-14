"""Plan explicit upstream collection without converting relationships into aliases."""

from dataclasses import dataclass

from standalone.evidence_pipeline.contracts import SourceScope
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_inputs import CVE_PATTERN
from standalone.evidence_pipeline.collection.public_transport import endpoint
from standalone.evidence_pipeline.parsing.ubuntu_advisories import (
    parse_ubuntu,
    endpoint as ubuntu_endpoint,
)


@dataclass(frozen=True)
class UpstreamPlan:
    targets: tuple[SourceScope, ...]
    unresolved: tuple[str, ...]


def plan(snapshot):
    if not snapshot.complete:
        raise ValueError("Upstream discovery requires a complete source snapshot")
    feed = parse_ubuntu(snapshot.payload, scope=snapshot.scope)
    targets, unresolved, seen = [], [], set()
    native = feed.records[0].advisory_id
    for upstream in feed.records[0].raw.get("upstream", []):
        if upstream in seen:
            continue
        seen.add(upstream)
        if upstream == native:
            unresolved.append(upstream)
            continue
        if CVE_PATTERN.fullmatch(upstream):
            source, kind = "CVE", "records"
            url = endpoint(source, upstream, input_kind=kind)
            provenance = (
                "CVE Program public record; https://github.com/CVEProject/cvelistV5"
            )
        else:
            try:
                url = ubuntu_endpoint(upstream)
            except ValueError:
                unresolved.append(upstream)
                continue
            source, kind = "Ubuntu", "advisories"
            provenance = "Canonical Ubuntu Vulnerability Data; CC-BY-SA-4.0; https://github.com/canonical/ubuntu-security-notices"
        targets.append(
            SourceScope(
                stable_id("ubuntu-upstream-source", snapshot.scope.origin, url),
                source,
                kind,
                url,
                snapshot.scope.origin,
                "TriageMate generated synthetic upstream collection fixture"
                if snapshot.scope.origin == "synthetic"
                else provenance,
            )
        )
    return UpstreamPlan(tuple(targets), tuple(unresolved))


def collect(
    snapshot,
    output,
    *,
    limit=10,
    after=None,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Retired Ubuntu collection entry point; see the source archive."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Ubuntu")


def _validate_mode(
    snapshot, limit, synthetic_payloads, allow_network, replay_only, import_records
):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Upstream collection limit must be 1 through 100")
    if any(
        type(flag) is not bool for flag in (allow_network, replay_only, import_records)
    ) or (allow_network and (snapshot.scope.origin != "public" or replay_only)):
        raise ValueError("Invalid upstream collection mode")
    if synthetic_payloads is not None and (
        snapshot.scope.origin != "synthetic" or not isinstance(synthetic_payloads, dict)
    ):
        raise ValueError("Synthetic upstream fixtures require a synthetic source")


def _output(output, replay_only):
    import os
    from pathlib import Path
    from standalone.evidence_pipeline.collection.osv_query_collection import _sync

    root = Path(output)
    if root.is_symlink():
        raise ValueError("Upstream output cannot be a symlink")
    if not root.exists():
        if replay_only:
            raise ValueError("Upstream replay requires existing output")
        root.mkdir(mode=0o700)
        _sync(root.parent)
    if (
        not root.is_dir()
        or root.stat().st_mode & 0o077
        or root.stat().st_uid != os.getuid()
    ):
        raise ValueError("Upstream output requires an owner-only directory")
    return root


def _attempt(parent, scope):
    return stable_id(
        "ubuntu-upstream-attempt",
        parent.execution_id,
        parent.input_fingerprint,
        scope.connection_id,
    )


def _collect_target(
    parent, scope, root, fixtures, allow_network, replay_only, import_records
):
    """Retired Ubuntu collection entry point; see the source archive."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Ubuntu")


def collect_tree(
    snapshot,
    output,
    *,
    limit=10,
    max_nodes=1000,
    synthetic_payloads=None,
    allow_network=False,
    replay_only=False,
    import_records=False,
):
    """Retired Ubuntu collection entry point; see the source archive."""
    from standalone.evidence_pipeline.collection.collection_scope import (
        require_active_collection,
    )

    require_active_collection("Ubuntu")
