"""Explicit upstream edges, separate publishers and bounded follow-up identity."""

from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4
import pytest
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from .test_ubuntu_advisories import scope
from .test_osv import document
from standalone.evidence_pipeline.collection.ubuntu_upstream import plan


def snapshot(upstream, identity="USN-9999-1"):
    raw = dict(
        document(),
        id=identity,
        aliases=["CVE-2099-9999"],
        related=["CVE-2099-8888"],
        upstream=upstream,
    )
    now = datetime.now(timezone.utc)
    return PublicSnapshot(
        scope(identity),
        str(uuid4()),
        now,
        now,
        "success",
        True,
        json.dumps(raw).encode(),
    )


def test_explicit_upstream_chain_preserves_publisher_and_origin():
    value = snapshot(["UBUNTU-CVE-2099-1234", "CVE-2099-5678", "UBUNTU-CVE-2099-1234"])
    result = plan(value)
    assert [(s.source, s.input_kind, s.origin) for s in result.targets] == [
        ("Ubuntu", "advisories", "synthetic"),
        ("CVE", "records", "synthetic"),
    ]
    assert all("synthetic" in s.provenance for s in result.targets)
    assert not result.unresolved
    assert plan(value) == result
    assert plan(snapshot(["CVE-2099-5678"])).targets[0] == result.targets[1]


def test_no_prefix_stripping_or_links_from_aliases_prose_or_related():
    assert plan(snapshot([])).targets == ()
    value = snapshot(
        ["USN-9999-1", "https://evil.example", "CVE-2099-bad", "UNKNOWN-1"]
    )
    result = plan(value)
    assert not result.targets
    assert result.unresolved == (
        "USN-9999-1",
        "https://evil.example",
        "CVE-2099-bad",
        "UNKNOWN-1",
    )


def test_failed_source_cannot_generate_followups():
    value = snapshot(["CVE-2099-1234"])
    with pytest.raises(ValueError):
        plan(
            replace(
                value,
                complete=False,
                outcome="failure",
                payload=b"",
                error_code="public_unavailable",
            )
        )
