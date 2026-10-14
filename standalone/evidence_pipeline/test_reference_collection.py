"""Reference routes and source-specific bounds across snapshot and durable replay."""

import pytest
from standalone.evidence_pipeline.collection import public_transport
from .test_reference_store import snapshot


@pytest.mark.parametrize("kind", ["exploit", "ctid", "attack"])
def test_fixed_reference_route_rejects_filters(kind):
    scope = snapshot(kind).scope
    assert (
        public_transport.endpoint(scope.source, input_kind=scope.input_kind)
        == scope.scope_reference
    )
    for options in (
        dict(cve="CVE-2099-1234"),
        dict(month="2026-Sep"),
        dict(advisory_id="OSV-1"),
        dict(repository_commit="a" * 40),
    ):
        with pytest.raises(ValueError):
            public_transport.endpoint(
                scope.source, input_kind=scope.input_kind, **options
            )
