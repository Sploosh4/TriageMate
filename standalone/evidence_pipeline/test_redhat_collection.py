"""Exact index-path routing and immutable synthetic Red Hat retry bundles."""

import pytest
from standalone.evidence_pipeline.collection.public_transport import endpoint


@pytest.mark.parametrize(
    "extra",
    [
        dict(cve="CVE-2099-1234"),
        dict(month="2099-Jan"),
        dict(advisory_id="RHSA-2099:1234"),
        dict(repository_commit="a" * 40),
        dict(repository_path="x"),
    ],
)
def test_redhat_rejects_mixed_routes(extra):
    with pytest.raises(ValueError):
        endpoint(
            "Red Hat",
            input_kind="advisories",
            vendor_path="2099/rhsa-2099_1234.json",
            **extra,
        )
    with pytest.raises(ValueError):
        endpoint(
            "Ubuntu", input_kind="advisories", vendor_path="2099/rhsa-2099_1234.json"
        )
