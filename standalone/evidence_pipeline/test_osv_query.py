"""Synthetic paginated HTTP; no upstream access or database mutation."""

import pytest
from standalone.evidence_pipeline.parsing import osv_query as query


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"name": "x"},
        {"purl": "https://private.invalid/pkg"},
        {"purl": "pkg:pypi/x", "name": "x"},
        {"purl": "pkg:pypi/x@1", "version": "1"},
        {"name": "x\n", "ecosystem": "PyPI"},
    ],
)
def test_invalid_query_contract(kwargs):
    with pytest.raises(ValueError):
        query.package_query(**kwargs)


def test_purl_or_case_sensitive_name_preserved():
    assert query.package_query(purl="pkg:npm/%40scope/name@1") == {
        "package": {"purl": "pkg:npm/%40scope/name@1"}
    }
    assert query.package_query(name="Example", ecosystem="PyPI", version="1") == {
        "package": {"name": "Example", "ecosystem": "PyPI"},
        "version": "1",
    }
