"""Generated legacy export fixtures preserve explicit operator and timeline fields."""

from dataclasses import replace
import json
from uuid import uuid4
import pytest

from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.httpd_advisories import BASE, parse_httpd


def scope():
    return SourceScope(
        str(uuid4()),
        "Apache HTTP Server",
        "advisories",
        BASE + "CVE-2099-1234.json",
        "synthetic",
        "TriageMate generated synthetic HTTP Server export",
    )


def document():
    return dict(
        data_type="CVE",
        data_format="MITRE",
        data_version="4.0",
        CVE_data_meta={"ID": "CVE-2099-1234", "STATE": "PUBLIC"},
        timeline=[{"value": "Synthetic release candidate only"}],
        affects={
            "vendor": {
                "vendor_data": [
                    {
                        "vendor_name": "Synthetic vendor",
                        "product": {
                            "product_data": [
                                {
                                    "product_name": "Synthetic HTTP Server",
                                    "version": {
                                        "version_data": [
                                            {
                                                "version_value": "9.9.1",
                                                "version_name": "9.9",
                                                "version_affected": "=",
                                            }
                                        ]
                                    },
                                }
                            ]
                        },
                    }
                ]
            }
        },
    )


def test_full_record_and_version_claims_survive():
    raw = document()
    record = parse_httpd(json.dumps(raw).encode(), scope=scope()).records[0]
    assert record.raw == raw
    assert (
        record.products[0]["product"]["version"]["version_data"][0]["version_affected"]
        == "="
    )


@pytest.mark.parametrize("change", ["identity", "format", "path", "version"])
def test_invalid_contract_rejected(change):
    chosen = scope()
    raw = document()
    if change == "public":
        chosen = replace(chosen, origin="public")
    elif change == "identity":
        raw["CVE_data_meta"]["ID"] = "CVE-2099-9999"
    elif change == "format":
        raw["data_version"] = "5.1"
    elif change == "path":
        chosen = replace(chosen, scope_reference=chosen.scope_reference + "?x=1")
    else:
        raw["affects"]["vendor"]["vendor_data"][0]["product"]["product_data"][0][
            "version"
        ]["version_data"][0]["version_value"] = 0
    with pytest.raises(ValueError):
        parse_httpd(json.dumps(raw).encode(), scope=chosen)
