"""Codec titles and unspecified bounds cannot supply package-version evidence."""

from copy import deepcopy

import pytest

from .test_store import db as db
from .test_store_media_migration import sql as sql
from .test_media_inventory_match import facts, source
from standalone.evidence_pipeline.assessment.media_inventory_match import (
    MEDIA_PRODUCTS,
    evaluate_media,
)
from standalone.evidence_pipeline.assessment.media_cpe_match import (
    evaluate_configurations,
)


@pytest.mark.parametrize(
    "product", ["Microsoft.WebpImageExtension", "Microsoft.MPEG2VideoExtension"]
)
@pytest.mark.parametrize(
    "case", ["windows_product", "unspecified_version", "staged_only"]
)
def test_codec_comparison_requires_exact_product_version_and_installed_evidence(
    sql, product, case
):
    f = facts()
    name, cpe = MEDIA_PRODUCTS[product]
    f.update(product=product, name=product, family_name=product + "_8wekyb3d8bbwe")
    f["manifest"].update(name=product, display_name=name)
    s = source()
    s["title"] = name + " Synthetic Vulnerability"
    s["affected"][0]["product"] = name
    s["cpeApplicability"] = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": f"cpe:2.3:a:microsoft:{cpe}:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0.0.0",
                            "versionEndExcluding": "2.0.0.0",
                        }
                    ],
                }
            ]
        }
    ]
    if case == "windows_product":
        s["affected"][0]["product"] = "Windows 11 Version 24H2"
        s["cpeApplicability"][0]["nodes"][0]["cpeMatch"][0]["criteria"] = (
            "cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*"
        )
    elif case == "unspecified_version":
        s["affected"][0]["versions"] = [{"version": "-", "status": "affected"}]
        entry = s["cpeApplicability"][0]["nodes"][0]["cpeMatch"][0]
        entry.pop("versionEndExcluding")
        entry["versionStartIncluding"] = "-"
    else:
        f["user_states"] = [{"install_state": "Staged"}]
    original = deepcopy((s, f))
    expected = evaluate_media(s, provider="microsoft", facts=f)
    cpe_expected = evaluate_configurations(s["cpeApplicability"], f)
    actual, cpe_actual = sql(s, f)
    assert {key: actual[key] for key in expected} == expected
    assert actual["state"] == actual["applicability"] == "unknown"
    assert cpe_actual == cpe_expected
    assert cpe_actual["state"] == "unknown"
    assert (s, f) == original
