"""Synthetic Store media boundaries preserve unknown full applicability."""

from copy import deepcopy
import pytest
from standalone.evidence_pipeline.assessment.media_inventory_match import (
    MEDIA_PRODUCTS,
    evaluate_media,
)
from standalone.evidence_pipeline.assessment.media_cpe_match import (
    evaluate_configurations,
)
from .test_media_inventory_match import facts, source


@pytest.mark.parametrize("product", list(MEDIA_PRODUCTS)[1:])
@pytest.mark.parametrize(
    "version,expected",
    [("1.1.0.0", "affected"), ("1.1.60961.0", "unknown"), ("2.0.0.0", "unknown")],
)
def test_explicit_store_media_version_rules(product, version, expected):
    f = facts()
    target, cpe = MEDIA_PRODUCTS[product]
    f.update(
        product=product,
        name=product,
        version=version,
        family_name=product + "_8wekyb3d8bbwe",
    )
    f["manifest"].update(name=product, version=version, display_name=target)
    s = source()
    s["affected"][0]["product"] = target
    s["affected"][0]["versions"][0]["version"] = "1.1.0.0"
    original = deepcopy((s, f))
    result = evaluate_media(s, provider="microsoft", facts=f)
    assert result["state"] == expected and result["applicability"] == "unknown"
    assert (s, f) == original
    config = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": f"cpe:2.3:a:microsoft:{cpe}:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.1.0.0",
                            "versionEndExcluding": "1.1.60961.0",
                        }
                    ],
                }
            ]
        }
    ]
    assert evaluate_configurations(config, f)["state"] == (
        "matched" if expected == "affected" else "excluded"
    )
    f["manifest"]["display_name"] = "Synthetic similar product"
    assert evaluate_media(s, provider="microsoft", facts=f)["state"] == "unknown"
    assert evaluate_configurations(config, f)["state"] == "unknown"
