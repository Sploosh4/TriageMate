"""Explicitly synthetic Apache website XML, with no network dependency."""

import pytest
from standalone.evidence_pipeline.parsing.tomcat_advisories import parse_tomcat


def fixture():
    return b"""<document><properties><title>Apache Tomcat 11 vulnerabilities</title></properties><body>
    <section name="Fixed in Apache Tomcat 11.0.9" rtext="2099-09-23">
    <p><strong>Low: Synthetic issue</strong><cve>CVE-2099-9999991</cve></p>
    <p>An earlier fix for <cve>CVE-2099-9999990</cve> was incomplete.</p>
    <p>Fixed with <hashlink hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"/>.</p>
    <p>Affects: 11.0.0-M1 to 11.0.8<br/>Only when a synthetic option is enabled.</p>
    <p><strong>Important: Another synthetic issue</strong><cve>CVE-2099-9999992</cve></p>
    <p>Affects: 11.0.7?</p></section>
    <section name="Not a Tomcat vulnerability"><p><strong>Synthetic workaround</strong><cve>CVE-2099-9999993</cve></p>
    <p>No Tomcat fix is claimed.</p></section></body></document>"""


def test_preserves_conditions_relationships_and_section_meaning():
    first, second, third = parse_tomcat(fixture(), series="11")
    assert first.fixed_release == "11.0.9"
    assert first.related_cves == ("CVE-2099-9999990",)
    assert first.commit_references == ("a" * 40,)
    assert "synthetic option" in first.affected_text[0]
    assert second.affected_text == ("Affects: 11.0.7?",)
    assert third.fixed_release is None
    assert third.section == "Not a Tomcat vulnerability"
    assert "<br" in first.source_xml


@pytest.mark.parametrize(
    "bad",
    [
        b'<!DOCTYPE document [<!ENTITY x "expanded">]><document>&x;</document>',
        b'<!DOCTYPE document SYSTEM "https://example.invalid/source"><document/>',
        b"<document>",
        b"<html><body>Changed format</body></html>",
        fixture().replace(b"CVE-2099-9999991", b"not-a-cve"),
        fixture().replace(b"11.0.9", b"10.0.9"),
        fixture().replace(
            b"Apache Tomcat 11 vulnerabilities", b"Apache Tomcat 10 vulnerabilities"
        ),
        b"<document><properties><title>Apache Tomcat 11 vulnerabilities</title></properties><body/></document>",
    ],
)
def test_rejects_unsafe_or_ambiguous_documents(bad):
    with pytest.raises(ValueError):
        parse_tomcat(bad, series="11")


def test_title_cve_reference_does_not_replace_notice_identity():
    payload = fixture().replace(
        b"Low: Synthetic issue",
        b"Low: Earlier fix for <cve>CVE-2099-9999990</cve> was incomplete",
    )
    first = parse_tomcat(payload, series="11")[0]
    assert first.cve_id == "CVE-2099-9999991"
    assert first.related_cves == ("CVE-2099-9999990",)


def test_unreleased_candidate_context_is_preserved_for_every_notice():
    payload = fixture().replace(
        b'<section name="Fixed in Apache Tomcat 11.0.9" rtext="2099-09-23">',
        b'<section name="Fixed in Apache Tomcat 11.0.9" rtext="2099-09-23"><p>This synthetic candidate was not released. The fix is available in a later release.</p>',
    )
    first, second, third = parse_tomcat(payload, series="11")
    assert first.section_context == second.section_context
    assert "not released" in first.section_context[0]
    assert third.section_context == ()
    assert first.fixed_release == "11.0.9"  # Publisher section label, not availability.
