"""Explicit synthetic announcements; no third-party advisory fixtures."""

import pytest

from standalone.evidence_pipeline.parsing import samba_advisories as samba

CVE = "CVE-2099-12345"
BODY = """
==================================================
== Subject:     Synthetic conditional vulnerability
==
== CVE ID#:     CVE-2099-12345
==
== Versions:    Synthetic releases before 9.2;
==              only with option X enabled
==
== Summary:     Synthetic example with &#x27;quoted&#x27;
==              configuration &amp; an unknown condition.
==================================================

===========
Description
===========
Synthetic description. CVE-2099-56789 is a related issue, not this identity.

==================
Patch Availability
==================
Synthetic 9.2 candidate exists; no final release is asserted.

==========
Workaround
==========
Synthetic condition: role = member
"""


def announcement(body=BODY):
    return (
        '<!DOCTYPE html PUBLIC "example" "https://invalid.example/external.dtd">'
        f"<html><body><H2>{CVE}.html:</H2><pre>{body}</pre></body></html>"
    ).encode()


def test_preserves_conditions_sections_and_original_bytes():
    payload = announcement()
    result = samba.parse_samba(payload, cve_id=CVE)
    assert result.cve_id == CVE
    assert result.versions_text == (
        "Synthetic releases before 9.2; only with option X enabled"
    )
    assert result.summary == (
        "Synthetic example with 'quoted' configuration & an unknown condition."
    )
    assert result.sections == (
        (
            "Description",
            "Synthetic description. CVE-2099-56789 is a related issue, not this identity.",
        ),
        (
            "Patch Availability",
            "Synthetic 9.2 candidate exists; no final release is asserted.",
        ),
        ("Workaround", "Synthetic condition: role = member"),
    )
    assert result.raw_payload == payload
    assert not hasattr(result, "fixed_version")


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\xff",
        b"<html>synthetic unavailable page</html>",
        announcement().replace(CVE.encode(), b"CVE-2099-22222", 1),
        announcement().replace(
            b"== CVE ID#:     " + CVE.encode(), b"== CVE ID#:     CVE-2099-22222"
        ),
        announcement().replace(b"</pre>", b""),
        announcement().replace(b"</pre>", b"</pre><pre>other</pre>"),
        announcement().replace(b"Synthetic description.", b"<script>bad</script>"),
        announcement().replace(b"== Subject:", b"== Subject: duplicate\n== Subject:"),
        announcement().replace(b"Description", b"Unrecognized format"),
    ],
)
def test_rejects_missing_mismatched_and_ambiguous_documents(payload):
    with pytest.raises(ValueError):
        samba.parse_samba(payload, cve_id=CVE)


@pytest.mark.parametrize("identity", [None, "../secret", "CVE-2099-12345\n"])
def test_rejects_invalid_requested_identity(identity):
    with pytest.raises(ValueError):
        samba.parse_samba(announcement(), cve_id=identity)


def test_duplicate_section_claims_remain_separate():
    result = samba.parse_samba(
        announcement(
            BODY
            + "\n==========\nWorkaround\n==========\nA later synthetic condition.\n"
        ),
        cve_id=CVE,
    )
    assert [text for title, text in result.sections if title == "Workaround"] == [
        "Synthetic condition: role = member",
        "A later synthetic condition.",
    ]
