"""Generated index documents only; no public HTML copied into test fixtures."""

import pytest

from standalone.evidence_pipeline.parsing.samba_discovery import parse_index, INDEX_URL


def index(*links):
    return (
        '<table class="security_table">'
        + "".join('<a href="' + link + '">Announcement</a>' for link in links)
        + "</table>"
    ).encode()


GOOD = "/samba/security/CVE-2099-12345.html"


def test_only_canonical_announcements_selected_and_duplicates_preserved_once():
    result = parse_index(
        index(
            GOOD,
            "https://www.samba.org" + GOOD,
            "/samba/ftp/patch.patch",
            "https://example.com/CVE-2099-12345",
            "/samba/security/legacy.html",
        )
    )
    assert result.advisory_ids == ("CVE-2099-12345",)
    assert result.unresolved_links == ("/samba/security/legacy.html",)
    assert INDEX_URL == "https://www.samba.org/samba/history/security.html"


@pytest.mark.parametrize(
    "link",
    [
        "https://example.com" + GOOD,
        "//example.com" + GOOD,
        "http://www.samba.org" + GOOD,
        GOOD + "?other=1",
        GOOD + "#fragment",
        "https://user@www.samba.org" + GOOD,
        "https://www.samba.org:443" + GOOD,
        "/samba/security/../security/CVE-2099-12345.html",
    ],
)
def test_announcement_lookalikes_are_rejected(link):
    with pytest.raises(ValueError):
        parse_index(index(GOOD, link))


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"<html>unavailable</html>",
        index(GOOD) * 2,
        index(GOOD).replace(b"</table>", b""),
        index(GOOD).replace(b"<a", b"<table><a", 1),
        index(GOOD).replace(b"href=", b'href="wrong" href=', 1),
        b"\xff",
    ],
)
def test_incomplete_ambiguous_or_invalid_index_is_rejected(payload):
    with pytest.raises(ValueError):
        parse_index(payload)


def test_links_outside_security_table_do_not_expand_membership():
    payload = b'<a href="/samba/security/CVE-2099-99999.html">Other</a>' + index(GOOD)
    assert parse_index(payload).advisory_ids == ("CVE-2099-12345",)
