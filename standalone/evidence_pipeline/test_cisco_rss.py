"""Synthetic Cisco RSS path, authority and source-date checks."""

import pytest
from dataclasses import replace
from uuid import uuid4
from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.cisco_rss import (
    parse_feed,
    endpoint,
    validate_scope,
)

NATIVE = "cisco-sa-synthetic-AbCd"
LINK = (
    endpoint(NATIVE).replace("https://", "http://").replace(".com/", ".com:80/")
    + "?vs_type=RSS"
)


def scope():
    return SourceScope(
        str(uuid4()),
        "Cisco",
        "advisories",
        endpoint(NATIVE),
        "synthetic",
        "Explicitly synthetic Cisco route validation",
    )


def test_canonical_scope_retains_case_and_accepts_public_authority():
    assert validate_scope(scope()) == NATIVE
    assert validate_scope(replace(scope(), origin="public")) == NATIVE


@pytest.mark.parametrize(
    "change",
    [
        {"source": "Other"},
        {"input_kind": "records"},
        {"origin": "customer"},
        {"tenant_id": str(uuid4())},
        {"scope_reference": endpoint(NATIVE) + "?tracking=1"},
        {"scope_reference": endpoint(NATIVE) + "#fragment"},
        {"scope_reference": endpoint(NATIVE).replace("https://", "http://")},
        {"scope_reference": endpoint(NATIVE).replace(".com/", ".com.evil/")},
        {"scope_reference": endpoint(NATIVE).replace("/csaf/", "/other/")},
        {"scope_reference": endpoint(NATIVE).replace(NATIVE + ".json", "other.json")},
        {"scope_reference": endpoint(NATIVE).replace("AbCd.json", "abcd.json")},
    ],
)
def test_scope_rejected_before_fetch(change):
    with pytest.raises(ValueError):
        validate_scope(replace(scope(), **change))


def feed(link=LINK, identity=NATIVE):
    return f"""<rdf:RDF xmlns:rdf="https://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="https://purl.org/rss/1.0/" xmlns:dc="https://purl.org/dc/elements/1.1/"><item><title>{identity}</title><link>{link}</link><dc:date>2099-01-01 16:00:00.0</dc:date></item></rdf:RDF>""".encode()


def test_fixed_https_route_retains_publisher_identity_link_and_unzoned_date():
    (item,) = parse_feed(feed())
    assert item.advisory_id == NATIVE
    assert item.url == endpoint(NATIVE)
    assert item.source_link == LINK
    assert item.publisher_date_text == "2099-01-01 16:00:00.0"


@pytest.mark.parametrize(
    "link",
    [
        LINK.replace(".com:80", ".com.evil:80"),
        LINK.replace("http://", "file://"),
        LINK.replace(":80", ":81"),
        LINK + "#fragment",
        LINK.replace("/csaf/", "/other/"),
        LINK.replace("http://", "http://user@"),
    ],
)
def test_untrusted_urls_never_become_fetch_targets(link):
    with pytest.raises(ValueError):
        parse_feed(feed(link))


@pytest.mark.parametrize(
    "raw",
    [
        b"<bad/>",
        b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        feed().replace(b"</item>", b"<title>other</title></item>"),
        feed().replace(b"</rdf:RDF>", b"<item>" + feed().split(b"<item>", 1)[1]),
    ],
)
def test_malformed_duplicates_and_external_entities(raw):
    with pytest.raises(ValueError):
        parse_feed(raw)


def test_dotted_product_version_in_native_id_is_preserved():
    identity = "cisco-sa-synthetic-tls1.3-AbCd"
    (item,) = parse_feed(feed(endpoint(identity), identity))
    assert item.advisory_id == identity


@pytest.mark.parametrize(
    "identity",
    ["cisco-sa-a/../b", "cisco-sa-a%2fb", "cisco-sa-a?x=1", "cisco-sa-a#fragment"],
)
def test_identity_cannot_change_path_or_url_components(identity):
    with pytest.raises(ValueError):
        endpoint(identity)
