"""Synthetic HTML verifies discovery identity, ambiguity and incomplete coverage."""

from dataclasses import FrozenInstanceError, replace
import pytest

from standalone.evidence_pipeline.parsing.catalog_discovery import (
    parse_search,
    search_url,
)

ID = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"


def row(identity=ID, product="Synthetic OS", index=0):
    fields = [
        "",
        f"<a onclick='goToDetails(\"{identity}\");'>Synthetic update KB9999991</a>",
        product,
        "Security Updates",
        "9/16/2026",
        "n/a",
        "1 MB",
        "Download",
    ]
    return (
        f'<tr id="{identity}_R{index}">'
        + "".join(
            f'<td id="{identity}_C{i}_R{index}">{value}</td>'
            for i, value in enumerate(fields)
        )
        + "</tr>"
    )


def payload(rows=None, count="1 - 1 of 1 (page 1 of 1)"):
    return (
        '<input id="ctl00_searchTextBox" value="KB9999991" />'
        f'<span id="ctl00_catalogBody_searchDuration">{count}</span>'
        '<table id="ctl00_catalogBody_updateMatches">'
        '<tr id="headerRow"><th>Title</th></tr>'
        + (row() if rows is None else rows)
        + "</table>"
    ).encode()


def test_discovery_retains_all_ambiguous_product_candidates():
    value = parse_search(
        payload(
            row() + row(OTHER, "Synthetic Other OS", 1), "1 - 2 of 2 (page 1 of 1)"
        ),
        kb="KB9999991",
    )
    assert value.complete and value.total == 2
    assert [hit.update_id for hit in value.hits] == [ID, OTHER]
    assert [hit.products for hit in value.hits] == [
        "Synthetic OS",
        "Synthetic Other OS",
    ]
    assert value.hits[0].url.endswith(ID)
    with pytest.raises(FrozenInstanceError):
        value.total = 1


def test_first_page_is_not_complete_coverage():
    value = parse_search(payload(count="1 - 1 of 2 (page 1 of 2)"), kb="KB9999991")
    assert not value.complete and value.total == 2 and len(value.hits) == 1


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.replace(b"KB9999991", b"KB9999992", 1),
        lambda b: b.replace(b"1 - 1 of 1", b"1 - 2 of 2"),
        lambda b: b.replace(b"1 - 1 of 1", b"0 - 0 of 0"),
        lambda b: b.replace(b"page 1 of 1", b"page 2 of 1"),
        lambda b: b.replace(b"goToDetails", b"runArbitraryScript"),
        lambda b: b.replace(
            b'goToDetails("' + ID.encode() + b'")',
            b'goToDetails("' + OTHER.encode() + b'")',
        ),
        lambda b: b.replace(b"_C5_R0", b"_C4_R0"),
        lambda b: b.replace(b"</table>", row().encode() + b"</table>"),
        lambda b: b.replace(b"</table>", b""),
        lambda b: b.replace(b"ctl00_catalogBody_updateMatches", b"unknown-table"),
        lambda b: b + b'<span id="ctl00_catalogBody_searchDuration">duplicate</span>',
    ],
)
def test_changed_identity_structure_and_coverage_fail_closed(change):
    with pytest.raises(ValueError):
        parse_search(change(payload()), kb="KB9999991")


@pytest.mark.parametrize(
    "value",
    ["kb9999991", "KB123", "KB9999991&other=1", "https://example.invalid", None],
)
def test_search_accepts_only_a_single_canonical_kb(value):
    with pytest.raises(ValueError):
        search_url(value)


def empty_payload(kb="KB9999991"):
    return (
        f'<input id="ctl00_searchTextBox" value="{kb}" />'
        '<span id="ctl00_catalogBody_noResultText">We did not find any results for </span>'
        f'<span id="ctl00_catalogBody_searchString">"{kb}"</span>'
    ).encode()


def test_explicit_empty_search_is_complete_not_applicability_evidence():
    result = parse_search(empty_payload(), kb="KB9999991")
    assert result.complete and result.total == 0 and result.hits == ()


@pytest.mark.parametrize(
    "damage",
    [
        lambda raw: raw.replace(b'"KB9999991"</span>', b'"KB9999992"</span>'),
        lambda raw: raw.replace(
            b"We did not find any results for", b"Service unavailable"
        ),
        lambda raw: raw.replace(b"</span>", b"", 1),
        lambda raw: raw + payload(),
        lambda raw: raw + b'<span id="ctl00_catalogBody_searchDuration">0</span>',
        lambda raw: raw + b'<span id="ctl00_catalogBody_noResultText">duplicate</span>',
    ],
)
def test_empty_search_requires_unambiguous_publisher_evidence(damage):
    with pytest.raises(ValueError):
        parse_search(damage(empty_payload()), kb="KB9999991")


def two_pages():
    return [
        parse_search(payload(count="1 - 1 of 2 (page 1 of 2)"), kb="KB9999991"),
        parse_search(
            payload(row(OTHER), count="2 - 2 of 2 (page 2 of 2)"), kb="KB9999991"
        ),
    ]


def test_contiguous_page_coverage_preserves_partial_and_complete_meanings():
    from standalone.evidence_pipeline.parsing.catalog_discovery import combine_pages

    first, second = two_pages()
    partial = combine_pages([first])
    assert not partial.complete
    assert (partial.collected_pages, partial.total_pages, partial.total) == (1, 2, 2)
    full = combine_pages([first, second])
    assert full.complete
    assert [hit.update_id for hit in full.hits] == [ID, OTHER]
    assert (full.collected_pages, full.total_pages) == (2, 2)
    empty = combine_pages([parse_search(empty_payload(), kb="KB9999991")])
    assert empty.complete and not empty.hits


@pytest.mark.parametrize(
    "damage",
    [
        lambda a, b: [],
        lambda a, b: [b],
        lambda a, b: [a, a],
        lambda a, b: [a, b, b],
        lambda a, b: [a, replace(b, kb="KB9999992")],
        lambda a, b: [a, replace(b, total=3)],
        lambda a, b: [a, replace(b, pages=3)],
        lambda a, b: [a, replace(b, first=3, last=3)],
        lambda a, b: [a, replace(b, first=1, last=1)],
        lambda a, b: [a, replace(b, hits=a.hits)],
    ],
)
def test_page_gaps_overlap_identity_changes_and_duplicates_reject(damage):
    from standalone.evidence_pipeline.parsing.catalog_discovery import combine_pages

    with pytest.raises(ValueError):
        combine_pages(damage(*two_pages()))


def test_search_page_url_uses_publisher_zero_based_parameter():
    assert search_url("KB9999991", page=1).endswith("?q=KB9999991")
    assert search_url("KB9999991", page=2).endswith("?q=KB9999991&p=1")
    for page in [0, -1, True, "2", 1.5]:
        with pytest.raises(ValueError):
            search_url("KB9999991", page=page)
