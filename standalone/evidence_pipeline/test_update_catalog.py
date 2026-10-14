"""Generated Catalog-shaped HTML; no update binaries or Microsoft tenant access."""

from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing.update_catalog import (
    endpoint,
    parse_detail,
    FIELDS,
)

ID = "11111111-1111-4111-8111-111111111111"
NEXT = "22222222-2222-4222-8222-222222222222"


def payload():
    values = dict(
        title="Synthetic Windows update KB9999991",
        updated_at="9/16/2026",
        description="TriageMate generated synthetic update metadata",
        architecture="n/a",
        classification="Security Updates",
        products="Synthetic OS",
        kb_articles="9999991",
    )
    fields = "".join(
        f'<div id="{element}">{label}{values[field]}</div>'
        for field, (element, label) in FIELDS.items()
    )
    return (
        f'<html><span id="ScopedViewHandler_UpdateID">{ID}</span>{fields}'
        '<div id="supersedesInfo"><div>Synthetic earlier update (KB9999990)</div></div>'
        f'<div id="supersededbyInfo"><div><a href="ScopedViewInline.aspx?updateid={NEXT}">Synthetic later update</a></div></div></html>'
    ).encode()


def test_explicit_source_relationships_preserve_missing_identity():
    value = parse_detail(payload(), identity=ID)
    assert value["architecture"] == "n/a"
    assert value["replaces"] == [
        {"update_id": None, "title": "Synthetic earlier update (KB9999990)"}
    ]
    assert value["replaced_by"] == [
        {"update_id": NEXT, "title": "Synthetic later update"}
    ]
    assert endpoint(ID).endswith(ID)


@pytest.mark.parametrize(
    "change",
    ["mismatch", "missing", "duplicate", "foreign_link", "malformed", "empty", "self"],
)
def test_changed_or_unexplained_catalog_metadata_fails_closed(change):
    raw = payload()
    if change == "mismatch":
        raw = raw.replace(ID.encode(), str(uuid4()).encode())
    elif change == "missing":
        raw = raw.replace(b"supersedesInfo", b"unknownSection")
    elif change == "duplicate":
        raw += b'<div id="ScopedViewHandler_UpdateID">duplicate</div>'
    elif change == "foreign_link":
        raw = raw.replace(
            b"ScopedViewInline.aspx?updateid=", b"https://example.invalid/?updateid="
        )
    elif change == "malformed":
        raw = raw.replace(NEXT.encode(), b"not-a-uuid")
    elif change == "empty":
        raw = raw.replace(b"<div>Synthetic earlier update (KB9999990)</div>", b"")
    else:
        raw = raw.replace(NEXT.encode(), ID.encode())
    with pytest.raises(ValueError):
        parse_detail(raw, identity=ID)


def test_explicit_no_relationships_is_different_from_missing_section():
    raw = payload().replace(b"<div>Synthetic earlier update (KB9999990)</div>", b"n/a")
    assert parse_detail(raw, identity=ID)["replaces"] == []


def test_invalid_date_and_truncated_replacement_section_are_rejected():
    for raw in (
        payload().replace(b"9/16/2026", b"2/31/2026"),
        payload().split(b"</a>")[0],
    ):
        with pytest.raises(ValueError):
            parse_detail(raw, identity=ID)
