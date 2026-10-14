"""Generated publication summaries, including older-month revisions."""

from io import BytesIO
import json
import pytest
from standalone.evidence_pipeline.parsing.msrc_publications import publications, CONTEXT


def entry(month="2099-Jan"):
    return dict(
        ID=month,
        Alias=month,
        DocumentTitle="Synthetic publication",
        Severity=None,
        InitialReleaseDate="2099-01-01T00:00:00Z",
        CurrentReleaseDate="2099-03-01T00:00:00Z",
        CvrfUrl="https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + month,
    )


def parse(value):
    return list(publications(BytesIO(json.dumps(value).encode())))


def test_original_dates_and_month_are_distinct_and_order_independent():
    raw = entry()
    result = parse({"value": [raw], "@odata.context": CONTEXT})[0]
    assert result.publication_id == "2099-Jan"
    assert result.current_release.month == 3
    assert result.initial_release.month == 1
    assert result.source_fields == raw
    assert parse({"@odata.context": CONTEXT, "value": []}) == []


@pytest.mark.parametrize(
    "change",
    [
        {"ID": "2099-01"},
        {"Alias": "2099-Feb"},
        {"CvrfUrl": "https://example.invalid/cvrf/2099-Jan"},
        {"CvrfUrl": "http://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2099-Jan"},
        {"DocumentTitle": " "},
        {"Severity": []},
        {"CurrentReleaseDate": "2098-01-01T00:00:00Z"},
        {"CurrentReleaseDate": "2099-03-01T00:00:00"},
        {"InitialReleaseDate": None},
        {"extra": True},
    ],
)
def test_invalid_source_statement_is_rejected(change):
    with pytest.raises(ValueError):
        parse({"@odata.context": CONTEXT, "value": [{**entry(), **change}]})


@pytest.mark.parametrize(
    "value",
    [
        {"value": []},
        {"@odata.context": CONTEXT, "value": {}},
        {"@odata.context": CONTEXT, "value": [entry(), entry()]},
        {"@odata.context": CONTEXT, "value": [entry()], "@odata.nextLink": "more"},
    ],
)
def test_incomplete_or_duplicate_index_is_rejected(value):
    with pytest.raises(ValueError):
        parse(value)


def test_late_errors_and_cancellation_cannot_complete_index():
    raw = json.dumps({"@odata.context": CONTEXT, "value": [entry()]}).encode()
    with pytest.raises(ValueError):
        list(publications(BytesIO(raw + b"{}")))
    with pytest.raises(ValueError, match="cancel"):
        list(publications(BytesIO(raw), cancelled=lambda: True))
    with pytest.raises(ValueError):
        list(publications(BytesIO(b'{"value":[],"value":[],"@odata.context":"x"}')))


@pytest.mark.parametrize("identity", ["2099-May-B", "2099-FEB"])
def test_source_identifier_spelling_and_supplement_are_preserved(identity):
    raw = entry(identity)
    result = parse({"@odata.context": CONTEXT, "value": [raw]})[0]
    assert result.publication_id == identity
    assert result.url.endswith("/" + identity)
    assert result.source_fields == raw


@pytest.mark.parametrize("field", ["InitialReleaseDate", "CurrentReleaseDate"])
def test_publication_rejects_offset_minute_overflow(field):
    with pytest.raises(ValueError, match="Invalid MSRC release date"):
        parse(
            {
                "@odata.context": CONTEXT,
                "value": [{**entry(), field: "2099-02-01T00:30:00+00:60"}],
            }
        )
