"""Generated WA SOC-shaped Markdown; no retained government text in fixtures."""

from dataclasses import replace
from uuid import uuid4
import pytest
from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.wasoc_advisories import (
    repository_endpoint,
    parse_wasoc,
    validate_scope,
)

COMMIT = "a" * 40
PATH = "docs/advisories/20990101001-Synthetic-Advisory.md"
BODY = b"""# Synthetic advisory - 20990101001

## Overview
Synthetic CVE-2099-12345; CVE-2099-12345 is repeated.

## What is vulnerable?
A vendor link mentions CVE-2099-56789; applicability is not established.

## What has been observed?
No reports in this explicitly synthetic example. This is not a universal negative.

## Recommendation
Apply vendor instructions when applicable, preserving the condition.
"""


def scope():
    return SourceScope(
        str(uuid4()),
        "WA SOC",
        "advisories",
        repository_endpoint(COMMIT, PATH, "20990101001"),
        "synthetic",
        "Explicitly synthetic WA SOC-shaped Markdown",
    )


def test_native_identity_original_prose_and_references_remain_distinct():
    assert validate_scope(scope()) == "20990101001"
    result = parse_wasoc(BODY, scope=scope())
    assert result.advisory_id == "20990101001"
    assert result.title == "Synthetic advisory"
    assert result.referenced_cves == ("CVE-2099-12345", "CVE-2099-56789")
    assert result.raw_payload == BODY
    assert len(result.sections) == 4
    assert "not a universal negative" in result.sections[2][1]
    assert not hasattr(result, "fixed_version")
    assert not hasattr(result, "publication_date")
    assert not hasattr(result, "exploited")


@pytest.mark.parametrize(
    "change",
    [
        {"source": "CISA"},
        {"input_kind": "records"},
        {"origin": "customer"},
        {"tenant_id": str(uuid4())},
        {"scope_reference": "https://soc.cyber.wa.gov.au/advisories/example"},
        {
            "scope_reference": repository_endpoint(COMMIT, PATH, "20990101001").replace(
                COMMIT, "main"
            )
        },
    ],
)
def test_unsupported_authority_or_mutable_route(change):
    with pytest.raises(ValueError):
        validate_scope(replace(scope(), **change))
    with pytest.raises(ValueError):
        parse_wasoc(BODY, scope=replace(scope(), **change))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        BODY + b"\n# Another advisory - 20990101001",
        BODY + b"\x00",
        b"\xff",
        b"# Synthetic advisory - 20990101001\n",
    ],
)
def test_wrong_identity_empty_or_malformed_document(body):
    with pytest.raises(ValueError):
        parse_wasoc(body, scope=scope())


@pytest.mark.parametrize(
    "path",
    [
        "../docs/advisories/20990101001-X.md",
        PATH + "?x=1",
        PATH.replace("Synthetic", "%2e%2e"),
        PATH.replace("20990101001", "20990101002"),
    ],
)
def test_fixed_route_rejects_path_confusion(path):
    with pytest.raises(ValueError):
        repository_endpoint(COMMIT, path, "20990101001")


@pytest.mark.parametrize(
    "name", [".NET 9.3", "Synthetic-(RCE)", "Synthetic-“quote”", "A&B+C"]
)
def test_real_filename_punctuation_has_one_canonical_encoded_url(name):
    path = "docs/advisories/20990101001-" + name + ".md"
    url = repository_endpoint(COMMIT, path, "20990101001")
    chosen = replace(scope(), scope_reference=url)
    assert parse_wasoc(BODY, scope=chosen).advisory_id == "20990101001"
    assert " " not in url and "“" not in url


@pytest.mark.parametrize(
    "suffix", ["%2Fother.md", "%252Fother.md", "%FF.md", "x%00.md"]
)
def test_encoded_path_cannot_escape_or_hide_invalid_bytes(suffix):
    url = (
        repository_endpoint(COMMIT, PATH, "20990101001").rsplit("/", 1)[0]
        + "/20990101001-"
        + suffix
    )
    with pytest.raises(ValueError):
        parse_wasoc(BODY, scope=replace(scope(), scope_reference=url))


@pytest.mark.parametrize(
    "heading",
    [
        b"# Synthetic advisory - 209901010002",
        b"# Synthetic advisory- 209901010002",
        b"# Synthetic advisory",
    ],
)
def test_conflicting_or_absent_heading_id_stays_a_claim_not_a_merge(heading):
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory
    from standalone.evidence_pipeline.parsing.reference_records import (
        normalize_references,
    )
    from standalone.evidence_pipeline.persistence.reference_attribution import (
        reconstruct_reference,
    )

    chosen = scope()
    body = heading + b"\n" + BODY.split(b"\n", 1)[1]
    (record,) = normalize_references(parse_advisory(body, scope=chosen))
    # The entire original document remains retained and reconstruction is exact.
    assert record.source_record_id == "20990101001"
    assert reconstruct_reference(chosen, record.claim) == record
    notice = parse_advisory(body, scope=chosen).records[0].fields["notice"]
    assert notice["identity_status"] == (
        "unknown_heading_identity"
        if heading == b"# Synthetic advisory"
        else "conflicting_heading_identity"
    )
    assert notice["source_heading_advisory_id"] == (
        None if heading == b"# Synthetic advisory" else "209901010002"
    )


@pytest.mark.parametrize("prefix", [b"# ", b"## ", b"### "])
def test_source_title_level_does_not_change_document_identity(prefix):
    from standalone.evidence_pipeline.parsing.wasoc_advisories import source_heading

    body = prefix + BODY[2:]
    assert source_heading(body) == ("Synthetic advisory", "20990101001")
    assert parse_wasoc(body, scope=scope()).advisory_id == "20990101001"


def test_top_level_reference_section_is_not_another_advisory_identity():
    from standalone.evidence_pipeline.parsing.advisory_feeds import parse_advisory
    from standalone.evidence_pipeline.parsing.reference_records import (
        normalize_references,
    )
    from standalone.evidence_pipeline.persistence.reference_attribution import (
        reconstruct_reference,
    )

    chosen = scope()
    body = BODY + b"\n# Additional References\nSynthetic reference CVE-2099-77777.\n"
    result = parse_wasoc(body, scope=chosen)
    assert result.sections[-1] == (
        "Additional References",
        "Synthetic reference CVE-2099-77777.",
    )
    assert result.raw_payload == body
    assert result.referenced_cves[-1] == "CVE-2099-77777"
    (record,) = normalize_references(parse_advisory(body, scope=chosen))
    assert reconstruct_reference(chosen, record.claim) == record
