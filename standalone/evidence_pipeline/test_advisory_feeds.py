"""Synthetic vendor acceptance fixtures retain native claims through reconstruction."""

from dataclasses import replace
import json
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.parsing import advisory_feeds as feeds
from .contracts import SourceScope
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from standalone.evidence_pipeline.persistence.reference_attribution import (
    reconstruct_reference,
)
from .test_debian_tracker import scope as debian_scope, document as debian_document
from .test_httpd_advisories import scope as httpd_scope, document as httpd_document
from .test_samba_advisories import announcement, CVE
from .test_tomcat_advisories import fixture as tomcat_fixture


def fixture(source):
    if source == "WA SOC":
        from .test_wasoc_advisories import scope, BODY

        return scope(), BODY
    if source == "Microsoft Update Catalog":
        from .test_update_catalog import ID, payload
        from standalone.evidence_pipeline.parsing.update_catalog import endpoint

        return SourceScope(
            str(uuid4()),
            source,
            "updates",
            endpoint(ID),
            "synthetic",
            "TriageMate generated synthetic Catalog metadata",
        ), payload()
    if source == "Palo Alto Networks":
        from .test_cve_program import document

        raw = document()
        return SourceScope(
            str(uuid4()),
            source,
            "advisories",
            "https://security.paloaltonetworks.com/json/" + raw["cveMetadata"]["cveId"],
            "synthetic",
            "TriageMate generated synthetic Palo Alto shaped record",
        ), json.dumps(raw).encode()
    if source == "Cisco":
        from .test_cisco_advisories import example

        scope, raw = example()
        return scope, json.dumps(raw).encode()
    if source == "Debian":
        return debian_scope(), json.dumps(debian_document()).encode()
    if source == "Apache HTTP Server":
        return httpd_scope(), json.dumps(httpd_document()).encode()
    if source == "Apache Tomcat":
        reference, payload = feeds.TOMCAT_BASE + "security-11.xml", tomcat_fixture()
    else:
        reference, payload = feeds.SAMBA_BASE + CVE + ".html", announcement()
    return SourceScope(
        str(uuid4()),
        source,
        "advisories",
        reference,
        "synthetic",
        "TriageMate generated synthetic vendor advisory",
    ), payload


@pytest.mark.parametrize("source", sorted({source for source, _ in feeds.SOURCES}))
def test_source_to_reference_reconstruction(source):
    scope, payload = fixture(source)
    feed = feeds.parse_advisory(payload, scope=scope)
    records = list(normalize_public(feed))
    assert len(records) == (2 if source == "Debian" else 1)
    for record in records:
        assert record.reference_kind == "vendor_advisory_data"
        assert reconstruct_reference(scope, record.claim) == record
        fields = json.loads(record.source_fields)
        if source == "Debian":
            assert fields["document"] == {
                record.source_record_id: debian_document()[record.source_record_id]
            }
        elif source in {"Cisco", "Palo Alto Networks"}:
            assert fields["document"] == json.loads(payload)
        elif source == "Apache HTTP Server":
            assert fields["document"] == httpd_document()
        else:
            assert fields["wire_text"].encode() == payload
    if source == "Apache Tomcat":
        notices = json.loads(records[0].source_fields)["notices"]
        assert notices[1]["affected_text"] == ["Affects: 11.0.7?"]
        assert notices[2]["fixed_release"] is None
    if source == "Samba":
        assert (
            "only with option X enabled"
            in json.loads(records[0].source_fields)["notice"]["versions_text"]
        )


@pytest.mark.parametrize("source", sorted({source for source, _ in feeds.SOURCES}))
@pytest.mark.parametrize("change", ["public", "tenant", "url"])
def test_acceptance_cannot_enable_public_or_private_sources(source, change):
    scope, payload = fixture(source)
    scope = replace(
        scope,
        **{
            "public": {"origin": "public"},
            "tenant": {"tenant_id": str(uuid4())},
            "url": {"scope_reference": scope.scope_reference + "?redirect=1"},
        }[change],
    )
    if change == "public" and source != "Cisco":
        assert feeds.parse_advisory(payload, scope=scope).scope == scope
    else:
        with pytest.raises(ValueError):
            feeds.parse_advisory(payload, scope=scope)


@pytest.mark.parametrize("source", sorted({source for source, _ in feeds.SOURCES}))
def test_durable_bundle_is_offline_and_replayable(source, tmp_path, monkeypatch):
    from standalone.evidence_pipeline.collection import public_collection

    scope, payload = fixture(source)
    from standalone.evidence_pipeline.collection.collection_scope import (
        DEFERRED_SOURCES,
    )

    if source in DEFERRED_SOURCES:
        with pytest.raises(ValueError, match="deferred"):
            public_collection.prepare(
                scope, str(uuid4()), tmp_path / "blocked", synthetic_payload=payload
            )
        assert not (tmp_path / "blocked").exists()
        return

    def unexpected_network(*args, **kwargs):
        raise AssertionError("Synthetic acceptance attempted network access")

    monkeypatch.setattr(public_collection, "download", unexpected_network)
    bundle = tmp_path / "bundle"
    execution = str(uuid4())
    saved = public_collection.prepare(
        scope, execution, bundle, synthetic_payload=payload
    )
    replay = public_collection.prepare(scope, execution, bundle, replay_only=True)
    assert saved == replay
    assert list(normalize_public(saved.feed())) == list(normalize_public(replay.feed()))
