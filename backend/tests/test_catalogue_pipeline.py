"""Synthetic signed authority and HTTP; no live credentials or tenant calls."""

from dataclasses import replace
from uuid import uuid4

import httpx
import pytest

from microsoft_evidence.catalogue_pipeline import collect_catalogue, INPUT_ID, PATH
from microsoft_evidence.pipeline import connection_scope
from microsoft_evidence.transport import MicrosoftHttpTransport, MicrosoftTransportError
from standalone.evidence_pipeline.parsing.vulnerability_catalogue import (
    RETAINED_FIELDS,
    normalize_catalogue,
)
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_transport import _lease


@pytest.fixture
def inputs():
    source = replace(scope(), source="Defender", input_kind="vulnerability_catalogue")
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            PATH,
            "https://api.security.microsoft.com",
            ("Vulnerability.Read.All",),
        ),
    )
    prepared = prepared.model_copy(
        update={
            "endpoint": prepared.endpoint.model_copy(
                update={
                    "allowed_query_parameter_names": ("$top", "$skip"),
                    "paging_query_parameter_names": ("$top", "$skip"),
                }
            )
        }
    )
    return source, prepared


def transport_collect(inputs, handler, **options):
    _, prepared = inputs
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return MicrosoftHttpTransport(
            client=client, now=lambda: NOW, **options
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            source_input_id=INPUT_ID,
            query={},
            allowed_record_fields=RETAINED_FIELDS,
            required_record_fields=frozenset({"id"}),
            offset_page_size=2,
        )


def test_full_page_without_nextlink_fetches_terminal_empty_page(inputs):
    calls = []

    def handler(request):
        calls.append(dict(request.url.params))
        return httpx.Response(
            200,
            json={
                "value": [{"id": "CVE-2026-10001"}, {"id": "CVE-2026-10002"}]
                if len(calls) == 1
                else []
            },
        )

    result = transport_collect(inputs, handler)
    assert calls == [{"$skip": "0", "$top": "2"}, {"$top": "2", "$skip": "2"}]
    assert result.record_count == 2
    assert not result.pages[0].terminal
    assert result.pages[-1].terminal


@pytest.mark.parametrize(
    "nextlink",
    [
        "https://evil.example/api/vulnerabilities?$top=2&$skip=2",
        "https://api.security.microsoft.com/api/vulnerabilities?$top=2&$skip=0",
        "https://api.security.microsoft.com/api/vulnerabilities?$top=2&$skip=4",
    ],
)
def test_wrong_continuation_is_rejected(inputs, nextlink):
    with pytest.raises(MicrosoftTransportError):
        transport_collect(
            inputs,
            lambda _: httpx.Response(
                200,
                json={
                    "value": [{"id": "CVE-2026-10001"}, {"id": "CVE-2026-10002"}],
                    "@odata.nextLink": nextlink,
                },
            ),
        )


@pytest.mark.parametrize("options", [{"max_pages": 1}, {"max_records": 1}])
def test_collection_bounds_are_cumulative(inputs, options):
    with pytest.raises(MicrosoftTransportError):
        transport_collect(
            inputs,
            lambda _: httpx.Response(
                200,
                json={"value": [{"id": "CVE-2026-10001"}, {"id": "CVE-2026-10002"}]},
            ),
            **options,
        )


def test_failed_second_page_is_not_complete(inputs):
    calls = []

    def handler(request):
        calls.append(request)
        return (
            httpx.Response(
                200,
                json={"value": [{"id": "CVE-2026-10001"}, {"id": "CVE-2026-10002"}]},
            )
            if len(calls) == 1
            else httpx.Response(429)
        )

    with pytest.raises(MicrosoftTransportError):
        transport_collect(inputs, handler, max_retries=0)
    assert len(calls) == 2


def test_collector_projects_validates_and_preserves_source_values(inputs):
    source, prepared = inputs
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "CVE-2026-10001",
                            "cvssV3": 4.2,
                            "publicExploit": False,
                            "providerFutureField": "not retained",
                        }
                    ]
                },
            )
        )
    ) as client:
        snapshot = collect_catalogue(
            scope=source,
            execution_id=str(uuid4()),
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
    assert b"providerFutureField" not in snapshot.payload
    assert normalize_catalogue(snapshot)[0].observation()["publicExploit"] is False


def test_scope_mismatch_never_calls_transport(inputs):
    source, prepared = inputs
    with pytest.raises(ValueError, match="authority"):
        collect_catalogue(
            scope=replace(source, connection_id=str(uuid4())),
            execution_id=str(uuid4()),
            prepared=prepared,
            token=None,
            transport=None,
            now=lambda: NOW,
        )


@pytest.mark.parametrize("allow_network", [False, True])
def test_saved_catalogue_replays_through_dedicated_command_without_credentials(
    inputs, tmp_path, monkeypatch, allow_network
):
    from microsoft_evidence import collector_command as command
    from standalone.evidence_pipeline.collection.snapshot_bundle import prepare
    from standalone.evidence_pipeline.contracts import Snapshot

    source, prepared = inputs
    execution = str(uuid4())
    snapshot = Snapshot(
        source, execution, NOW, NOW, "success", True, b'[{"id":"CVE-2026-10001"}]'
    )
    config = command.Configuration(
        source,
        prepared.endpoint,
        None,
        tmp_path / "missing-key",
        tmp_path / "missing-cert",
        tmp_path,
    )
    prepare(source, execution, tmp_path, collect=lambda: snapshot)
    seen = []
    monkeypatch.setattr(
        command,
        "ingest_catalogue",
        lambda item: seen.append(item) or {"outcome": "success"},
    )
    monkeypatch.setattr(
        command, "ingest", lambda _: pytest.fail("Catalogue routed to device importer")
    )
    assert (
        command.run(config, execution, allow_network=allow_network)["outcome"]
        == "success"
    )
    assert seen == [snapshot]
    with pytest.raises(ValueError, match="device binding"):
        command.run(config, execution, device_snapshot=snapshot)


def test_wire_decimal_survives_transport_snapshot_and_normalization(inputs):
    from decimal import Decimal

    source, prepared = inputs
    raw = b'{"value":[{"id":"CVE-2026-12345","epss":0.1234567890123456789,"cvssV3":9.1234567890123456789}]}'
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, content=raw, headers={"Content-Type": "application/json"}
            )
        )
    ) as client:
        snapshot = collect_catalogue(
            scope=source,
            execution_id=str(uuid4()),
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
    assert b'"epss":0.1234567890123456789' in snapshot.payload
    claim = normalize_catalogue(snapshot)[0].observation()
    assert claim["epss"] == Decimal("0.1234567890123456789")
    assert claim["cvssV3"] == Decimal("9.1234567890123456789")


@pytest.mark.parametrize("damage", [None, "wrong_id", "list_envelope", "continuation"])
def test_exact_cve_catalogue_cannot_expand_to_inventory(inputs, damage):
    from microsoft_evidence.catalogue_pipeline import catalogue_path

    source, _ = inputs
    source = replace(source, scope_reference="cve-id:CVE-2026-10001")
    path = catalogue_path(source)
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            path,
            "https://api.security.microsoft.com",
            ("Vulnerability.Read.All",),
        ),
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.path == path and not request.url.query
        row = {
            "id": "CVE-2026-10002" if damage == "wrong_id" else "CVE-2026-10001",
            "publicExploit": False,
            "cvssV3": 0,
        }
        if damage == "list_envelope":
            row = {"value": [row]}
        if damage == "continuation":
            row["@odata.nextLink"] = (
                "https://api.security.microsoft.com/api/vulnerabilities"
            )
        return httpx.Response(200, json=row)

    def run():
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            return collect_catalogue(
                scope=source,
                execution_id=str(uuid4()),
                prepared=prepared,
                token=_lease(prepared),
                transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
                now=lambda: NOW,
            )

    if damage:
        with pytest.raises((ValueError, MicrosoftTransportError)):
            run()
    else:
        result = run()
        assert result.complete and len(result.records()) == 1
    assert len(calls) == 1


@pytest.mark.parametrize(
    "selector",
    ["cve-id:", "cve-id:../x", "cve-id:CVE-2026-10001/other", "cve-id:CVE-2026-١٠٠٠١"],
)
def test_invalid_cve_selector_cannot_fall_back_to_inventory(inputs, selector):
    from microsoft_evidence.catalogue_pipeline import catalogue_path

    with pytest.raises(ValueError):
        catalogue_path(replace(inputs[0], scope_reference=selector))
