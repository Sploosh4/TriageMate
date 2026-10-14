"""Synthetic Defender finding collection bound to explicit device evidence."""

from dataclasses import replace
from uuid import uuid4
import httpx
import pytest

from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.parsing.exposure import normalize_findings
from microsoft_evidence.pipeline import connection_scope, collect_findings
from microsoft_evidence.transport import MicrosoftHttpTransport
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_transport import _lease


@pytest.fixture
def inputs():
    source = replace(scope(), source="Defender")
    device = Snapshot(
        source, str(uuid4()), NOW, NOW, "success", True, b'[{"id":"synthetic-machine"}]'
    )
    finding_scope = replace(source, connection_id=str(uuid4()), input_kind="findings")
    prepared = _live_prepared(
        scope=connection_scope(finding_scope),
        source_input=(
            "defender",
            "/api/vulnerabilities/machinesVulnerabilities",
            "https://api.security.microsoft.com",
            ("Vulnerability.Read.All",),
        ),
    )
    # Server-owned test policy permits the bounded page-size request.
    prepared = prepared.model_copy(
        update={
            "endpoint": prepared.endpoint.model_copy(
                update={
                    "allowed_query_parameter_names": ("$top",),
                    "paging_query_parameter_names": ("$skiptoken",),
                }
            )
        }
    )
    record = {
        "id": "synthetic-finding",
        "machineId": "synthetic-machine",
        "cveId": "CVE-2026-999999",
        "productName": "Synthetic software",
        "productVersion": "1",
        "fixingKbId": None,
        "severity": "High",
    }
    return finding_scope, device, prepared, record


def collect(inputs, handler):
    source, device, prepared, _ = inputs
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return collect_findings(
            scope=source,
            execution_id=str(uuid4()),
            device_snapshot=device,
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )


def test_source_cve_and_unknown_fix_are_preserved(inputs):
    def handler(request):
        assert request.url.params["$top"] == "10000"
        return httpx.Response(200, json={"value": [inputs[3]]})

    snapshot = collect(inputs, handler)
    (finding,) = normalize_findings(snapshot, {"synthetic-machine"})
    assert finding.cve_id == "CVE-2026-999999"
    assert finding.fixing_patch_reference is None
    assert finding.source_severity_label == "High"


def test_uncollected_device_is_rejected(inputs):
    record = {**inputs[3], "machineId": "unknown"}
    with pytest.raises(ValueError, match="uncollected device"):
        collect(inputs, lambda _: httpx.Response(200, json={"value": [record]}))


def test_cross_tenant_binding_rejected_before_request(inputs):
    source, device, prepared, record = inputs
    device = replace(device, scope=replace(device.scope, tenant_id=str(uuid4())))
    with pytest.raises(ValueError, match="same tenant"):
        collect(
            (source, device, prepared, record),
            lambda _: pytest.fail("Requested cross-tenant findings"),
        )


def test_full_terminal_page_is_not_assumed_complete(inputs):
    records = [{**inputs[3], "id": str(index)} for index in range(10000)]
    with pytest.raises(ValueError, match="snapshot completeness"):
        collect(inputs, lambda _: httpx.Response(200, json={"value": records}))


def test_complete_empty_findings_is_allowed(inputs):
    assert (
        collect(inputs, lambda _: httpx.Response(200, json={"value": []})).records()
        == []
    )


@pytest.mark.parametrize(
    "selection",
    (None, "ms-defender-machine-v1", "ms-entra-directory-device-v1", "unknown"),
)
def test_missing_or_wrong_contract_does_not_resolve_shared_endpoint(inputs, selection):
    from microsoft_evidence.transport import MicrosoftTransportError

    with pytest.raises(MicrosoftTransportError, match="one source contract"):
        MicrosoftHttpTransport._source_contract(inputs[2], source_input_id=selection)


def test_finding_retry_after_uncertain_import_keeps_device_binding(
    inputs, tmp_path, monkeypatch
):
    from microsoft_evidence.pipeline import collect_and_ingest_findings
    from standalone.evidence_pipeline import commands

    source, device, prepared, record = inputs
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    requests = []
    imports = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"value": [record]})

    def ingest(snapshot, device_attempt_id):
        imports.append((snapshot, device_attempt_id))
        if len(imports) == 1:
            raise RuntimeError("Synthetic lost acknowledgement")
        return {"outcome": "success"}

    monkeypatch.setattr(commands, "ingest_exposure", ingest)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        args = dict(
            scope=source,
            execution_id=str(uuid4()),
            device_snapshot=device,
            root=root,
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(client=client, now=lambda: NOW),
            now=lambda: NOW,
        )
        with pytest.raises(RuntimeError):
            collect_and_ingest_findings(**args)
        assert collect_and_ingest_findings(**args) == {"outcome": "success"}
        assert imports[0] == imports[1]
        args["device_snapshot"] = replace(
            device, payload=b'[{"id":"different-machine"}]'
        )
        with pytest.raises(ValueError, match="binding differs"):
            collect_and_ingest_findings(**args)
    assert len(requests) == 1
    assert len(imports) == 2


@pytest.mark.parametrize(
    "case",
    [
        "matching",
        "empty",
        "wrong_device",
        "continuation",
        "wrong_binding",
        "invalid_selector",
    ],
)
def test_exact_device_findings_cannot_expand_scope(inputs, case):
    import json
    from microsoft_evidence.transport import MicrosoftTransportError

    source, device, _, record = inputs
    native = "a" * 40
    source = replace(
        source,
        scope_reference="native-device-id:"
        + ("bad" if case == "invalid_selector" else native),
    )
    device = replace(
        device,
        payload=json.dumps(
            [{"id": "b" * 40 if case == "wrong_binding" else native}]
        ).encode(),
    )
    prepared = _live_prepared(
        scope=connection_scope(source),
        source_input=(
            "defender",
            "/api/vulnerabilities/machinesVulnerabilities",
            "https://api.security.microsoft.com",
            ("Vulnerability.Read.All",),
        ),
    )
    prepared = prepared.model_copy(
        update={
            "endpoint": prepared.endpoint.model_copy(
                update={"allowed_query_parameter_names": ("$filter", "$top")}
            )
        }
    )
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.params["$filter"] == f"machineId eq '{native}'"
        body = {
            "value": []
            if case == "empty"
            else [
                {**record, "machineId": "b" * 40 if case == "wrong_device" else native}
            ]
        }
        if case == "continuation":
            body["@odata.nextLink"] = (
                "https://api.security.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$skiptoken=unfiltered"
            )
        return httpx.Response(200, json=body)

    args = (source, device, prepared, record)
    if case in ("matching", "empty"):
        assert len(collect(args, handler).records()) == (case == "matching")
    else:
        with pytest.raises((ValueError, MicrosoftTransportError)):
            collect(args, handler)
    assert len(calls) == (0 if case in ("wrong_binding", "invalid_selector") else 1)
