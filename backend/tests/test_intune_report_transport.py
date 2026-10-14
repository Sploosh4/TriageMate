"""Exact synthetic contracts for Intune update report row 9."""

from __future__ import annotations

from datetime import timedelta

from io import BytesIO, StringIO

import csv


import hashlib


import json


from uuid import uuid4

from zipfile import ZIP_DEFLATED, ZipFile

import httpx


import pytest


import microsoft_evidence.cloud as cloud_module


from microsoft_evidence.cloud import (
    MicrosoftEndpointPolicy,
    MicrosoftPermissionManifest,
    PermissionGrant,
    prepare_server_owned_collection_context,
)

from microsoft_evidence.contracts import MicrosoftEvidenceScope

from microsoft_evidence.intune_report_transport import (
    HttpIntuneUpdateReportTransport,
    IntuneUpdateReportExport,
    IntuneUpdateStatusRecord,
    REPORT_FIELDS,
    REPORT_SELECT_FIELDS,
)

from microsoft_evidence.live_authority import (
    MicrosoftAccessTokenLease,
    verify_microsoft_app_token,
)


from microsoft_evidence.transport import MicrosoftTransportError

from tests.test_microsoft_live_authority import NOW, _Keys, _token

POLICY_ID = "71000000-0000-4000-8000-000000000001"


DEVICE_ID = "72000000-0000-4000-8000-000000000001"


ENTRA_ID = "73000000-0000-4000-8000-000000000001"


JOB_ID = "QualityUpdateDeviceStatusByPolicy_synthetic-job-1"


DOWNLOAD_URL = (
    "https://syntheticreports.blob.core.windows.net/reports/"
    "QualityUpdateDeviceStatusByPolicy.zip?sig=synthetic"
)


def _row(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "AADDeviceId": ENTRA_ID,
        "DeviceId": DEVICE_ID,
        "DeviceName": "synthetic-device.example.invalid",
        "PolicyId": POLICY_ID,
        "AggregateState": "inProgress",
        "AggregateState_loc": "In progress",
        "CurrentDeviceUpdateStatus": "Downloading",
        "CurrentDeviceUpdateStatus_loc": "Downloading",
        "CurrentDeviceUpdateSubstatus": "DownloadInProgress",
        "CurrentDeviceUpdateSubstatus_loc": "Download in progress",
        "EventDateTimeUTC": NOW.isoformat(),
        "LastWUScanTimeUTC": NOW.isoformat(),
        "LatestAlertMessage": "",
        "LatestAlertMessage_loc": "",
        "OwnerType": "Company",
        "UPN": "synthetic.user@example.invalid",
    }
    value.update(changes)
    return value


def test_live_csv_timestamp_shape_is_validated_without_rewriting_source():
    row = _row(
        EventDateTimeUTC="2026-09-12 10:00:00.1234567",
        LastWUScanTimeUTC="0001-01-01 00:00:00.0000000",
    )
    assert IntuneUpdateStatusRecord.model_validate(row).model_dump() == row


def _zip_csv(rows: list[dict[str, object]], *, fields=REPORT_FIELDS) -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        csv_text = StringIO(newline="")
        writer = csv.DictWriter(csv_text, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        archive.writestr(
            "QualityUpdateDeviceStatusByPolicy.csv",
            csv_text.getvalue().encode(),
        )
    return output.getvalue()


def _prepared(connection=None):
    endpoint_values = {
        "schema_version": 1,
        "endpoint_policy_id": "live-global-intune-update-export-v1",
        "classification": "live",
        "cloud": "global",
        "product": "intune",
        "scheme": "https",
        "host": "graph.microsoft.com",
        "port": 443,
        "path_template": "/beta/deviceManagement/reports/exportJobs",
        "api_versions": ("beta",),
        "token_audience": "https://graph.microsoft.com",
        "allowed_query_parameter_names": (),
        "continuation_query_parameter_names": (),
    }
    endpoint = MicrosoftEndpointPolicy(
        **endpoint_values,
        endpoint_policy_sha256=cloud_module._canonical_sha256(endpoint_values),
    )
    base = next(iter(cloud_module._PERMISSION_MANIFESTS.values()))
    scope = connection or MicrosoftEvidenceScope(
        agency_id="synthetic-update-report-live-policy",
        tenant_id=base.scope.tenant_id,
        cloud="global",
        data_location="synthetic-au-west",
        product="intune",
    )
    manifest_values = {
        field: getattr(base, field)
        for field in MicrosoftPermissionManifest.model_fields
        if field != "manifest_sha256"
    }
    manifest_values.update(
        manifest_id=uuid4(),
        classification="live",
        revision="synthetic-approved-update-export-v1",
        scope=scope,
        endpoint_policy_ids=(endpoint.endpoint_policy_id,),
        grants=(
            PermissionGrant(
                role="DeviceManagementConfiguration.ReadWrite.All",
                effect="read",
            ),
        ),
        elevated_permission_approval_id="synthetic-security-approval",
        elevated_permission_approval_sha256="e" * 64,
        credential_effective_from=NOW - timedelta(days=1),
        credential_effective_until=NOW + timedelta(days=1),
        effective_from=NOW - timedelta(days=1),
        effective_until=NOW + timedelta(days=1),
    )
    canonical = MicrosoftPermissionManifest.model_construct(
        **manifest_values,
        manifest_sha256="0" * 64,
    ).model_dump(mode="json", exclude={"manifest_sha256"})
    manifest = MicrosoftPermissionManifest(
        **manifest_values,
        manifest_sha256=cloud_module._canonical_sha256(canonical),
    )
    return prepare_server_owned_collection_context(
        scope=scope,
        endpoint=endpoint,
        manifest=manifest,
        now=NOW,
    )


def _lease(prepared) -> MicrosoftAccessTokenLease:
    raw = _token(prepared)
    return MicrosoftAccessTokenLease(
        access_token=raw,
        verified=verify_microsoft_app_token(
            access_token=raw,
            prepared=prepared,
            signing_keys=_Keys(),
            now=NOW,
        ),
    )


def _http_transport(handler, **changes):
    prepared = _prepared()
    values = {
        "client": httpx.Client(transport=httpx.MockTransport(handler)),
        "prepared": prepared,
        "token": _lease(prepared),
        "max_polls": 3,
        "poll_interval_seconds": 0,
        "sleep": lambda _seconds: None,
        "now": lambda: NOW + timedelta(minutes=1),
    }
    values.update(changes)
    return HttpIntuneUpdateReportTransport(**values)


def _completed_handler(archive: bytes, *, url: str = DOWNLOAD_URL):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                201,
                json=_job("completed", url=url),
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(
            200,
            content=archive,
            headers={"Content-Type": "application/zip"},
        )

    return handler


def _job(status: str, *, url: str | None = None) -> dict[str, object]:
    return {
        "@odata.context": (
            "https://graph.microsoft.com/beta/$metadata#deviceManagement/"
            "reports/exportJobs/$entity"
        ),
        "id": JOB_ID,
        "reportName": "QualityUpdateDeviceStatusByPolicy",
        "filter": f"(PolicyId eq '{POLICY_ID}')",
        "select": list(REPORT_SELECT_FIELDS),
        "format": "csv",
        "localizationType": "LocalizedValuesAsAdditionalColumn",
        "snapshotId": None,
        "status": status,
        "url": url,
        "requestDateTime": NOW.isoformat(),
        "expirationDateTime": (
            (NOW + timedelta(hours=1)).isoformat() if url else "0001-01-01T00:00:00Z"
        ),
    }


@pytest.mark.parametrize("wire_variant", [False, True])
def test_http_export_uses_exact_request_poll_and_anonymous_zip_download(
    wire_variant,
) -> None:
    prepared = _prepared()
    token = _lease(prepared)
    archive = _zip_csv([_row()])
    calls: list[httpx.Request] = []

    def wire(job):
        if wire_variant:
            job["localizationType"] = "localizedValuesAsAdditionalColumn"
            if job["url"] is None:
                job.pop("url")
        return job

    polls = iter((wire(_job("inProgress")), wire(_job("completed", url=DOWNLOAD_URL))))

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "POST":
            assert request.url == httpx.URL(
                "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
            )
            assert request.headers["Authorization"] == token.authorization_header()
            assert json.loads(request.content) == {
                "reportName": "QualityUpdateDeviceStatusByPolicy",
                "filter": f"(PolicyId eq '{POLICY_ID}')",
                "select": list(REPORT_SELECT_FIELDS),
                "format": "csv",
                "localizationType": "LocalizedValuesAsAdditionalColumn",
            }
            return httpx.Response(
                201,
                json=wire(_job("notStarted")),
                headers={"Content-Type": "application/json"},
            )
        if request.url.host == "graph.microsoft.com":
            assert request.url.path.endswith(f"/exportJobs/{JOB_ID}")
            return httpx.Response(
                200,
                json=next(polls),
                headers={"Content-Type": "application/json"},
            )
        assert request.url == httpx.URL(DOWNLOAD_URL)
        assert "Authorization" not in request.headers
        return httpx.Response(
            200,
            content=archive,
            headers={"Content-Type": "application/zip"},
        )

    transport = HttpIntuneUpdateReportTransport(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        prepared=prepared,
        token=token,
        max_polls=3,
        poll_interval_seconds=0,
        sleep=lambda _seconds: None,
        now=lambda: NOW + timedelta(minutes=1),
    )

    result = transport.collect(POLICY_ID)

    assert isinstance(result, IntuneUpdateReportExport)
    assert result.result.record_count == 1
    assert result.job_id_sha256 == hashlib.sha256(JOB_ID.encode()).hexdigest()
    assert tuple(request.method for request in calls) == ("POST", "GET", "GET", "GET")
    serialized = result.model_dump_json()
    assert DOWNLOAD_URL not in serialized
    assert token.authorization_header() not in serialized


def test_reordered_csv_header_is_canonicalized_to_the_source_contract() -> None:
    result = _http_transport(
        _completed_handler(_zip_csv([_row()], fields=tuple(reversed(REPORT_FIELDS))))
    ).collect(POLICY_ID)

    assert tuple(result.result.pages[0].records[0]) == REPORT_FIELDS


@pytest.mark.parametrize("kind", ("invalid", "multiple", "traversal"))
def test_unsafe_report_archives_fail_closed(kind: str) -> None:
    if kind == "invalid":
        archive = b"not a zip"
    else:
        output = BytesIO()
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as zipped:
            csv_bytes = _zip_csv([_row()])
            if kind == "multiple":
                zipped.writestr("one.csv", csv_bytes)
                zipped.writestr("two.csv", csv_bytes)
            else:
                zipped.writestr("../report.csv", csv_bytes)
        archive = output.getvalue()

    with pytest.raises(MicrosoftTransportError, match="archive"):
        _http_transport(_completed_handler(archive)).collect(POLICY_ID)


def test_wrapped_poll_envelope_and_retry_after_are_bounded() -> None:
    archive = _zip_csv([_row()])
    calls = 0
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        if request.method == "POST":
            return httpx.Response(
                201,
                json=_job("notStarted"),
                headers={"Content-Type": "application/json"},
            )
        if request.url.host == "graph.microsoft.com":
            return httpx.Response(
                200,
                json={"value": _job("completed", url=DOWNLOAD_URL)},
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(
            200,
            content=archive,
            headers={"Content-Type": "application/octet-stream"},
        )

    result = _http_transport(
        handler,
        poll_interval_seconds=0,
        sleep=sleeps.append,
    ).collect(POLICY_ID)

    assert result.result.record_count == 1
    assert sleeps == [0.5, 0.5, 0.5, 0.5]


def test_poll_limit_deadline_and_cancellation_fail_without_download() -> None:
    def pending(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201 if request.method == "POST" else 200,
            json=_job("notStarted" if request.method == "POST" else "inProgress"),
            headers={"Content-Type": "application/json"},
        )

    with pytest.raises(MicrosoftTransportError, match="polling limit"):
        _http_transport(pending, max_polls=1).collect(POLICY_ID)

    moments = iter((NOW, NOW, NOW + timedelta(minutes=16)))
    with pytest.raises(MicrosoftTransportError, match="deadline"):
        _http_transport(
            pending,
            max_elapsed_seconds=15 * 60,
            now=lambda: next(moments),
        ).collect(POLICY_ID)

    with pytest.raises(MicrosoftTransportError, match="cancelled"):
        _http_transport(pending, cancelled=lambda: True).collect(POLICY_ID)


def test_expired_completed_job_and_download_redirect_fail_closed() -> None:
    expired = _job("completed", url=DOWNLOAD_URL)
    expired["expirationDateTime"] = NOW.isoformat()

    def expired_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json=expired,
            headers={"Content-Type": "application/json"},
        )

    with pytest.raises(MicrosoftTransportError, match="expired"):
        _http_transport(expired_handler).collect(POLICY_ID)

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                201,
                json=_job("completed", url=DOWNLOAD_URL),
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(302, headers={"Location": "https://example.invalid"})

    with pytest.raises(MicrosoftTransportError, match="status 302"):
        _http_transport(redirect_handler).collect(POLICY_ID)


@pytest.mark.parametrize("change", ("filter", "future_status"))
def test_job_contract_substitution_and_future_state_fail_closed(change: str) -> None:
    job = _job("completed", url=DOWNLOAD_URL)
    if change == "filter":
        job["filter"] = "(PolicyId ne null)"
    else:
        job["status"] = "newProviderState"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json=job,
            headers={"Content-Type": "application/json"},
        )

    with pytest.raises(MicrosoftTransportError):
        _http_transport(handler).collect(POLICY_ID)


def test_503_retry_exhaustion_is_bounded() -> None:
    calls = 0
    sleeps: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    with pytest.raises(MicrosoftTransportError, match="retry limit"):
        _http_transport(
            handler,
            max_retries=1,
            sleep=sleeps.append,
        ).collect(POLICY_ID)

    assert calls == 2
    assert sleeps == [0.5, 0.5]


def test_download_host_and_signed_url_remain_closed_and_redacted() -> None:
    unsafe = "https://blob.core.windows.net.evil.example/report.zip?sig=secret"
    with pytest.raises(MicrosoftTransportError) as captured:
        _http_transport(_completed_handler(b"", url=unsafe)).collect(POLICY_ID)

    assert unsafe not in str(captured.value)
    assert "sig=secret" not in str(captured.value)


def test_signed_download_url_is_redacted_when_the_network_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(
                201,
                json=_job("completed", url=DOWNLOAD_URL),
                headers={"Content-Type": "application/json"},
            )
        raise httpx.ConnectError("failed for " + str(request.url))

    with pytest.raises(MicrosoftTransportError) as captured:
        _http_transport(handler, max_retries=0).collect(POLICY_ID)

    assert DOWNLOAD_URL not in str(captured.value)
    assert captured.value.__cause__ is None


def test_download_has_no_configured_byte_ceiling() -> None:
    # ZIP permits a preamble; this keeps the actual CSV fixture small while
    # exercising a download above both the former 32 MiB and UI 45 MB budgets.
    archive = b" " * 45_000_001 + _zip_csv([_row()])
    result = _http_transport(_completed_handler(archive)).collect(POLICY_ID)
    assert len(result.result.pages[0].records) == 1


def test_csv_display_text_remains_inert_and_exact() -> None:
    alert = '=HYPERLINK("https://example.invalid","synthetic")'
    device_name = "synthetic,device\nsecond line"
    result = _http_transport(
        _completed_handler(
            _zip_csv([_row(LatestAlertMessage=alert, DeviceName=device_name)])
        )
    ).collect(POLICY_ID)

    record = result.result.pages[0].records[0]
    assert record["LatestAlertMessage"] == alert
    assert record["DeviceName"] == device_name


def test_live_report_authority_requires_explicit_elevated_permission_approval() -> None:
    base = next(iter(cloud_module._PERMISSION_MANIFESTS.values()))
    values = {
        field: getattr(base, field)
        for field in MicrosoftPermissionManifest.model_fields
        if field != "manifest_sha256"
    }
    values.update(
        grants=(
            PermissionGrant(
                role="DeviceManagementConfiguration.ReadWrite.All",
                effect="read",
            ),
        ),
        elevated_permission_approval_id=None,
        elevated_permission_approval_sha256=None,
    )
    canonical = MicrosoftPermissionManifest.model_construct(
        **values,
        manifest_sha256="0" * 64,
    ).model_dump(mode="json", exclude={"manifest_sha256"})

    with pytest.raises(ValueError, match="elevated permission approval"):
        MicrosoftPermissionManifest(
            **values,
            manifest_sha256=cloud_module._canonical_sha256(canonical),
        )


def test_http_export_decodes_gzip_job_and_archive_once():
    import gzip

    archive = _zip_csv([_row()])

    def handler(request):
        body = (
            json.dumps(_job("completed", url=DOWNLOAD_URL)).encode()
            if request.method == "POST"
            else archive
        )
        return httpx.Response(
            201 if request.method == "POST" else 200,
            content=gzip.compress(body),
            headers={
                "Content-Type": "application/json"
                if request.method == "POST"
                else "application/zip",
                "Content-Encoding": "gzip",
            },
        )

    result = _http_transport(handler).collect(POLICY_ID)
    assert result.result.record_count == 1
    assert result.download_sha256 == hashlib.sha256(archive).hexdigest()


def test_http_export_rejects_corrupt_content_encoding_without_raw_error():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(
            201,
            stream=httpx.ByteStream(b"synthetic-invalid-gzip"),
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )

    with pytest.raises(
        MicrosoftTransportError, match="response encoding is invalid"
    ) as error:
        _http_transport(handler).collect(POLICY_ID)
    assert len(requests) == 1
    assert error.value.__suppress_context__
    assert "synthetic-invalid-gzip" not in str(error.value)


def test_request_selects_source_columns_not_generated_localizations():
    from microsoft_evidence.intune_report_transport import _request_body

    assert _request_body(POLICY_ID)["select"] == [
        "AADDeviceId",
        "AggregateState",
        "CurrentDeviceUpdateStatus",
        "CurrentDeviceUpdateSubstatus",
        "DeviceId",
        "DeviceName",
        "EventDateTimeUTC",
        "LastWUScanTimeUTC",
        "LatestAlertMessage",
        "OwnerType",
        "PolicyId",
        "UPN",
    ]
    assert "AggregateState_loc" in REPORT_FIELDS
    assert (
        _request_body(POLICY_ID)["localizationType"]
        == "LocalizedValuesAsAdditionalColumn"
    )


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_download_checks_elapsed_deadline_and_cancellation_during_body(
    stop, monkeypatch
):
    from microsoft_evidence import transport as module

    clock = {"elapsed": 0.0, "cancelled": False}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["elapsed"])

    class Body(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b"synthetic partial archive"
            clock["elapsed"] = 31.0 if stop == "deadline" else 1.0
            clock["cancelled"] = stop == "cancel"
            yield b"synthetic remaining archive"

        def close(self):
            self.closed = True

    body = Body()
    completed = _completed_handler(b"")

    def handler(request):
        if request.method == "POST":
            return completed(request)
        return httpx.Response(
            200, headers={"Content-Type": "application/zip"}, stream=body
        )

    transport = _http_transport(handler, cancelled=lambda: clock["cancelled"])
    try:
        with pytest.raises(MicrosoftTransportError, match=stop):
            transport.collect(POLICY_ID)
    finally:
        transport._client.close()
    assert body.closed


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_archive_decode_checks_interrupt_and_closes_member(stop, monkeypatch):
    import zipfile
    from microsoft_evidence import transport as module

    state = {"elapsed": 0.0, "cancelled": False, "closed": False}
    monkeypatch.setattr(module.time, "monotonic", lambda: state["elapsed"])
    original_read = zipfile.ZipExtFile.read1
    original_close = zipfile.ZipExtFile.close

    def interrupted_read(stream, *args):
        data = original_read(stream, *args)
        state["cancelled"] = stop == "cancel"
        state["elapsed"] = 31.0 if stop == "deadline" else 1.0
        return data

    def close(stream):
        state["closed"] = True
        return original_close(stream)

    monkeypatch.setattr(zipfile.ZipExtFile, "read1", interrupted_read)
    monkeypatch.setattr(zipfile.ZipExtFile, "close", close)
    transport = _http_transport(
        lambda _: pytest.fail("Archive decoding must not fetch"),
        cancelled=lambda: state["cancelled"],
    )
    try:
        response = httpx.Response(
            200, headers={"Content-Type": "application/zip"}, content=_zip_csv([_row()])
        )
        with pytest.raises(MicrosoftTransportError, match=stop):
            transport._download_records(response)
    finally:
        transport._client.close()
    assert state["closed"]
