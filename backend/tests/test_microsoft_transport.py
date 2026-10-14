"""Paging, retry, cancellation, and schema tests for Microsoft transport."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from microsoft_evidence.live_authority import (
    MicrosoftAccessTokenLease,
    verify_microsoft_app_token,
)
from microsoft_evidence.transport import (
    MicrosoftHttpTransport,
    MicrosoftTransportCancelled,
    MicrosoftTransportError,
    _operation_matches_route,
)
from tests.test_microsoft_live_authority import (
    KEY_ID,
    NOW,
    _Keys,
    _live_prepared,
    _token,
)


FIELDS = frozenset({"id", "accountEnabled"})


@pytest.mark.parametrize("app_id", (".", "..", "%2e%2e"))
def test_normalized_route_rejected_before_sending_token(app_id):
    prepared = _live_prepared(
        scope=_live_prepared().scope.model_copy(update={"product": "intune"}),
        source_input=(
            "intune",
            f"/v1.0/deviceManagement/detectedApps/{app_id}/managedDevices",
            "https://graph.microsoft.com",
            ("DeviceManagementManagedDevices.Read.All",),
        ),
    )
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda request: pytest.fail("Sent token to normalized route")
        )
    ) as client:
        with pytest.raises(MicrosoftTransportError, match="normalization"):
            MicrosoftHttpTransport(client=client, now=lambda: NOW).collect(
                prepared=prepared,
                token=_lease(prepared),
                query={"$select": "id"},
                allowed_record_fields=frozenset({"id"}),
                required_record_fields=frozenset({"id"}),
                source_input_id="ms-intune-detected-app-device-edge-v1",
            )


@pytest.mark.parametrize(
    ("operation", "route", "matches"),
    (
        (
            "GET /groups/{group-id}/members?$select=id for each retained group",
            "/groups/20000000-0000-4000-8000-000000000001/members",
            True,
        ),
        (
            "GET /servicePrincipals/{servicePrincipal-id}/appRoleAssignedTo?$select=id",
            "/servicePrincipals/30000000-0000-4000-8000-000000000001/appRoleAssignedTo",
            True,
        ),
        (
            "GET /deviceManagement/detectedApps/{detectedApp-id}/managedDevices for each retained application",
            "/deviceManagement/detectedApps/63000000-0000-4000-8000-000000000001/managedDevices",
            True,
        ),
        (
            "GET https://api.security.microsoft.com/api/machines",
            "/api/machines",
            True,
        ),
        (
            "GET /groups/{group-id}/members?$select=id",
            "/groups/one/members/escape",
            False,
        ),
        ("GET /groups", "/users", False),
    ),
)
def test_registry_operation_templates_match_only_exact_concrete_routes(
    operation: str, route: str, matches: bool
) -> None:
    assert _operation_matches_route(operation, route) is matches


def _lease(prepared=None) -> MicrosoftAccessTokenLease:
    prepared = prepared or _live_prepared()
    raw = _token(prepared)
    verified = verify_microsoft_app_token(
        access_token=raw,
        prepared=prepared,
        signing_keys=_Keys(),
        now=NOW,
    )
    return MicrosoftAccessTokenLease(access_token=raw, verified=verified)


def _response(payload, status=200, headers=None) -> httpx.Response:
    response_headers = {"Content-Type": "application/json"}
    response_headers.update(headers or {})
    return httpx.Response(status, json=payload, headers=response_headers)


def test_exact_endpoint_pages_are_collected_without_retaining_urls_or_tokens() -> None:
    prepared = _live_prepared()
    lease = _lease(prepared)
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["Authorization"] == lease.authorization_header()
        if len(requests) == 1:
            assert request.url.params["$select"] == "id,accountEnabled"
            return _response(
                {
                    "value": [{"id": "synthetic-device-1", "accountEnabled": True}],
                    "@odata.nextLink": (
                        "https://graph.microsoft.com/v1.0/devices?"
                        "$select=id%2CaccountEnabled&$skiptoken=synthetic-page-2"
                    ),
                }
            )
        return _response(
            {"value": [{"id": "synthetic-device-2", "accountEnabled": False}]}
        )

    transport = MicrosoftHttpTransport(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        now=lambda: NOW,
    )

    result = transport.collect(
        prepared=prepared,
        token=lease,
        query={"$select": "id,accountEnabled"},
        allowed_record_fields=FIELDS,
        required_record_fields=FIELDS,
    )

    assert result.record_count == 2
    assert result.input_id == "ms-entra-directory-device-v1"
    assert result.source_contract_id.startswith("ms-source-v1:")
    assert tuple(page.page_sequence for page in result.pages) == (0, 1)
    assert result.pages[-1].terminal is True
    serialized = result.model_dump_json()
    assert "synthetic-page-2" not in serialized
    assert lease.authorization_header() not in serialized
    assert "graph.microsoft.com" not in serialized


@pytest.mark.parametrize(
    "next_link",
    (
        "http://graph.microsoft.com/v1.0/devices?$skiptoken=x",
        "https://evil.example/v1.0/devices?$skiptoken=x",
        "https://graph.microsoft.com/v1.0/users?$skiptoken=x",
        "https://graph.microsoft.com:4443/v1.0/devices?$skiptoken=x",
        "https://graph.microsoft.com/v1.0/devices?access_token=x",
        "https://graph.microsoft.com/v1.0/devices?$skiptoken=x#$fragment",
    ),
)
def test_continuation_link_cannot_escape_endpoint_policy(next_link) -> None:
    prepared = _live_prepared()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _request: _response({"value": [], "@odata.nextLink": next_link})
        )
    )

    with pytest.raises(MicrosoftTransportError, match="continuation"):
        MicrosoftHttpTransport(client=client, now=lambda: NOW).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )


def test_throttle_and_unavailable_responses_use_bounded_retry_after() -> None:
    prepared = _live_prepared()
    statuses = iter((429, 503, 200))
    sleeps = []

    def handler(_request):
        status = next(statuses)
        if status == 200:
            return _response({"value": []})
        return _response({}, status=status, headers={"Retry-After": "999"})

    result = MicrosoftHttpTransport(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        max_retries=2,
        sleep=sleeps.append,
        now=lambda: NOW,
    ).collect(
        prepared=prepared,
        token=_lease(prepared),
        query={},
        allowed_record_fields=FIELDS,
        required_record_fields=frozenset(),
    )

    assert result.record_count == 0
    assert sum(sleeps) == 120.0
    assert max(sleeps) == 0.5


def test_timeout_retry_limit_and_cancellation_fail_closed() -> None:
    prepared = _live_prepared()
    attempts = 0

    def timeout(request):
        nonlocal attempts
        attempts += 1
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    with pytest.raises(MicrosoftTransportError, match="retry limit"):
        MicrosoftHttpTransport(
            client=httpx.Client(transport=httpx.MockTransport(timeout)),
            max_retries=1,
            sleep=lambda _seconds: None,
            now=lambda: NOW,
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )
    assert attempts == 2

    cancellation = {"value": False}

    def cancel_during_wait(_seconds):
        cancellation["value"] = True

    throttled = MicrosoftHttpTransport(
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: _response(
                    {}, status=429, headers={"Retry-After": "30"}
                )
            )
        ),
        sleep=cancel_during_wait,
        now=lambda: NOW,
    )
    with pytest.raises(MicrosoftTransportCancelled):
        throttled.collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
            cancelled=lambda: cancellation["value"],
        )

    with pytest.raises(MicrosoftTransportCancelled):
        MicrosoftHttpTransport(
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _request: _response({"value": []}))
            ),
            now=lambda: NOW,
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
            cancelled=lambda: True,
        )


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (_response({"value": [], "unexpected": True}), "envelope"),
        (_response({"value": [], "@odata.count": -1}), "count"),
        (_response({"value": [], "@odata.count": True}), "count"),
        (_response({"value": [], "@odata.count": "1"}), "count"),
        (_response({"value": "not-a-list"}), "records"),
        (_response({"value": [{"id": "x", "unapproved": True}]}), "record schema"),
        (
            httpx.Response(
                200, text="not json", headers={"Content-Type": "text/plain"}
            ),
            "content type",
        ),
        (_response({"value": [], "@odata.nextLink": 7}), "continuation"),
    ),
)
def test_response_schema_drift_is_rejected(response, message) -> None:
    prepared = _live_prepared()
    transport = MicrosoftHttpTransport(
        client=httpx.Client(transport=httpx.MockTransport(lambda _request: response)),
        now=lambda: NOW,
    )

    with pytest.raises(MicrosoftTransportError, match=message):
        transport.collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )


def test_query_authority_expiry_and_error_content_are_not_bypassed() -> None:
    prepared = _live_prepared()
    raw_error = "synthetic provider body must not escape"
    error_transport = MicrosoftHttpTransport(
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(403, text=raw_error)
            )
        ),
        now=lambda: NOW,
    )
    with pytest.raises(MicrosoftTransportError) as captured:
        error_transport.collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )
    assert raw_error not in str(captured.value)

    with pytest.raises(MicrosoftTransportError, match="query"):
        error_transport.collect(
            prepared=prepared,
            token=_lease(prepared),
            query={"access_token": "never-allowed"},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )

    expired_transport = MicrosoftHttpTransport(
        client=httpx.Client(
            transport=httpx.MockTransport(lambda _request: _response({"value": []}))
        ),
        now=lambda: NOW + timedelta(minutes=10),
    )
    with pytest.raises(MicrosoftTransportError, match="expired"):
        expired_transport.collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )


def test_verified_authority_must_match_the_exact_prepared_policy() -> None:
    prepared = _live_prepared()
    lease = _lease(prepared)
    lease.verified = lease.verified.model_copy(
        update={"endpoint_policy_sha256": "f" * 64}
    )

    with pytest.raises(MicrosoftTransportError, match="does not match"):
        MicrosoftHttpTransport(
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _request: _response({"value": []}))
            ),
            now=lambda: NOW,
        ).collect(
            prepared=prepared,
            token=lease,
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )


def test_caller_cannot_expand_fields_beyond_source_contract() -> None:
    prepared = _live_prepared()

    with pytest.raises(MicrosoftTransportError, match="source contract"):
        MicrosoftHttpTransport(
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _request: _response({"value": []}))
            ),
            now=lambda: NOW,
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS | {"password"},
            required_record_fields=frozenset(),
        )

    with pytest.raises(MicrosoftTransportError, match="select fields"):
        MicrosoftHttpTransport(
            client=httpx.Client(
                transport=httpx.MockTransport(lambda _request: _response({"value": []}))
            ),
            now=lambda: NOW,
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={"$select": "id,password"},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )


def test_signing_key_id_constant_is_not_exposed_by_transport_result() -> None:
    prepared = _live_prepared()
    result = MicrosoftHttpTransport(
        client=httpx.Client(
            transport=httpx.MockTransport(lambda _request: _response({"value": []}))
        ),
        now=lambda: NOW,
    ).collect(
        prepared=prepared,
        token=_lease(prepared),
        query={},
        allowed_record_fields=FIELDS,
        required_record_fields=frozenset(),
    )

    assert KEY_ID not in result.model_dump_json()


@pytest.mark.parametrize(
    "error", [httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError]
)
def test_network_failures_are_bounded_and_sanitized(error):
    prepared = _live_prepared()
    attempts = []

    def handler(request):
        attempts.append(request)
        raise error("synthetic-sensitive-provider-detail", request=request)

    with pytest.raises(MicrosoftTransportError, match="retry limit") as caught:
        MicrosoftHttpTransport(
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            max_retries=1,
            sleep=lambda _: None,
            now=lambda: NOW,
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )
    assert len(attempts) == 2
    assert "synthetic-sensitive" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_response_above_frontend_budget_is_collected_and_closed():
    class Body(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            for _ in range(46):
                yield b" " * 1_000_000
            yield b'{"value": [{"id": "synthetic-large-response"}]}'

        def close(self):
            self.closed = True

    prepared = _live_prepared()
    body = Body()
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, headers={"Content-Type": "application/json"}, stream=body
            )
        )
    ) as client:
        result = MicrosoftHttpTransport(client=client, now=lambda: NOW).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset({"id"}),
        )
    assert result.record_count == 1
    assert body.closed


def test_compressed_response_is_decoded_exactly_once():
    import gzip

    class Body(httpx.SyncByteStream):
        def __iter__(self):
            yield gzip.compress(b'{"value": []}')

    prepared = _live_prepared()
    result = MicrosoftHttpTransport(
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Encoding": "gzip",
                    },
                    stream=Body(),
                )
            )
        ),
        now=lambda: NOW,
    ).collect(
        prepared=prepared,
        token=_lease(prepared),
        query={},
        allowed_record_fields=FIELDS,
        required_record_fields=frozenset(),
    )
    assert result.record_count == 0


def test_corrupt_compression_is_sanitized_without_retry():
    class Body(httpx.SyncByteStream):
        def __iter__(self):
            yield b"synthetic-invalid-gzip"

    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=Body())

    prepared = _live_prepared()
    with pytest.raises(MicrosoftTransportError, match="encoding is invalid") as caught:
        MicrosoftHttpTransport(
            client=httpx.Client(transport=httpx.MockTransport(handler)), now=lambda: NOW
        ).collect(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset(),
        )
    assert len(attempts) == 1
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("overflow", (False, True))
def test_collection_record_limits_cover_all_pages(overflow):
    responses = [
        _response(
            {
                "value": [{"id": "synthetic-one"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/devices?$skiptoken=two",
            }
        ),
        _response({"value": [{"id": "synthetic-two"}]}),
    ]
    requests = []

    def handler(request):
        requests.append(request)
        return responses[len(requests) - 1]

    limits = {"max_records": 2 - int(overflow)}
    prepared = _live_prepared()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        transport = MicrosoftHttpTransport(client=client, now=lambda: NOW, **limits)
        args = dict(
            prepared=prepared,
            token=_lease(prepared),
            query={},
            allowed_record_fields=FIELDS,
            required_record_fields=frozenset({"id"}),
        )
        if overflow:
            with pytest.raises(MicrosoftTransportError, match="collection .* limit"):
                transport.collect(**args)
        else:
            assert transport.collect(**args).record_count == 2
    assert len(requests) == 2


@pytest.mark.parametrize(
    "body",
    (
        b'{"value": [], "value": [{"id": "hidden"}]}',
        b'{"value": [{"id": "one", "id": "two"}]}',
        b'{"value": [{"id": "one", "accountEnabled": NaN}]}',
    ),
)
def test_ambiguous_json_cannot_become_a_complete_collection(body):
    prepared = _live_prepared()
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, content=body, headers={"Content-Type": "application/json"}
            )
        )
    ) as client:
        with pytest.raises(MicrosoftTransportError, match="JSON is invalid"):
            MicrosoftHttpTransport(client=client, now=lambda: NOW).collect(
                prepared=prepared,
                token=_lease(prepared),
                query={},
                allowed_record_fields=FIELDS,
                required_record_fields=frozenset({"id"}),
            )


def test_result_rejects_continuation_after_terminal_page():
    import hashlib
    import json
    from microsoft_evidence.transport import (
        MicrosoftTransportPage,
        MicrosoftTransportResult,
    )

    pages = tuple(
        MicrosoftTransportPage(
            page_sequence=index,
            request_url_sha256="0" * 64,
            response_sha256="1" * 64,
            observed_at=NOW,
            records=(),
            terminal=True,
            continuation_present=False,
        )
        for index in range(2)
    )
    chain = hashlib.sha256(
        json.dumps(
            tuple(page.response_sha256 for page in pages), separators=(",", ":")
        ).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="continue after a terminal"):
        MicrosoftTransportResult(
            pages=pages,
            input_id="synthetic",
            source_contract_id="synthetic",
            record_count=0,
            page_chain_sha256=chain,
        )


def test_invalid_next_page_is_consumed_and_closed():
    first = _response(
        {
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/devices?$skiptoken=two",
        }
    )

    class Body(httpx.SyncByteStream):
        count = 0
        closed = False

        def __iter__(self):
            for _ in range(10):
                self.count += 1
                yield b"x" * 8

        def close(self):
            self.closed = True

    body = Body()
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return first
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, stream=body
        )

    prepared = _live_prepared()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MicrosoftTransportError, match="JSON"):
            MicrosoftHttpTransport(
                client=client,
                now=lambda: NOW,
            ).collect(
                prepared=prepared,
                token=_lease(prepared),
                query={},
                allowed_record_fields=FIELDS,
                required_record_fields=frozenset(),
            )
    assert len(requests) == 2
    assert body.count == 10
    assert body.closed


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_response_interrupt_closes_stream_before_publishing(stop, monkeypatch):
    from microsoft_evidence import transport as module

    clock = {"elapsed": 0.0, "cancelled": False}
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["elapsed"])

    class Body(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b'{"value": ['
            clock["elapsed"] = 31.0 if stop == "deadline" else 1.0
            clock["cancelled"] = stop == "cancel"
            yield b'{"id": "synthetic-interrupted"}]}'

        def close(self):
            self.closed = True

    body = Body()
    prepared = _live_prepared()
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200, headers={"Content-Type": "application/json"}, stream=body
            )
        )
    ) as client:
        with pytest.raises(MicrosoftTransportError, match=stop):
            MicrosoftHttpTransport(client=client, now=lambda: NOW).collect(
                prepared=prepared,
                token=_lease(prepared),
                query={},
                allowed_record_fields=FIELDS,
                required_record_fields=frozenset({"id"}),
                cancelled=lambda: clock["cancelled"],
            )
    assert body.closed
