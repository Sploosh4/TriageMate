"""Synthetic provider refusals retain safe categories through durable collection."""

from uuid import uuid4

import httpx
import pytest

from microsoft_evidence.failures import failure_code
from microsoft_evidence.live_authority import MicrosoftTokenRequestError
from microsoft_evidence.pipeline import prepare_device_collection, connection_scope
from microsoft_evidence.resource_authority import acquire_resource_token
from microsoft_evidence.transport import MicrosoftHttpTransport
from tests.test_microsoft_live_authority import NOW, _live_prepared
from tests.test_microsoft_pipeline import scope
from tests.test_microsoft_transport import _lease
from tests.test_microsoft_resource_authority import Resolver


@pytest.mark.parametrize(
    "status,code",
    [
        (401, "microsoft_authentication_rejected"),
        (403, "microsoft_access_forbidden"),
        (404, "microsoft_collection_failed"),
        (429, "microsoft_request_throttled"),
        (503, "microsoft_service_unavailable"),
        (500, "microsoft_service_unavailable"),
    ],
)
def test_resource_refusal_is_durable_without_provider_body(tmp_path, status, code):
    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, text="synthetic-private-provider-body")
        )
    ) as client:
        result = prepare_device_collection(
            scope=source,
            execution_id=str(uuid4()),
            root=tmp_path,
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(
                client=client, now=lambda: NOW, max_retries=0
            ),
            now=lambda: NOW,
        )
    assert result.error_code == code and not result.complete
    assert result.payload == b""
    assert "synthetic-private-provider-body" not in repr(result)


@pytest.mark.parametrize(
    "status,code",
    [
        (400, "microsoft_token_request_rejected"),
        (401, "microsoft_token_request_rejected"),
        (403, "microsoft_token_request_rejected"),
        (500, "microsoft_service_unavailable"),
        (429, "microsoft_request_throttled"),
    ],
)
def test_token_refusal_never_infers_expiry_or_retains_body(status, code):
    prepared = _live_prepared(scope=connection_scope(scope()))
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, text="synthetic-private-token-error")
        )
    ) as client:
        with pytest.raises(MicrosoftTokenRequestError) as caught:
            acquire_resource_token(
                prepared=prepared,
                credential_resolver=Resolver(),
                client=client,
                now=NOW,
            )
    assert failure_code(caught.value) == code
    assert "synthetic-private-token-error" not in str(caught.value)


@pytest.mark.parametrize(
    "error,code",
    [
        (httpx.ReadTimeout, "microsoft_token_request_timeout"),
        (httpx.ConnectTimeout, "microsoft_token_request_timeout"),
        (httpx.ConnectError, "microsoft_token_transport_failed"),
        (httpx.RemoteProtocolError, "microsoft_token_transport_failed"),
    ],
)
def test_token_transport_labels_discard_request_and_exception_details(error, code):
    prepared = _live_prepared(scope=connection_scope(scope()))

    def fail(request):
        raise error("synthetic-private-token-detail", request=request)

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(RuntimeError) as caught:
            acquire_resource_token(
                prepared=prepared,
                credential_resolver=Resolver(),
                client=client,
                now=NOW,
            )
    assert failure_code(caught.value) == code
    assert "synthetic-private" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


@pytest.mark.parametrize(
    "error,code",
    [
        (httpx.ReadTimeout, "microsoft_request_timeout"),
        (httpx.ConnectError, "microsoft_request_transport_failed"),
        (httpx.RemoteProtocolError, "microsoft_request_transport_failed"),
    ],
)
def test_resource_transport_category_survives_durable_collection(tmp_path, error, code):
    source = scope()
    prepared = _live_prepared(scope=connection_scope(source))
    calls = []

    def fail(request):
        calls.append(1)
        raise error("synthetic-private-resource-detail", request=request)

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        result = prepare_device_collection(
            scope=source,
            execution_id=str(uuid4()),
            root=tmp_path,
            prepared=prepared,
            token=_lease(prepared),
            transport=MicrosoftHttpTransport(
                client=client, now=lambda: NOW, max_retries=1, sleep=lambda _: None
            ),
            now=lambda: NOW,
        )
    assert len(calls) == 2
    assert result.error_code == code and not result.complete
    assert result.payload == b""
    assert "synthetic-private" not in repr(result)


def test_arbitrary_exception_text_cannot_claim_a_diagnostic_category():
    assert (
        failure_code(RuntimeError("microsoft_request_timeout"))
        == "microsoft_collection_failed"
    )
