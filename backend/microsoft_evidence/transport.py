"""Closed-endpoint, paged Microsoft HTTP transport."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import re
from io import BytesIO
import time
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from pydantic import Field, model_validator

from evidence_types import Sha256, StrictModel

from .cloud import PreparedCollectionContext
from .live_authority import MicrosoftAccessTokenLease
from .source_registry import SOURCE_INPUTS, MicrosoftSourceInput
from .resource_authority import MicrosoftResourceToken, verify_resource_authority


def _require_utc(name: str, value: datetime) -> None:
    if value.utcoffset() is None or value.utcoffset().total_seconds() != 0:
        raise ValueError(f"{name} must be UTC")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _scope_sha256(prepared: PreparedCollectionContext) -> str:
    return hashlib.sha256(prepared.scope.model_dump_json().encode()).hexdigest()


def _operation_matches_route(operation: str, route: str) -> bool:
    """Match one concrete policy route to an exact registry path template."""

    operation_parts_text = operation.split()
    if len(operation_parts_text) < 2:
        return False
    operation_target = operation_parts_text[1]
    operation_path = (
        urlsplit(operation_target).path
        if operation_target.startswith(("https://", "http://"))
        else operation_target.split("?", maxsplit=1)[0]
    )
    route_parts = tuple(part for part in route.strip("/").split("/") if part)
    operation_parts = tuple(
        part for part in operation_path.strip("/").split("/") if part
    )
    if len(route_parts) != len(operation_parts):
        return False
    return all(
        expected == actual
        or (expected.startswith("{") and expected.endswith("}") and bool(actual))
        for expected, actual in zip(operation_parts, route_parts, strict=True)
    )


class MicrosoftTransportError(RuntimeError):
    """A Microsoft request failed without returning provider or secret content."""


class MicrosoftHTTPError(MicrosoftTransportError):
    """Retain only a numeric status from a failed resource request."""

    def __init__(self, status):
        self.status = status
        super().__init__(f"Microsoft request failed with status {status}")


class MicrosoftTransportCancelled(MicrosoftTransportError):
    """The caller cancelled collection at a safe request boundary."""


class MicrosoftRequestTimeout(MicrosoftTransportError):
    """A request or response deadline elapsed."""


class MicrosoftRequestTransportFailure(MicrosoftTransportError):
    """Request transport failed after its configured retries."""


def read_response_content(response, *, deadline, cancelled):
    """Read one decoded response without duplicate chunk storage or a byte cap.

    Elapsed time is checked between network reads, including after EOF. A blocking
    read remains subject to the client's socket timeout; worker termination is the
    hard cancellation boundary for a blocked network call.
    """

    def check():
        if cancelled():
            raise MicrosoftTransportCancelled("Microsoft collection was cancelled")
        if time.monotonic() >= deadline:
            raise MicrosoftRequestTimeout("Microsoft response deadline was exceeded")

    check()
    with BytesIO() as content:
        for chunk in response.iter_bytes():
            check()
            content.write(chunk)
        check()
        return content.getvalue()


class MicrosoftTransportPage(StrictModel):
    schema_version: Literal[1] = 1
    page_sequence: int = Field(strict=True, ge=0)
    request_url_sha256: Sha256
    response_sha256: Sha256
    observed_at: datetime
    records: tuple[dict[str, object], ...]
    terminal: bool
    continuation_present: bool

    @model_validator(mode="after")
    def validate_page(self) -> MicrosoftTransportPage:
        _require_utc("observed_at", self.observed_at)
        if self.terminal == self.continuation_present:
            raise ValueError("transport page terminal state is inconsistent")
        return self


class MicrosoftTransportResult(StrictModel):
    schema_version: Literal[1] = 1
    pages: tuple[MicrosoftTransportPage, ...]
    input_id: str
    source_contract_id: str
    record_count: int = Field(strict=True, ge=0)
    page_chain_sha256: Sha256

    @model_validator(mode="after")
    def validate_result(self) -> MicrosoftTransportResult:
        if not self.pages or not self.pages[-1].terminal:
            raise ValueError("transport result requires a terminal page")
        if any(page.terminal for page in self.pages[:-1]):
            raise ValueError("transport result cannot continue after a terminal page")
        if tuple(item.page_sequence for item in self.pages) != tuple(
            range(len(self.pages))
        ):
            raise ValueError("transport page sequence is not contiguous")
        if self.record_count != sum(len(item.records) for item in self.pages):
            raise ValueError("transport record count does not match pages")
        encoded = json.dumps(
            tuple(item.response_sha256 for item in self.pages),
            separators=(",", ":"),
        ).encode()
        if self.page_chain_sha256 != _sha256_bytes(encoded):
            raise ValueError("transport page-chain hash is not canonical")
        return self


def verify_microsoft_transport_authority(
    *,
    prepared: PreparedCollectionContext,
    token: MicrosoftAccessTokenLease | MicrosoftResourceToken,
    now: datetime,
) -> None:
    """Verify one token against its exact prepared endpoint authority."""

    if isinstance(token, MicrosoftResourceToken):
        verify_resource_authority(prepared, token, now)
        return
    verified = token.verified
    if prepared.classification != "live" or not verified.activation_allowed:
        raise MicrosoftTransportError(
            "Microsoft request does not have verified live authority"
        )
    expected = (
        _scope_sha256(prepared),
        prepared.permission_manifest_id,
        prepared.permission_manifest_sha256,
        prepared.endpoint.endpoint_policy_id,
        prepared.endpoint.endpoint_policy_sha256,
        prepared.credential_reference_id,
    )
    actual = (
        verified.scope_sha256,
        verified.permission_manifest_id,
        verified.permission_manifest_sha256,
        verified.endpoint_policy_id,
        verified.endpoint_policy_sha256,
        verified.credential_reference_id,
    )
    if actual != expected:
        raise MicrosoftTransportError(
            "verified Microsoft authority does not match endpoint policy"
        )
    _require_utc("transport authority time", now)
    if now < verified.not_before or now >= verified.expires_at:
        raise MicrosoftTransportError(
            "verified Microsoft token is expired or not current for collection"
        )


class MicrosoftHttpTransport:
    """Fetch one complete collection through an exact server-owned endpoint."""

    def __init__(
        self,
        *,
        client: httpx.Client,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        max_pages: int = 10_000,
        max_records: int = 100_000,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if timeout_seconds <= 0 or max_retries < 0:
            raise ValueError("Microsoft transport timeout or retry limit is invalid")
        if max_pages <= 0:
            raise ValueError("Microsoft transport size limits must be positive")
        if any(type(value) is not int or value <= 0 for value in (max_records,)):
            raise ValueError("Microsoft collection limits must be positive integers")
        self._client = client
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._max_pages = max_pages
        self._max_records = max_records
        self._sleep = sleep
        self._now = now

    def collect(
        self,
        *,
        prepared: PreparedCollectionContext,
        token: MicrosoftAccessTokenLease | MicrosoftResourceToken,
        query: Mapping[str, str],
        allowed_record_fields: frozenset[str],
        required_record_fields: frozenset[str],
        cancelled: Callable[[], bool] = lambda: False,
        source_input_id: str | None = None,
        offset_page_size: int | None = None,
        allow_continuation: bool = True,
    ) -> MicrosoftTransportResult:
        self._validate_authority(prepared=prepared, token=token)
        source = self._source_contract(prepared, source_input_id=source_input_id)
        if offset_page_size is not None:
            if (
                source.input_id
                not in (
                    "ms-defender-vulnerability-catalogue-v1",
                    "ms-defender-recommendation-v1",
                )
                or type(offset_page_size) is not int
                or not 1
                <= offset_page_size
                <= (
                    8000
                    if source.input_id == "ms-defender-vulnerability-catalogue-v1"
                    else 10000
                )
                or query
            ):
                raise MicrosoftTransportError("Invalid catalogue offset pagination")
            query = {"$top": str(offset_page_size), "$skip": "0"}
        if not required_record_fields <= allowed_record_fields:
            raise ValueError("required record fields must be allowlisted")
        if not allowed_record_fields <= frozenset(source.retained_fields):
            raise MicrosoftTransportError(
                "Microsoft response fields exceed the source contract"
            )
        if tuple(prepared.expected_roles) != tuple(source.application_permissions):
            raise MicrosoftTransportError(
                "Microsoft permission manifest does not match the source contract"
            )
        query_names = tuple(sorted(query))
        if len(query_names) != len(set(query_names)) or not set(query_names) <= set(
            prepared.endpoint.allowed_query_parameter_names
        ):
            raise MicrosoftTransportError(
                "Microsoft request query is not allowed by endpoint policy"
            )
        if any(not isinstance(value, str) for value in query.values()):
            raise MicrosoftTransportError("Microsoft request query values are invalid")
        self._validate_select_fields(
            query=query,
            allowed_record_fields=allowed_record_fields,
        )
        url = urlunsplit(
            (
                prepared.endpoint.scheme,
                prepared.endpoint.host,
                prepared.endpoint.path_template,
                urlencode(tuple(sorted(query.items()))),
                "",
            )
        )
        pages: list[MicrosoftTransportPage] = []
        record_count = 0
        while url:
            if httpx.URL(url).path != prepared.endpoint.path_template:
                raise MicrosoftTransportError(
                    "HTTP URL normalization changes the prepared endpoint path"
                )
            if len(pages) >= self._max_pages:
                raise MicrosoftTransportError("Microsoft paging limit was exceeded")
            if cancelled():
                raise MicrosoftTransportCancelled("Microsoft collection was cancelled")
            response = self._request(
                url=url,
                authorization=token.authorization_header(),
                cancelled=cancelled,
            )
            observed_at = self._now()
            _require_utc("transport observed_at", observed_at)
            expiry = (
                token.acquisition.expires_at
                if isinstance(token, MicrosoftResourceToken)
                else token.verified.expires_at
            )
            if observed_at >= expiry:
                raise MicrosoftTransportError(
                    "verified Microsoft token expired during collection"
                )
            records, next_link = self._validate_response(
                response,
                allowed_record_fields=allowed_record_fields,
                required_record_fields=required_record_fields,
                single_record=(
                    source.input_id == "ms-intune-managed-device-v1"
                    and re.fullmatch(
                        r"/v1\.0/deviceManagement/managedDevices/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                        prepared.endpoint.path_template,
                    )
                    is not None
                )
                or (
                    source.input_id == "ms-defender-vulnerability-catalogue-v1"
                    and re.fullmatch(
                        r"/api/vulnerabilities/CVE-[0-9]{4}-[0-9]{4,19}",
                        prepared.endpoint.path_template,
                    )
                    is not None
                ),
                exact_numbers=source.input_id
                in (
                    "ms-defender-vulnerability-catalogue-v1",
                    "ms-defender-vulnerability-baseline-v1",
                    "ms-defender-vulnerability-events-v1",
                    "ms-defender-recommendation-v1",
                ),
                discard_unretained_fields=source.input_id
                in (
                    "ms-defender-machine-v1",
                    "ms-defender-missing-kb-v1",
                    "ms-defender-antivirus-health-v1",
                    "ms-defender-vulnerability-catalogue-v1",
                    "ms-defender-vulnerability-baseline-v1",
                    "ms-defender-vulnerability-events-v1",
                    "ms-defender-recommendation-v1",
                    "ms-defender-recommendation-device-v1",
                ),
            )
            if not allow_continuation and next_link is not None:
                raise MicrosoftTransportError(
                    "Single-device collection cannot follow a continuation"
                )
            if offset_page_size is not None:
                if len(records) > offset_page_size:
                    raise MicrosoftTransportError(
                        "Catalogue exceeded requested page size"
                    )
                # This endpoint documents offsets, not mandatory next links. A
                # full page requires another request, including an empty final
                # page when the catalogue size is an exact multiple of $top.
                expected_next = None
                if len(records) == offset_page_size:
                    expected_next = urlunsplit(
                        (
                            prepared.endpoint.scheme,
                            prepared.endpoint.host,
                            prepared.endpoint.path_template,
                            urlencode(
                                {
                                    "$top": str(offset_page_size),
                                    "$skip": str(record_count + len(records)),
                                }
                            ),
                            "",
                        )
                    )
                if next_link is not None:
                    checked = self._validate_next_link(
                        prepared=prepared,
                        value=next_link,
                        allowed_record_fields=allowed_record_fields,
                    )
                    if (
                        expected_next is None
                        or httpx.URL(checked).params != httpx.URL(expected_next).params
                    ):
                        raise MicrosoftTransportError(
                            "Catalogue continuation differs from expected offset"
                        )
                next_link = expected_next
            record_count += len(records)
            if record_count > self._max_records:
                raise MicrosoftTransportError(
                    "Microsoft collection record limit was exceeded"
                )
            if next_link is not None:
                next_link = self._validate_next_link(
                    prepared=prepared,
                    value=next_link,
                    allowed_record_fields=allowed_record_fields,
                )
            pages.append(
                MicrosoftTransportPage(
                    page_sequence=len(pages),
                    request_url_sha256=_sha256_bytes(url.encode()),
                    response_sha256=_sha256_bytes(response.content),
                    observed_at=observed_at,
                    records=tuple(records),
                    terminal=next_link is None,
                    continuation_present=next_link is not None,
                )
            )
            url = next_link or ""
        encoded = json.dumps(
            tuple(item.response_sha256 for item in pages),
            separators=(",", ":"),
        ).encode()
        return MicrosoftTransportResult(
            pages=tuple(pages),
            input_id=source.input_id,
            source_contract_id=source.source_contract_id,
            record_count=sum(len(item.records) for item in pages),
            page_chain_sha256=_sha256_bytes(encoded),
        )

    @staticmethod
    def _source_contract(
        prepared: PreparedCollectionContext, *, source_input_id: str | None = None
    ) -> MicrosoftSourceInput:
        route = prepared.endpoint.path_template
        for prefix in ("/v1.0", "/beta"):
            if route.startswith(prefix):
                route = route[len(prefix) :]
                break
        candidates = tuple(
            source
            for source in SOURCE_INPUTS
            if (source_input_id is None or source.input_id == source_input_id)
            and any(
                _operation_matches_route(operation, route)
                for operation in source.operations
            )
            and (
                (
                    prepared.scope.product == "entra"
                    and source.input_id.startswith("ms-entra-")
                )
                or (
                    prepared.scope.product == "intune"
                    and source.input_id.startswith("ms-intune-")
                )
                or (
                    prepared.scope.product == "defender"
                    and source.input_id.startswith("ms-defender-")
                )
            )
        )
        if len(candidates) != 1:
            raise MicrosoftTransportError(
                "Microsoft endpoint does not resolve to one source contract"
            )
        return candidates[0]

    def _validate_authority(
        self,
        *,
        prepared: PreparedCollectionContext,
        token: MicrosoftAccessTokenLease | MicrosoftResourceToken,
    ) -> None:
        verify_microsoft_transport_authority(
            prepared=prepared,
            token=token,
            now=self._now(),
        )

    def _request(
        self,
        *,
        url: str,
        authorization: str,
        cancelled: Callable[[], bool],
    ) -> httpx.Response:
        retry = 0
        while True:
            if cancelled():
                raise MicrosoftTransportCancelled("Microsoft collection was cancelled")
            try:
                deadline = time.monotonic() + self._timeout
                with self._client.stream(
                    "GET",
                    url,
                    headers={
                        "Authorization": authorization,
                        "Accept": "application/json",
                    },
                    timeout=self._timeout,
                    follow_redirects=False,
                ) as streamed:
                    headers = dict(streamed.headers)
                    content = b""
                    if streamed.status_code == 200:
                        content = read_response_content(
                            streamed, deadline=deadline, cancelled=cancelled
                        )
                    # iter_bytes has already decoded content encoding. Do not
                    # decode it again when constructing the bounded response.
                    headers.pop("content-encoding", None)
                    headers.pop("content-length", None)
                    response = httpx.Response(
                        streamed.status_code, headers=headers, content=content
                    )
            except httpx.DecodingError:
                raise MicrosoftTransportError(
                    "Microsoft response encoding is invalid"
                ) from None
            except httpx.TransportError as exc:
                if retry >= self._max_retries:
                    reason = (
                        "timed out"
                        if isinstance(exc, httpx.TimeoutException)
                        else "failed"
                    )
                    error_type = (
                        MicrosoftRequestTimeout
                        if isinstance(exc, httpx.TimeoutException)
                        else MicrosoftRequestTransportFailure
                    )
                    raise error_type(
                        f"Microsoft request {reason} after retry limit"
                    ) from None
                retry += 1
                self._wait(1.0, cancelled=cancelled)
                continue
            if response.status_code in (429, 503):
                if retry >= self._max_retries:
                    raise MicrosoftHTTPError(response.status_code)
                retry += 1
                self._wait(
                    self._retry_after(response),
                    cancelled=cancelled,
                )
                continue
            if response.status_code != 200:
                raise MicrosoftHTTPError(response.status_code)
            return response

    def _wait(self, seconds: float, *, cancelled: Callable[[], bool]) -> None:
        remaining = seconds
        while remaining > 0:
            if cancelled():
                raise MicrosoftTransportCancelled("Microsoft collection was cancelled")
            interval = min(remaining, 0.5)
            self._sleep(interval)
            remaining -= interval
        if cancelled():
            raise MicrosoftTransportCancelled("Microsoft collection was cancelled")

    @staticmethod
    def _retry_after(response: httpx.Response) -> float:
        try:
            seconds = float(response.headers.get("Retry-After", "1"))
        except ValueError:
            return 1.0
        return min(max(seconds, 0.0), 60.0)

    def _validate_response(
        self,
        response: httpx.Response,
        *,
        allowed_record_fields: frozenset[str],
        required_record_fields: frozenset[str],
        discard_unretained_fields: bool = False,
        exact_numbers: bool = False,
        single_record: bool = False,
    ) -> tuple[list[dict[str, object]], str | None]:
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
        if content_type.casefold() != "application/json":
            raise MicrosoftTransportError("Microsoft response content type is invalid")
        try:

            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("Duplicate JSON key")
                    result[key] = value
                return result

            def reject_constant(value):
                raise ValueError("Nonfinite JSON number")

            payload = json.loads(
                response.content,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
                parse_float=Decimal if exact_numbers else float,
            )
        except (ValueError, RecursionError) as exc:
            raise MicrosoftTransportError("Microsoft response JSON is invalid") from exc
        if single_record:
            if not isinstance(payload, dict) or "@odata.nextLink" in payload:
                raise MicrosoftTransportError(
                    "Microsoft single-record response is invalid"
                )
            payload = {
                "value": [
                    {
                        key: value
                        for key, value in payload.items()
                        if key not in ("@odata.context", "@odata.type")
                    }
                ]
            }
        allowed_envelope = {
            "value",
            "@odata.count",
            "@odata.context",
            "@odata.nextLink",
            "@odata.deltaLink",
        }
        if not isinstance(payload, dict) or not set(payload) <= allowed_envelope:
            raise MicrosoftTransportError("Microsoft response envelope is invalid")
        if "@odata.count" in payload and (
            type(payload["@odata.count"]) is not int or payload["@odata.count"] < 0
        ):
            raise MicrosoftTransportError("Microsoft response count is invalid")
        records = payload.get("value")
        if not isinstance(records, list) or any(
            not isinstance(item, dict) for item in records
        ):
            raise MicrosoftTransportError("Microsoft response records are invalid")
        for item in records:
            fields = set(item)
            if not required_record_fields <= fields or (
                not discard_unretained_fields and not fields <= allowed_record_fields
            ):
                raise MicrosoftTransportError(
                    "Microsoft response record schema is invalid"
                )
        next_link = payload.get("@odata.nextLink")
        if next_link is not None and not isinstance(next_link, str):
            raise MicrosoftTransportError("Microsoft continuation link is invalid")
        if next_link is not None and "@odata.deltaLink" in payload:
            raise MicrosoftTransportError(
                "Microsoft response cannot contain next and delta links together"
            )
        # Defender device and missing-KB endpoints return full provider objects.
        # Project before record storage, durable bundles, or database ingestion.
        # The separate response hash still fingerprints the full received body.
        return [
            {key: value for key, value in item.items() if key in allowed_record_fields}
            for item in records
        ], next_link

    @staticmethod
    def _validate_select_fields(
        *, query: Mapping[str, str], allowed_record_fields: frozenset[str]
    ) -> None:
        selected = query.get("$select")
        if selected is None:
            return
        fields = tuple(part.strip() for part in selected.split(","))
        if (
            not fields
            or any(not field for field in fields)
            or len(set(fields)) != len(fields)
            or not set(fields) <= allowed_record_fields
        ):
            raise MicrosoftTransportError(
                "Microsoft select fields exceed the source contract"
            )

    @staticmethod
    def _validate_next_link(
        *,
        prepared: PreparedCollectionContext,
        value: str,
        allowed_record_fields: frozenset[str],
    ) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != prepared.endpoint.scheme
            or parsed.hostname != prepared.endpoint.host
            or parsed.port not in (None, prepared.endpoint.port)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.path != prepared.endpoint.path_template
        ):
            raise MicrosoftTransportError(
                "Microsoft continuation endpoint is not allowed by policy"
            )
        query = parse_qsl(parsed.query, keep_blank_values=True)
        names = tuple(name for name, _value in query)
        allowed = set(prepared.endpoint.allowed_query_parameter_names) | set(
            prepared.endpoint.paging_query_parameter_names
        )
        if len(names) != len(set(names)) or not set(names) <= allowed:
            raise MicrosoftTransportError(
                "Microsoft continuation query is not allowed by policy"
            )
        MicrosoftHttpTransport._validate_select_fields(
            query=dict(query),
            allowed_record_fields=allowed_record_fields,
        )
        return value


__all__ = [
    "MicrosoftHttpTransport",
    "MicrosoftTransportCancelled",
    "MicrosoftTransportError",
    "MicrosoftTransportPage",
    "MicrosoftTransportResult",
]
