"""Collect a bounded Defender catalogue with verified offset pagination."""

from datetime import datetime, timezone
import re
from standalone.evidence_pipeline.source_json import encode_source_records

from standalone.evidence_pipeline.contracts import Snapshot
from standalone.evidence_pipeline.parsing.vulnerability_catalogue import (
    RETAINED_FIELDS,
    normalize_catalogue,
)

from .pipeline import connection_scope
from .source_registry import SOURCE_INPUTS

INPUT_ID = "ms-defender-vulnerability-catalogue-v1"
PATH = "/api/vulnerabilities"


def selected_catalogue_cve(scope):
    if not scope.scope_reference.startswith("cve-id"):
        return None
    value = scope.scope_reference.removeprefix("cve-id:")
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", value):
        raise ValueError("Invalid selected catalogue CVE")
    return value


def catalogue_path(scope):
    selected = selected_catalogue_cve(scope)
    return PATH if selected is None else PATH + "/" + selected


def collect_catalogue(
    *,
    scope,
    execution_id,
    prepared,
    token,
    transport,
    now=lambda: datetime.now(timezone.utc),
    cancelled=lambda: False,
):
    if (scope.source, scope.input_kind, scope.origin) != (
        "Defender",
        "vulnerability_catalogue",
        "lab",
    ):
        raise ValueError("Catalogue collection requires its dedicated Microsoft scope")
    if prepared.scope != connection_scope(scope, cloud=prepared.scope.cloud):
        raise ValueError("Catalogue authority differs from connection")
    selected = selected_catalogue_cve(scope)
    if prepared.endpoint.path_template != catalogue_path(scope):
        raise ValueError("Catalogue requires its fixed endpoint")
    started = now()
    source = next(item for item in SOURCE_INPUTS if item.input_id == INPUT_ID)
    result = transport.collect(
        prepared=prepared,
        token=token,
        source_input_id=INPUT_ID,
        query={},
        allowed_record_fields=RETAINED_FIELDS,
        required_record_fields=frozenset({"id"}),
        cancelled=cancelled,
        offset_page_size=8000 if selected is None else None,
        allow_continuation=selected is None,
    )
    if (
        result.input_id != INPUT_ID
        or result.source_contract_id != source.source_contract_id
        or not result.pages
        or not result.pages[-1].terminal
    ):
        raise ValueError("Catalogue response lacks a complete matching source contract")
    raw = [record for page in result.pages for record in page.records]
    if selected is not None and (len(raw) != 1 or raw[0].get("id") != selected):
        raise ValueError("Catalogue response differs from selected CVE")
    payload = encode_source_records(raw)
    snapshot = Snapshot(scope, execution_id, started, now(), "success", True, payload)
    normalize_catalogue(snapshot)
    return snapshot
