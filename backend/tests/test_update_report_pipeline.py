"""Policy and device boundaries for synthetic Intune report exports."""

from dataclasses import replace
from datetime import timedelta
import json
from types import SimpleNamespace as NS
from uuid import uuid4

import pytest

from microsoft_evidence.pipeline import connection_scope
from microsoft_evidence.intune_report_transport import (
    build_injected_update_report_export,
)
from microsoft_evidence.update_report_pipeline import (
    collect_update_status,
    POLICY_SCOPE_PREFIX,
)
from standalone.evidence_pipeline.contracts import SourceScope, Snapshot
from tests.test_intune_report_transport import (
    _row,
    POLICY_ID,
    DEVICE_ID,
)
from tests.test_microsoft_live_authority import NOW


def collection(rows=None):
    scope = SourceScope(
        str(uuid4()),
        "Intune",
        "update_status",
        POLICY_SCOPE_PREFIX + POLICY_ID,
        "lab",
        "Explicitly synthetic report test",
        str(uuid4()),
    )
    device_scope = replace(scope, input_kind="devices", connection_id=str(uuid4()))
    device = Snapshot(
        device_scope,
        str(uuid4()),
        NOW,
        NOW,
        "success",
        True,
        json.dumps([{"id": DEVICE_ID}]).encode(),
    )
    authority = connection_scope(scope)
    export = build_injected_update_report_export(
        scope=authority,
        policy_id=POLICY_ID,
        records=[_row()] if rows is None else rows,
        observed_at=NOW + timedelta(seconds=1),
        job_id="synthetic-job",
    )
    moments = iter([NOW, NOW + timedelta(seconds=2)])
    args = dict(
        scope=scope,
        execution_id=str(uuid4()),
        device_snapshot=device,
        prepared=NS(
            scope=authority,
            endpoint=NS(path_template="/beta/deviceManagement/reports/exportJobs"),
        ),
        transport=NS(collect=lambda policy: export),
        now=lambda: next(moments),
    )
    return args, export


def test_policy_status_keeps_facts_and_excludes_user_principal_name():
    args, _ = collection()
    result = collect_update_status(**args)
    (row,) = result.records()
    assert row["DeviceId"] == DEVICE_ID and row["PolicyId"] == POLICY_ID
    assert row["CurrentDeviceUpdateStatus"] == "Downloading"
    assert "UPN" not in row and "cve_id" not in row


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope_reference", "all-intune"),
        ("tenant_id", "00000000-0000-4000-8000-000000000099"),
        ("origin", "synthetic"),
        ("input_kind", "devices"),
    ],
)
def test_wrong_scope_rejected_before_collect(field, value):
    args, _ = collection()
    args["scope"] = replace(args["scope"], **{field: value})
    args["transport"].collect = lambda policy: pytest.fail("Collected with wrong scope")
    with pytest.raises(ValueError):
        collect_update_status(**args)


@pytest.mark.parametrize(
    "change", ["policy", "authority", "observation", "device", "duplicate"]
)
def test_wrong_export_or_unbound_rows_rejected(change):
    rows = [_row(DeviceId=str(uuid4()))] if change == "device" else [_row()]
    if change == "duplicate":
        rows *= 2
    args, export = collection(rows)
    if change == "policy":
        export = export.model_copy(update={"policy_id": str(uuid4())})
    if change == "authority":
        export = export.model_copy(update={"authority_scope_sha256": "0" * 64})
    if change == "observation":
        export = export.model_copy(update={"observed_at": NOW + timedelta(seconds=3)})
    args["transport"].collect = lambda policy: export
    with pytest.raises(ValueError):
        collect_update_status(**args)


def test_complete_empty_policy_report_stays_empty():
    args, _ = collection([])
    assert collect_update_status(**args).records() == []


@pytest.mark.parametrize("bound", ["MAX_RECORDS"])
def test_report_aggregate_bound(monkeypatch, bound):
    import microsoft_evidence.update_report_pipeline as pipeline

    args, _ = collection()
    monkeypatch.setattr(pipeline, bound, 0)
    with pytest.raises(ValueError, match="bounds"):
        collect_update_status(**args)


def test_http_export_accepts_connection_scope_and_never_sends_token_to_download():
    import httpx
    from microsoft_evidence.intune_report_transport import (
        HttpIntuneUpdateReportTransport,
    )
    from tests.test_intune_report_transport import (
        _prepared,
        _lease,
        _zip_csv,
        _completed_handler,
    )

    args, _ = collection()
    prepared = _prepared(connection_scope(args["scope"]))
    original = _completed_handler(_zip_csv([_row()]))
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            assert "authorization" not in request.headers
        return original(request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        args.update(
            prepared=prepared,
            now=lambda: NOW + timedelta(minutes=1),
            transport=HttpIntuneUpdateReportTransport(
                client=client,
                prepared=prepared,
                token=_lease(prepared),
                now=lambda: NOW + timedelta(minutes=1),
                poll_interval_seconds=0,
            ),
        )
        result = collect_update_status(**args)
    assert result.complete and len(result.records()) == 1
    assert [r.method for r in requests] == ["POST", "GET"]


@pytest.mark.parametrize(
    "suffix",
    [
        "",
        ":group:",
        ":group:00000000-0000-0000-0000-000000000000",
        ":group:not-a-uuid",
        ":group:22222222-3333-4444-8555-666666666666:group:other",
    ],
)
def test_fresh_isolation_requires_one_canonical_nonzero_group(suffix):
    from microsoft_evidence.update_report_pipeline import isolation_group_id, policy_id

    args, _ = collection()
    scope = replace(
        args["scope"], scope_reference=POLICY_SCOPE_PREFIX + POLICY_ID + suffix
    )
    if not suffix:
        assert policy_id(scope) == POLICY_ID  # Historical replay compatibility.
    with pytest.raises(ValueError):
        isolation_group_id(scope)
