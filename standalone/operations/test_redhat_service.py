"""Active MSRC/Catalog index collection proves imports before acknowledging success."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import time
from uuid import uuid4
import pytest

from standalone.evidence_pipeline.runtime import local_database
from standalone.evidence_pipeline.test_commands import cleanup
from standalone.evidence_pipeline.test_redhat_advisories import document
from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.redhat_discovery import BASE, INDEX_URL
from types import SimpleNamespace


@pytest.mark.parametrize(
    "source,mode",
    [
        (source, mode)
        for source in ("Microsoft Update Catalog", "MSRC")
        for mode in ("complete", "budget", "missing")
    ]
    + [
        ("Microsoft Update Catalog", "incomplete"),
        ("Microsoft Update Catalog", "repeat"),
        ("Microsoft Update Catalog", "empty"),
        ("MSRC", "membership"),
        ("MSRC", "repeat"),
        ("MSRC", "recovery"),
    ],
)
def test_application_schedules_discovery_index(tmp_path, source, mode):
    pass_limit = 1 if mode == "budget" else 100
    if source == "Red Hat":
        payloads, scopes = {}, []
        for _ in range(2):
            number = str(uuid4().int % 9_000_000_000 + 1_000_000_000)
            path = "2099/rhsa-2099_" + number + ".json"
            raw = document()
            raw["document"]["tracking"]["id"] = "RHSA-2099:" + number
            raw["vulnerabilities"] = []
            payloads[path] = json.dumps(raw).encode()
            scopes.append(
                SimpleNamespace(
                    connection_id=stable_id(
                        "redhat-discovered-source", "synthetic", BASE + path
                    ),
                    origin="synthetic",
                    tenant_id=None,
                )
            )
        index = "\n".join(payloads) + "\n"
    elif source == "MSRC":
        from io import BytesIO
        from standalone.evidence_pipeline.test_msrc_publications import entry, CONTEXT
        from standalone.evidence_pipeline.parsing.msrc_publications import publications
        from standalone.evidence_pipeline.collection.msrc_discovered_collection import (
            source_scope,
        )

        year = 2100 + uuid4().int % 7800
        months = [f"{year}-Jan", f"{year}-Feb"]
        index = json.dumps(
            {"@odata.context": CONTEXT, "value": [entry(month) for month in months]}
        )
        # Empty valid months isolate scheduler/receipt behavior; populated CVRF
        # writer, patch joins and completeness are tested transactionally elsewhere.
        from standalone.evidence_pipeline.test_cvrf_updates import (
            document as cvrf_document,
        )

        empty = cvrf_document()
        empty["Vulnerability"] = []
        payloads = {month: json.dumps(empty).encode() for month in months}
        scopes = [
            source_scope("synthetic", item)
            for item in publications(BytesIO(index.encode()))
        ]
        with local_database().connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM evidence.source_connections WHERE id=ANY(%s::uuid[])",
                ([scope.connection_id for scope in scopes],),
            )
            assert cur.fetchone() == (0,), (
                "Generated test months must not overlap retained scopes"
            )
    elif source == "Cisco":
        from standalone.evidence_pipeline.test_cisco_collection import fixtures
        from standalone.evidence_pipeline.parsing.cisco_rss import parse_feed
        from standalone.evidence_pipeline.collection.cisco_collection import (
            source_scope,
        )

        raw_index, payloads = fixtures(
            tuple("cisco-sa-synthetic-" + uuid4().hex for _ in range(2))
        )
        index = raw_index.decode()
        scopes = [source_scope("synthetic", item) for item in parse_feed(raw_index)]
    else:
        index, payloads, scopes = catalog_fixture(mode)
    complete_payloads = dict(payloads)
    if mode in {"missing", "recovery"}:
        del payloads[min(payloads) if source == "Cisco" else next(iter(payloads))]
    if mode == "malformed":
        payloads[min(payloads)] = b"{}"
    fixture = tmp_path / "synthetic-repository.json"
    fixture.write_text(
        json.dumps(
            {
                "origin": "synthetic",
                "index": index,
                "records": {path: wire.decode() for path, wire in payloads.items()},
            }
        )
    )
    fixture.chmod(0o600)
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    key, input_id = "synthetic-redhat-service-" + str(uuid4()), str(uuid4())
    config = tmp_path / "operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=5,
                inputs=[
                    dict(
                        scope=dict(
                            connection_id=input_id,
                            source=source,
                            input_kind="repository"
                            if source != "Microsoft Update Catalog"
                            else "catalog_search",
                            scope_reference="https://api.msrc.microsoft.com/cvrf/v3.0/updates"
                            if source == "MSRC"
                            else INDEX_URL
                            if source == "Red Hat"
                            else "https://sec.cloudapps.cisco.com/security/center/csaf_10.xml"
                            if source == "Cisco"
                            else "https://www.catalog.update.microsoft.com/Search.aspx?q=KB9999991",
                            origin="synthetic",
                            provenance="Explicitly synthetic repository service acceptance",
                        ),
                        schedule=dict(
                            kind="interval",
                            seconds=5
                            if mode in {"repeat", "recovery", "membership"}
                            else 3600,
                            anchor=(
                                datetime.now(timezone.utc) + timedelta(seconds=1)
                            ).isoformat(),
                            offset_seconds=0,
                        ),
                        bundle_root=str(root),
                        synthetic_input=str(fixture),
                        allow_network=False,
                        parameters=dict(
                            record_limit=1,
                            pass_limit=pass_limit,
                            **(
                                {"starting_month": months[0], "retained_ids": []}
                                if source == "MSRC"
                                else {"kb": "KB9999991"}
                                if source == "Microsoft Update Catalog"
                                else {}
                            ),
                        ),
                    )
                ],
            )
        )
    )
    config.chmod(0o600)
    from app.services.operations_api import create_service
    from app.services.postgres_query import PostgreSQLQueries

    service, run = None, None
    try:
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        service.request_mode("running")
        deadline = time.monotonic() + 30
        changed = False
        failure_notice_id = None
        expected_runs = 2 if mode in {"repeat", "recovery", "membership"} else 1
        while time.monotonic() < deadline:
            status = service.status()
            runs = [path.name for path in root.iterdir() if path.is_dir()]
            if (
                mode in {"recovery", "membership"}
                and not changed
                and len(runs) == 1
                and not status["inputs"][0]["active"]
                and not status["recovery_required"]
            ):
                # Change upstream evidence only between completed scheduled runs.
                # Recovery is a new run, not a retry of the immutable failed one.
                if mode == "recovery":
                    from .notifications import load

                    notices = load(key)
                    assert status["inputs"][0]["latest_success"] is False
                    assert len(notices) == 1
                    assert notices[0]["status"] == "unresolved"
                    failure_notice_id = notices[0]["id"]
                    payloads = complete_payloads
                else:
                    assert status["inputs"][0]["latest_success"] is True
                    # Retain one member, drop one and add a distinct advisory.
                    if source == "MSRC":
                        revised = entry(months[0])
                        revised["CurrentReleaseDate"] = "2099-04-01T00:00:00Z"
                        revised["DocumentTitle"] = "Revised synthetic publication"
                        added = f"{year}-Mar"
                        index = json.dumps(
                            {
                                "@odata.context": CONTEXT,
                                "value": [revised, entry(added)],
                            }
                        )
                        payloads = {
                            month: complete_payloads[months[0]]
                            for month in (months[0], added)
                        }
                        members = publications(BytesIO(index.encode()))
                    else:
                        raw_index, payloads = fixtures(
                            (min(payloads), "cisco-sa-synthetic-" + uuid4().hex)
                        )
                        index = raw_index.decode()
                        members = parse_feed(raw_index)
                    for item in members:
                        scope = source_scope("synthetic", item)
                        if scope.connection_id not in {x.connection_id for x in scopes}:
                            scopes.append(scope)
                fixture.write_text(
                    json.dumps(
                        {
                            "origin": "synthetic",
                            "index": index,
                            "records": {
                                path: wire.decode() for path, wire in payloads.items()
                            },
                        }
                    )
                )
                changed = True
            if (
                len(runs) >= expected_runs
                and not status["inputs"][0]["active"]
                and not status["recovery_required"]
            ):
                break
            time.sleep(0.05)
        assert len(runs) == expected_runs and not status["inputs"][0]["active"], status
        successful = mode in {"complete", "repeat", "empty", "recovery", "membership"}
        assert status["inputs"][0]["latest_success"] is successful, status
        run = status["inputs"][0]["latest_snapshot"] if successful else runs[0]
        expected_snapshot = run if successful else None
        assert status["inputs"][0]["latest_snapshot"] == expected_snapshot
        from .notifications import load as notifications

        # The private index declaration is not an analyst notification.
        notices = notifications(key)
        if mode == "recovery":
            assert changed and len(notices) == 1
            assert notices[0]["id"] == failure_notice_id
            assert notices[0]["status"] == "resolved"
        elif successful:
            assert notices == []
        else:
            assert len(notices) == 1
            assert notices[0]["category"] == "collection-failure"
            assert notices[0]["urgency"] == "critical"
            assert notices[0]["status"] == "unresolved"
        response = PostgreSQLQueries().execute(
            dict(
                requestId=str(uuid4()),
                sql=(
                    "SELECT count(DISTINCT connection_id) FROM evidence.collection_attempts WHERE complete AND outcome='success' AND connection_id IN ("
                    if source == "MSRC"
                    else "SELECT count(*) FROM evidence_pipeline.current_public_references WHERE connection_id IN ("
                )
                + (
                    ",".join("'" + scope.connection_id + "'::uuid" for scope in scopes)
                    or "NULL"
                )
                + ")",
            )
        )
        assert json.loads(response)["rows"] == [
            [
                3
                if mode == "membership"
                else 2
                if mode in {"complete", "repeat", "incomplete", "recovery"}
                else 1
                if mode in {"budget", "malformed"}
                else 0
            ]
        ]
        if mode in {"repeat", "membership", "recovery"}:
            with local_database().connect() as conn, conn.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=ANY(%s::uuid[]) AND complete AND outcome='success'",
                    ([scope.connection_id for scope in scopes],),
                )
                assert cursor.fetchone() == (2 if mode == "recovery" else 4,)
        service.request_mode("off")
        service.close(timeout=5)
        service = create_service(tmp_path, config, key)
        assert service.status()["state"] == "off"
        assert service.status()["inputs"][0]["latest_snapshot"] == expected_snapshot
    finally:
        if service is not None:
            service.close(timeout=5)
        with (
            closing(local_database().connect()) as connection,
            connection,
            connection.cursor() as cursor,
        ):
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
        for scope in scopes:
            with (
                local_database().connect() as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(
                    "DELETE FROM evidence.public_reference_observations WHERE receipt_id IN "
                    "(SELECT r.id FROM evidence.observation_receipts r JOIN evidence.source_revisions rev "
                    "ON rev.id=r.source_revision_id WHERE rev.connection_id=%s)",
                    (scope.connection_id,),
                )
                cursor.execute(
                    "DELETE FROM evidence_pipeline.public_claims WHERE source_revision_id IN "
                    "(SELECT id FROM evidence.source_revisions WHERE connection_id=%s)",
                    (scope.connection_id,),
                )
            cleanup(scope)


def catalog_fixture(mode):
    from standalone.evidence_pipeline.test_catalog_discovery import payload, row, ID
    from standalone.evidence_pipeline.test_update_catalog import payload as detail
    from standalone.evidence_pipeline.collection.catalog_collection import catalog_scope
    from standalone.evidence_pipeline.parsing.update_catalog import endpoint

    if mode == "empty":
        from standalone.evidence_pipeline.test_catalog_discovery import empty_payload

        return empty_payload().decode(), {}, []

    identities = [str(uuid4()), str(uuid4())]
    index = payload(
        "".join(row(identity, index=i) for i, identity in enumerate(identities)),
        "1 - 2 of 3 (page 1 of 2)"
        if mode == "incomplete"
        else "1 - 2 of 2 (page 1 of 1)",
    )
    return (
        index.decode(),
        {
            identity: detail().replace(ID.encode(), identity.encode())
            for identity in identities
        },
        [catalog_scope("synthetic", endpoint(identity)) for identity in identities],
    )
