"""Each scheduled repository reports a pre-record failure immediately."""

from datetime import datetime, timedelta, timezone
import json
import time
from uuid import uuid4

import pytest

from standalone.evidence_pipeline.runtime import local_database
from standalone.evidence_pipeline.parsing.catalog_discovery import search_url
from .notifications import load
from .repository_recipe import SOURCE_URLS
from standalone.evidence_pipeline.collection.collection_scope import DEFERRED_SOURCES


@pytest.mark.parametrize("source", sorted(set(SOURCE_URLS) - DEFERRED_SOURCES))
def test_index_failure_reaches_critical_channel_without_native_records(
    tmp_path, source
):
    key, input_id = "synthetic-index-failure-" + str(uuid4()), str(uuid4())
    fixture = tmp_path / "synthetic.json"
    document = dict(origin="synthetic", records={})
    catalog = source == "Microsoft Update Catalog"
    parameters = dict(record_limit=1, pass_limit=1)
    if source == "MSRC":
        parameters.update(starting_month="2099-Jan", retained_ids=[])
    elif catalog:
        parameters["kb"] = "KB9999991"
    if source in {"Red Hat", "MSRC", "Cisco", "Microsoft Update Catalog"}:
        document["index"] = "invalid synthetic index"
    else:
        document["objects"] = []
    fixture.write_text(json.dumps(document))
    fixture.chmod(0o600)
    root = tmp_path / "bundles"
    root.mkdir(mode=0o700)
    config = tmp_path / "operations.json"
    config.write_text(
        json.dumps(
            dict(
                version=1,
                concurrency=1,
                grace_seconds=1,
                inputs=[
                    dict(
                        scope=dict(
                            connection_id=input_id,
                            source=source,
                            input_kind="catalog_search" if catalog else "repository",
                            scope_reference=search_url(parameters["kb"])
                            if catalog
                            else SOURCE_URLS[source],
                            origin="synthetic",
                            provenance="Explicitly synthetic missing repository metadata",
                        ),
                        schedule=dict(
                            kind="interval",
                            seconds=3600,
                            anchor=(
                                datetime.now(timezone.utc) + timedelta(seconds=1)
                            ).isoformat(),
                            offset_seconds=0,
                        ),
                        bundle_root=str(root),
                        synthetic_input=str(fixture),
                        allow_network=False,
                        parameters=parameters,
                        overdue_after_seconds=86400,
                    )
                ],
            )
        )
    )
    # The test deadline is far below the overdue threshold: only immediate
    # failure notification can satisfy it.
    config.chmod(0o600)
    from app.services.operations_api import create_service

    service = None
    try:
        service = create_service(tmp_path, config, key)
        service.request_mode("running")
        deadline = time.monotonic() + 20
        notices = []
        while time.monotonic() < deadline:
            notices = load(key)
            if notices:
                break
            time.sleep(0.05)
        assert len(notices) == 1
        record = notices[0]
        assert record["urgency"] == "critical" and record["synthetic"]
        assert record["status"] == "unresolved"
        assert record["category"] == "collection-failure"
        assert record["details"]["source"] == source
        assert service.status()["inputs"][0]["latest_success"] is False
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM evidence.collection_attempts WHERE connection_id=%s",
                (input_id,),
            )
            assert cursor.fetchone() == (0,)
    finally:
        if service is not None:
            service.close(timeout=5)
        with local_database().connect() as conn, conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_events WHERE service_key=%s",
                (key,),
            )
            cursor.execute(
                "DELETE FROM evidence_pipeline.operation_checkpoints WHERE service_key=%s",
                (key,),
            )
