"""Committed synthetic import to application SQL reader, with owned-record cleanup."""

import json
from uuid import uuid4

from .commands import register, ingest
from .test_commands import cleanup
from .test_devices import make


def test_device_command_exposes_counts_and_false_cell_through_application_reader():
    snapshot = make(
        "Entra",
        [{"id": str(uuid4()), "deviceId": str(uuid4()), "isManaged": False}],
    )
    from app.services.postgres_query import PostgreSQLQueries

    try:
        register(snapshot.scope)
        ingest(snapshot)
        reader = PostgreSQLQueries()
        selected = (
            "SELECT computer_key FROM evidence_pipeline.current_computer_links "
            "WHERE connection_id='" + snapshot.scope.connection_id + "'::uuid"
        )
        result = json.loads(
            reader.execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT completeness,completeness_total,applicability_unknown_total,definition_id "
                    "FROM evidence_pipeline.current_completeness WHERE computer_key IN ("
                    + selected
                    + ")",
                }
            )
        )
        assert result["rows"] == [[3, 12, 22, "computer-device-v2"]]
        result = json.loads(
            reader.execute(
                {
                    "requestId": str(uuid4()),
                    "sql": "SELECT populated,value FROM evidence_pipeline.current_completeness_cells "
                    "WHERE field_key='entra.managed_flag' AND computer_key IN ("
                    + selected
                    + ")",
                }
            )
        )
        assert result["rows"] == [[True, {"type": "jsonb", "value": "false"}]]
    finally:
        cleanup(snapshot.scope)
