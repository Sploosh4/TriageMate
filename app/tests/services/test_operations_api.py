"""Collection controls use the local request boundary and durable supervisor."""

import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from app.services.operations_api import OperationsAPI
from app.services.postgres_query import QueryError
from standalone.operations.dispatch import Dispatcher
from standalone.operations.service import Service
from standalone.operations.test_dispatch import NOW
from standalone.operations.test_service import Workers
from standalone.operations.test_supervisor import Repository


def factory(*_):
    repository = Repository()
    return Service(
        repository,
        Dispatcher([], now=NOW, grace_seconds=0),
        Workers(repository),
        clock=lambda: NOW,
    )


class OperationsTests(unittest.TestCase):
    def test_modes_keep_restart_available_and_closed_service_rejects_writes(self):
        api = OperationsAPI("unused", factory=factory)
        self.assertEqual(api.read()["state"], "off")
        for mode in ("running", "maintenance", "off", "running"):
            self.assertEqual(api.save({"mode": mode})["state"], mode)
            self.assertTrue(api.read()["available"])
        for body in ({}, {"mode": "delete"}, {"mode": "off", "extra": True}):
            with self.assertRaises(QueryError):
                api.save(body)
        self.assertTrue(api.close())
        with self.assertRaises(QueryError):
            api.save({"mode": "running"})

    def test_unavailable_boot_is_visible_without_exposing_exception(self):
        attempts = []

        def sometimes(*args):
            attempts.append(True)
            if len(attempts) == 1:
                raise ValueError("synthetic private configuration detail")
            return factory(*args)

        api = OperationsAPI("unused", factory=sometimes)
        self.assertFalse(api.read()["available"])
        self.assertNotIn("synthetic private", json.dumps(api.read()))
        self.assertEqual(api.save({"mode": "off"})["state"], "off")
        self.assertTrue(api.close())

    def test_status_retries_unavailable_startup_without_changing_mode(self):
        create = Mock(side_effect=[ValueError("private detail"), factory()])
        with patch(
            "app.services.operations_api.time.monotonic", return_value=10
        ) as clock:
            api = OperationsAPI("unused", factory=create)
            self.assertFalse(api.read()["available"])
            self.assertEqual(create.call_count, 1)
            clock.return_value = 15
            self.assertEqual(api.read()["state"], "off")
            self.assertEqual(create.call_count, 2)
            self.assertTrue(api.close())

    def test_unavailable_status_never_opens_concurrently_or_after_close(self):
        create = Mock(side_effect=ValueError("private detail"))
        with patch(
            "app.services.operations_api.time.monotonic", return_value=10
        ) as clock:
            api = OperationsAPI("unused", factory=create)
            clock.return_value = 15
            with api.lock:
                self.assertFalse(api.read()["available"])
            self.assertEqual(create.call_count, 1)
            self.assertTrue(api.close())
            self.assertFalse(api.read()["available"])
            self.assertEqual(create.call_count, 1)

    def test_http_controls_require_local_host_origin_and_session_token(self):
        import os
        from fastapi.testclient import TestClient
        from app.api import create_app

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.dict(os.environ, {"TRIAGEMATE_STATE_DIR": directory}),
        ):
            api = OperationsAPI(directory, factory=factory)
            queries = Mock()
            queries.close.return_value = True
            application = create_app(lambda: queries, lambda *_args: api)
            with TestClient(application) as client:
                token = client.get("/api/session").json()["token"]
                for headers in (
                    {"X-Lab-Token": "invalid"},
                    {"X-Lab-Token": token, "Origin": "https://example.invalid"},
                    {"X-Lab-Token": token, "Host": "example.invalid"},
                ):
                    assert client.post(
                        "/api/operations", json={"mode": "running"}, headers=headers
                    ).status_code in (400, 403)
                assert client.get("/api/operations").json()["state"] == "off"
                assert (
                    client.post(
                        "/api/operations",
                        json={"mode": "running"},
                        headers={"X-Lab-Token": token},
                    ).json()["state"]
                    == "running"
                )
                assert (
                    client.post(
                        "/api/operations",
                        json={"mode": "off"},
                        headers={"X-Lab-Token": token},
                    ).json()["state"]
                    == "off"
                )
                queries.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
