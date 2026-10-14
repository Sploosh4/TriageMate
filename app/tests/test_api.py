"""FastAPI transport boundaries independent of Microsoft or network inputs."""

import json
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from app.api import create_app


class Queries:
    def __init__(self):
        self.calls = []
        self.closed = False

    def execute(self, body, started=None):
        self.calls.append((body, started))
        return json.dumps({"rows": [[1]], "columns": ["value"]}).encode()

    catalogue = execute

    def cancel(self, body):
        return {"cancelled": body["requestId"]}

    def close(self, _timeout):
        self.closed = True
        return True


class Operations:
    def __init__(self, *_args):
        self.mode = "off"
        self.closed = False

    def read(self):
        return {"state": self.mode}

    def save(self, body):
        self.mode = body["mode"]
        return self.read()

    def close(self):
        self.closed = True
        return True

    def notifications(self):
        return []


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGEMATE_STATE_DIR", str(tmp_path))
    queries = Queries()
    app = create_app(lambda: queries, Operations)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.headers["X-Lab-Token"] = client.get("/api/session").json()["token"]
        yield client, queries, app
    assert queries.closed and app.state.operations.closed


def test_query_body_is_replayed_to_typed_route_and_deadline_starts_at_ingress(client):
    http, queries, _app = client
    identifier = str(uuid4())
    result = http.post("/api/query", json={"requestId": identifier, "sql": "SELECT 1"})
    assert result.status_code == 200 and result.json()["rows"] == [[1]]
    assert queries.calls[0][0] == {"requestId": identifier, "sql": "SELECT 1"}
    assert isinstance(queries.calls[0][1], float)


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Lab-Token": "invalid"},
        {"Origin": "https://example.invalid"},
        {"Sec-Fetch-Site": "cross-site"},
        {"Host": "example.invalid"},
    ],
)
def test_request_guards_reject_before_execution(client, headers):
    http, queries, _app = client
    result = http.post(
        "/api/query",
        json={"requestId": str(uuid4()), "sql": "SELECT 1"},
        headers=headers,
    )
    assert result.status_code in (400, 403)
    assert not queries.calls


def test_validation_and_body_limit_do_not_execute(client):
    http, queries, _app = client
    assert (
        http.post(
            "/api/query", json={"requestId": "bad", "sql": "SELECT 1"}
        ).status_code
        == 422
    )
    assert (
        http.post(
            "/api/query",
            json={"requestId": str(uuid4()), "sql": "SELECT 1", "extra": True},
        ).status_code
        == 422
    )
    assert http.post("/api/query", content=b" " * 65537).status_code == 413
    assert not queries.calls


def test_operations_remains_distinct_from_query_execution(client):
    http, queries, _app = client
    assert http.get("/api/operations").json()["state"] == "off"
    assert (
        http.post("/api/operations", json={"mode": "running"}).json()["state"]
        == "running"
    )
    assert not queries.calls


def test_retired_notebook_endpoints_are_unavailable(client):
    http, _queries, _app = client
    for path in ("/api/page", "/api/pages", "/api/search"):
        assert http.get(path).status_code == 404
    assert http.post("/api/save", json={"markdown": "unused"}).status_code == 404


def test_populated_collection_and_operational_notices_remain_structured(client):
    http, queries, app = client
    identifier, attempt = str(uuid4()), str(uuid4())
    row = [
        identifier,
        str(uuid4()),
        attempt,
        attempt,
        "2026-10-14T00:00:00+00:00",
        "unresolved",
        None,
        None,
        "FIRST",
        "epss",
        "synthetic-scope",
        "synthetic",
        "System/TriageMate/Notifiations/collection-" + identifier,
        1,
        attempt,
        "timeout",
        "critical",
        "2026-10-14T00:01:00+00:00",
    ]
    queries.execute = lambda *_args, **_kwargs: json.dumps({"rows": [row]}).encode()
    app.state.operations.notifications = lambda: [
        {
            "id": "overdue-example",
            "parameters": {"api": "FIRST", "organisation": "synthetic-scope"},
            "category": "collection-overdue",
            "status": "unresolved",
            "urgency": "high",
            "message": "Collection is overdue",
        },
    ]
    result = http.get("/api/notifications")
    assert result.status_code == 200
    notices = result.json()["notifications"]
    assert notices[0]["failures"] == [
        {"attemptId": attempt, "code": "timeout", "finishedAt": row[17]}
    ]
    assert (
        notices[1]["input"] == "collection-overdue"
        and notices[1]["message"] == "Collection is overdue"
    )
    assert "markdown" not in json.dumps(notices)
    row[13] = 2
    assert http.get("/api/notifications").status_code == 503


def test_operational_notification_failure_is_reported_without_private_details(client):
    http, queries, app = client
    queries.execute = lambda *_args, **_kwargs: b'{"rows":[]}'

    def fail():
        raise ValueError("synthetic private scope details")

    app.state.operations.notifications = fail
    result = http.get("/api/notifications")
    assert result.status_code == 503
    assert "synthetic private" not in result.text


def test_notification_measurements_remain_exact_for_browser_json(client):
    http, queries, app = client
    queries.execute = lambda *_args, **_kwargs: b'{"rows":[]}'
    app.state.operations.notifications = lambda: [
        {
            "id": "synthetic-storage",
            "parameters": {"api": "storage", "organisation": "synthetic-scope"},
            "category": "storage-condition",
            "status": "unresolved",
            "urgency": "high",
            "message": "Synthetic measurement",
            "details": {
                "known_bytes": 9007199254740993,
                "maximum_bytes": 2**63 - 1,
                "small": 42,
                "partial": False,
                "nested": [-(2**53 + 1)],
            },
        }
    ]
    response = http.get("/api/notifications")
    assert response.status_code == 200
    details = response.json()["notifications"][0]["details"]
    assert details["known_bytes"] == "9007199254740993"
    assert details["maximum_bytes"] == "9223372036854775807"
    assert details["nested"] == ["-9007199254740993"]
    assert details["small"] == 42 and details["partial"] is False
