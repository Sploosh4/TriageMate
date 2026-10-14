"""Synthetic transaction substitutes verify API validation and commit acknowledgements."""

from uuid import uuid4

import psycopg2
import pytest

from app.services.classification_api import ClassificationAPI
from app.services.postgres_query import QueryError


def body():
    return dict(
        decisionId=str(uuid4()),
        deviceId=str(uuid4()),
        selectedType="Workstation",
        reason="Synthetic operator choice",
        expectedPrevious=None,
    )


class Transaction:
    def __init__(self, fail=None):
        self.fail = fail
        self.committed = False
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.fail:
            raise self.fail
        self.committed = True

    def cursor(self):
        transaction = self

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def execute(self, query, params):
                transaction.calls.append((query, params))

            def fetchone(self):
                return (transaction.calls[-1][1][0],)

        return Cursor()


def test_save_is_parameterized_and_acknowledged_after_commit():
    transaction = Transaction()
    api = ClassificationAPI(lambda: transaction)
    value = body()
    value["reason"] = "Synthetic '; DROP TABLE evidence.computers; --"
    assert api.save(value) == {"decisionId": value["decisionId"]}
    assert transaction.committed
    query, params = transaction.calls[0]
    assert value["reason"] not in query and value["reason"] in params


@pytest.mark.parametrize(
    "change",
    [
        {"actor": "someone else"},
        {"selectedType": ""},
        {"reason": " "},
        {"deviceId": "bad"},
        {"expectedPrevious": "bad"},
        {"reason": "x" * 4001},
    ],
)
def test_invalid_fields_do_not_connect(change):
    calls = []
    api = ClassificationAPI(lambda: calls.append(1))
    with pytest.raises(QueryError) as error:
        api.save({**body(), **change})
    assert error.value.status == 400 and calls == []


@pytest.mark.parametrize(
    "failure,status",
    [
        (RuntimeError("unconfirmed commit"), 503),
        (psycopg2.errors.SerializationFailure(), 409),
        (psycopg2.errors.InvalidParameterValue(), 400),
    ],
)
def test_failed_commits_are_not_acknowledged_and_slots_are_released(failure, status):
    api = ClassificationAPI(lambda: Transaction(failure))
    for _ in range(5):
        with pytest.raises(QueryError) as error:
            api.save(body())
        assert error.value.status == status
    api.connector = Transaction
    assert "decisionId" in api.save(body())


def test_http_classification_endpoint_retains_local_request_guards(
    tmp_path, monkeypatch
):
    from fastapi.testclient import TestClient
    from unittest.mock import Mock
    from app.api import create_app

    monkeypatch.setenv("TRIAGEMATE_STATE_DIR", str(tmp_path))
    transaction = Transaction()
    queries = Mock()
    operations = Mock()
    operations.close.return_value = True
    queries.close.return_value = True
    application = create_app(lambda: queries, lambda *_args: operations)
    with TestClient(application) as client:
        application.state.classifications = ClassificationAPI(lambda: transaction)
        token = client.get("/api/session").json()["token"]
        for headers in (
            {},
            {"X-Lab-Token": token, "Origin": "https://example.invalid"},
        ):
            assert (
                client.post(
                    "/api/classifications", json=body(), headers=headers
                ).status_code
                == 403
            )
            assert transaction.calls == []
        value = body()
        assert client.post(
            "/api/classifications", json=value, headers={"X-Lab-Token": token}
        ).json() == {"decisionId": value["decisionId"]}
        assert transaction.committed
