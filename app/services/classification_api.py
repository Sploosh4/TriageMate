"""Constrained local classification decisions, separate from the read-only SQL API."""

import threading
from uuid import uuid4

import psycopg2

from app.services.postgres_query import QueryError

from standalone.evidence_pipeline.contracts import identifier
from standalone.evidence_pipeline.runtime import connect

LIST_SQL = """SELECT provider_device_id::text,source_name,native_device_id,display_name,
operating_system,source_present,source_category,source_device_type,source_subtype,
decision_id::text,selected_type,reason,actor_reference,decided_at::text,decision_revision
FROM evidence_pipeline.current_classifications ORDER BY source_name,native_device_id"""


class ClassificationAPI:
    def __init__(self, connector=connect):
        self.connector = connector
        self.slots = threading.BoundedSemaphore(3)

    def read(self, queries):
        return queries.execute({"requestId": str(uuid4()), "sql": LIST_SQL})

    def save(self, body):
        keys = {"decisionId", "deviceId", "selectedType", "reason", "expectedPrevious"}
        try:
            if not isinstance(body, dict) or set(body) != keys:
                raise ValueError("Unexpected classification fields")
            decision = identifier(body["decisionId"])
            device = identifier(body["deviceId"])
            previous = (
                None
                if body["expectedPrevious"] is None
                else identifier(body["expectedPrevious"])
            )
            for key, bound in (("selectedType", 128), ("reason", 4000)):
                value = body[key]
                if (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value) > bound
                    or "\x00" in value
                ):
                    raise ValueError("Invalid classification text")
        except (ValueError, TypeError, AttributeError):
            raise QueryError(
                "Choose a device and type, and provide a reason. Reload if the decision has changed.",
                400,
                "invalid_classification",
            ) from None
        if not self.slots.acquire(blocking=False):
            raise QueryError(
                "Classification requests are busy. Retry the same decision shortly.",
                429,
                "classification_busy",
            )
        try:
            with self.connector() as conn, conn.cursor() as cursor:
                cursor.execute(
                    "SELECT evidence_pipeline.record_classification(%s,%s,%s,%s,%s)",
                    (decision, device, body["selectedType"], body["reason"], previous),
                )
                saved = str(cursor.fetchone()[0])
            # Exiting the connection context commits before acknowledgement.
            return {"decisionId": saved}
        except psycopg2.errors.SerializationFailure:
            raise QueryError(
                "Classification changed. Reload the device before saving another decision.",
                409,
                "classification_conflict",
            ) from None
        except psycopg2.errors.InvalidParameterValue:
            raise QueryError(
                "Classification target or request changed. Reload and check the device, type and reason.",
                400,
                "invalid_classification",
            ) from None
        except Exception:
            raise QueryError(
                "Classification save was not confirmed. Retry the same decision; do not discard its request ID.",
                503,
                "classification_unconfirmed",
            ) from None
        finally:
            self.slots.release()
