"""Append public evidence transactionally after the explicit authority migration."""

from standalone.evidence_pipeline.parsing.devices import stable_id
from standalone.evidence_pipeline.parsing.public_records import normalize_public
from standalone.evidence_pipeline.parsing.public_snapshot import PublicSnapshot
from standalone.evidence_pipeline.persistence.store import (
    atomic,
    stage_attempt,
    ReplayConflict,
)
from psycopg2 import sql
from psycopg2.extras import execute_values
from collections import defaultdict
from standalone.evidence_pipeline.text_bytes import utf8_size

from contextlib import closing


def _batches(records):
    batch, size, projection_rows = [], 0, 0
    for record in records:
        length = utf8_size(record.claim)
        rows = len(getattr(record, "rows", ()))
        if batch and (
            len(batch) >= 250
            or size + length > 2_000_000
            or projection_rows + rows > 500
        ):
            yield batch
            batch, size, projection_rows = [], 0, 0
        batch.append(record)
        size += length
        projection_rows += rows
    if batch:
        yield batch


def _insert_many(cursor, schema, table, values, conflict=False):
    if not values:
        return
    columns = tuple(values[0])
    if any(tuple(value) != columns for value in values):
        raise ValueError("Inconsistent public projection columns")
    statement = sql.SQL("INSERT INTO {}.{} ({}) VALUES %s{}").format(
        sql.Identifier(schema),
        sql.Identifier(table),
        sql.SQL(",").join(map(sql.Identifier, columns)),
        sql.SQL(" ON CONFLICT DO NOTHING" if conflict else ""),
    )
    if len(values) == 1:
        # execute_values builds and joins an additional complete SQL buffer.
        # A single large source record needs no batching buffer. Parameterized
        # execution preserves escaping, authority and all database constraints.
        statement = sql.SQL("INSERT INTO {}.{} ({}) VALUES ({}){}").format(
            sql.Identifier(schema),
            sql.Identifier(table),
            sql.SQL(",").join(map(sql.Identifier, columns)),
            sql.SQL(",").join(sql.Placeholder() for _ in columns),
            sql.SQL(" ON CONFLICT DO NOTHING" if conflict else ""),
        )
        parameters = dict(values[0])
        if (
            (schema, table) == ("evidence_pipeline", "public_claims")
            and isinstance(parameters.get("claim"), str)
            and len(parameters["claim"]) > 1_000_000
        ):
            # An encoding strategy threshold, never an input/output size cap.
            from standalone.evidence_pipeline.persistence.large_text_parameter import (
                LargeTextParameter,
            )

            parameters["claim"] = LargeTextParameter(parameters["claim"])
        cursor.execute(statement, tuple(parameters[c] for c in columns))
        return
    execute_values(
        cursor,
        statement,
        [tuple(value[c] for c in columns) for value in values],
        page_size=100,
    )


def _reuse_reference(cursor, values):
    """Copy receipt-local fields only from the exact already-compared revision.

    Normal insertion constraints still compare the complete copied projection to
    its immutable claim. Missing prior evidence is an error, never a partial row
    or a substitution from another revision or connection.
    """
    cursor.execute(
        "INSERT INTO evidence.public_reference_observations "
        "(id,receipt_id,native_id,reference_kind,cve_ids,source_fields) "
        "SELECT %s,%s,previous.native_id,previous.reference_kind,previous.cve_ids,previous.source_fields "
        "FROM evidence.observation_receipts current_receipt "
        "JOIN evidence.observation_receipts prior_receipt "
        "ON prior_receipt.source_revision_id=current_receipt.source_revision_id "
        "AND prior_receipt.id<>current_receipt.id "
        "JOIN evidence.public_reference_observations previous ON previous.receipt_id=prior_receipt.id "
        "WHERE current_receipt.id=%s AND previous.native_id=%s "
        "AND previous.reference_kind=%s AND previous.cve_ids=%s "
        "ORDER BY prior_receipt.id LIMIT 1",
        (
            values["id"],
            values["receipt_id"],
            values["receipt_id"],
            values["native_id"],
            values["reference_kind"],
            values["cve_ids"],
        ),
    )
    if cursor.rowcount != 1:
        raise ReplayConflict(
            "Existing public reference revision has no matching projection"
        )


def persist_public(connection, snapshot: PublicSnapshot):
    if not isinstance(snapshot, PublicSnapshot) or connection.autocommit:
        raise ValueError(
            "Public persistence requires a public snapshot and transaction"
        )
    snapshot.verify_payload()
    feed = snapshot.feed() if snapshot.complete else None
    with (
        connection.cursor() as cursor,
        atomic(cursor),
        closing(normalize_public(feed)) as normalized,
        closing(_batches(normalized)) as batches,
    ):
        cursor.execute("SELECT pg_advisory_xact_lock(731904217)")
        replay = stage_attempt(cursor, snapshot)
        result = dict(
            execution_id=snapshot.execution_id,
            outcome="success" if snapshot.complete else "failure",
            replayed=replay,
        )
        if replay:
            return result
        from standalone.evidence_pipeline.persistence.osv_query_store import (
            stage_context,
            link_advisories,
        )

        stage_context(cursor, snapshot)
        if feed is None:
            return result
        for batch in batches:
            records = [
                (
                    stable_id(
                        "public-revision",
                        snapshot.scope.connection_id,
                        record.source_record_id,
                        record.content_hash,
                    ),
                    record,
                )
                for record in batch
            ]
            existing = dict(
                execute_values(
                    cursor,
                    "SELECT p.source_revision_id::text,p.claim FROM evidence_pipeline.public_claims p JOIN (VALUES %s) requested(id) ON p.source_revision_id=requested.id",
                    [(revision,) for revision, _ in records],
                    template="(%s::uuid)",
                    page_size=250,
                    fetch=True,
                )
            )
            revisions, claims, receipts, cves = [], [], [], []
            projections = defaultdict(list)
            reused_references = []
            cvrf_map, cvrf_batches = [], []
            for revision, record in records:
                if revision in existing:
                    # Release the retained comparison copy before projecting a
                    # large source record. Equality still checks the complete
                    # claim, not only its hash; collision rejection is unchanged.
                    if existing[revision] != record.claim:
                        raise ReplayConflict("Public source claim revision collision")
                    existing[revision] = record.claim
                else:
                    revisions.append(
                        dict(
                            id=revision,
                            connection_id=snapshot.scope.connection_id,
                            source_record_id=record.source_record_id,
                            collected_at=snapshot.finished_at,
                            content_hash=record.content_hash,
                            origin=snapshot.scope.origin,
                            source_url=snapshot.scope.scope_reference,
                            licence_or_provenance=snapshot.scope.provenance,
                        )
                    )
                    claims.append(dict(source_revision_id=revision, claim=record.claim))
                receipt = stable_id("public-receipt", revision, snapshot.execution_id)
                receipts.append(
                    dict(
                        id=receipt,
                        source_revision_id=revision,
                        collection_attempt_id=snapshot.execution_id,
                    )
                )
                cves.extend(dict(cve_id=cve) for cve in record.cve_ids)
                for row_index, (table, values) in enumerate(
                    record.evidence_rows(receipt)
                ):
                    if snapshot.scope.input_kind == "security_updates":
                        cvrf_map.append(
                            dict(
                                receipt_id=receipt,
                                row_index=row_index,
                                entity_id=values["id"],
                                table_name=table,
                            )
                        )
                    # An unchanged reference already has an exact stored claim.
                    # Reuse its constrained projection without another large SQL
                    # parameter; first imports and other tables keep their path.
                    if (
                        revision in existing
                        and table == "public_reference_observations"
                    ):
                        reused_references.append(values)
                    else:
                        # CVSS versions may project different column sets.
                        projections[(table, tuple(values))].append(values)
                if snapshot.scope.input_kind == "security_updates":
                    cvrf_batches.append(
                        dict(receipt_id=receipt, row_count=len(record.rows))
                    )
            _insert_many(cursor, "evidence", "source_revisions", revisions)
            _insert_many(cursor, "evidence_pipeline", "public_claims", claims)
            _insert_many(cursor, "evidence", "observation_receipts", receipts)
            _insert_many(cursor, "evidence_pipeline", "cvrf_batches", cvrf_batches)
            _insert_many(cursor, "evidence_pipeline", "cvrf_projection", cvrf_map)
            _insert_many(cursor, "evidence", "vulnerabilities", cves, conflict=True)
            for values in reused_references:
                _reuse_reference(cursor, values)
            for (table, _), values in projections.items():
                _insert_many(cursor, "evidence", table, values)
            # Each batch contains complete receipt-local projections. Drain its
            # deferred checks now instead of accumulating an entire monthly
            # feed's checks into one timeout-limited statement at the end.
            # This is still one transaction: any later failure rolls back every
            # batch, and no partial snapshot becomes visible to readers.
            if (snapshot.scope.source, snapshot.scope.input_kind) in {
                ("MSRC", "security_updates"),
                ("FIRST", "epss"),
            }:
                cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
                cursor.execute("SET CONSTRAINTS ALL DEFERRED")
        link_advisories(cursor, snapshot)
        return result
