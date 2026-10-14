"""One independently reproduced historical ACL order, not arbitrary normalization."""

from contextlib import closing
import hashlib
import json

import pytest
from psycopg2 import sql
from psycopg2.extras import Json

from backend.database.schema import BASE, verify_predecessor
from backend.tests.predecessor_fixture import restore_predecessor
from standalone.evidence_pipeline.test_bootstrap import empty_database as empty_database


def reconstructed_signature(cursor):
    cursor.execute(
        "SELECT signature FROM evidence_pipeline.installation WHERE singleton"
    )
    signature = cursor.fetchone()[0]
    counts = {}
    for category in ("tables", "relation_authority"):
        changed = 0
        for row in signature[category]:
            value = row[4]
            if not isinstance(value, str) or not value.startswith("{"):
                continue
            entries = value[1:-1].split(",")
            fixture = next(
                (
                    i
                    for i, entry in enumerate(entries)
                    if entry.startswith("tm_mock_fixture=")
                ),
                None,
            )
            reader = next(
                (
                    i
                    for i, entry in enumerate(entries)
                    if entry.startswith("tm_mock_reader=")
                ),
                None,
            )
            if fixture is not None and reader is not None and fixture < reader:
                entries[fixture], entries[reader] = entries[reader], entries[fixture]
                row[4] = "{" + ",".join(entries) + "}"
                changed += 1
        counts[category] = changed
    assert counts == {"tables": 5, "relation_authority": 55}
    return signature


def test_exact_acl_order_variant_is_derived_from_independent_archive(
    empty_database, tmp_path
):
    restore_predecessor(empty_database, tmp_path, profile="synthetic")
    with closing(empty_database.connect()) as conn, conn.cursor() as cursor:
        original = verify_predecessor(cursor)
        assert original == "synthetic"
        signature = reconstructed_signature(cursor)
        digest = hashlib.sha256(
            json.dumps(signature, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        metadata = json.loads((BASE / "predecessor-metadata.json").read_text())
        assert metadata["signature_alternatives_sha256"] == {"synthetic": [digest]}
        cursor.execute(
            "UPDATE evidence_pipeline.installation SET signature=%s WHERE singleton",
            (Json(signature),),
        )
        assert verify_predecessor(cursor) == "synthetic"
        legacy = json.loads((BASE / "legacy-annotations.json").read_text())[
            "annotations"
        ]["synthetic"]
        legacy["sha256"]["manage.py"] = (
            "5fa79fa1c97db2e1bd323630e2e5337f4c391e40522a48e71b5355f34f56585a"
        )
        legacy["sha256"].pop("catalogue_metadata.sql")
        cursor.execute(
            sql.SQL("COMMENT ON DATABASE {} IS %s").format(
                sql.Identifier(empty_database.DB)
            ),
            (json.dumps(legacy, sort_keys=True),),
        )
        assert verify_predecessor(cursor) == "synthetic"
        cursor.execute("GRANT INSERT ON evidence.source_connections TO tm_mock_reader")
        with pytest.raises(ValueError):
            verify_predecessor(cursor)


@pytest.mark.parametrize(
    "damage", ["extra_ordering", "permission", "owner", "definition"]
)
def test_acl_order_variant_does_not_accept_other_metadata_changes(
    empty_database, tmp_path, damage
):
    restore_predecessor(empty_database, tmp_path, profile="synthetic")
    with closing(empty_database.connect()) as conn, conn.cursor() as cursor:
        signature = reconstructed_signature(cursor)
        if damage == "extra_ordering":
            row = next(
                row
                for row in signature["relation_authority"]
                if isinstance(row[4], str) and "," in row[4]
            )
            row[4] = "{" + ",".join(reversed(row[4][1:-1].split(","))) + "}"
        elif damage == "permission":
            row = next(
                row
                for row in signature["relation_authority"]
                if isinstance(row[4], str) and "tm_mock_reader=r/" in row[4]
            )
            row[4] = row[4].replace("tm_mock_reader=r/", "tm_mock_reader=ar/")
        elif damage == "owner":
            signature["relation_authority"][0][-1] = "tm_mock_reader"
        else:
            signature["views"][0][1] += " -- synthetic definition change"
        cursor.execute(
            "UPDATE evidence_pipeline.installation SET signature=%s WHERE singleton",
            (Json(signature),),
        )
        with pytest.raises(ValueError, match="installation signature differs"):
            verify_predecessor(cursor)
