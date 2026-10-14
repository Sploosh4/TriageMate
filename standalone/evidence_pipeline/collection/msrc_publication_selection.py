"""Select changed MSRC index entries under an explicit publication-range policy.

This compares discovery evidence, not child-import completion. A scheduler must
retain unfinished imports separately and advance its accepted checkpoint only
when the selected children have verified committed outcomes.
"""

from datetime import datetime
import sqlite3
import hashlib
import json

from standalone.evidence_pipeline.parsing.msrc_publications import Publication, period
from standalone.evidence_pipeline.temporary_index import temporary_index


def fingerprint(publication):
    if not isinstance(publication, Publication):
        raise ValueError("Expected validated MSRC publication")
    return hashlib.sha256(
        json.dumps(
            publication.source_fields,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def select_changed(
    current,
    previous,
    *,
    starting_month,
    retained_ids,
    unfinished_ids=frozenset(),
    cancelled=lambda: False,
):
    """Choose new/revised summaries; None explicitly means all publication periods.

    `retained_ids` keeps previously selected older scopes eligible. Native IDs
    remain distinct, including supplements and source spelling. `unfinished_ids`
    forces previously selected but uncommitted child imports to remain pending,
    even when their index summaries are unchanged. It does not retry exhausted
    jobs or modify scheduler policy. Input iterators
    must be fully validated before any returned selection can trigger work.
    """

    def check_cancelled():
        if cancelled():
            raise ValueError("MSRC selection cancelled")

    check_cancelled()
    start = None
    if starting_month is not None:
        if not isinstance(starting_month, str) or len(starting_month) != 8:
            raise ValueError("Starting month requires YYYY-Mmm without a supplement")
        start = period(starting_month)
    if not isinstance(retained_ids, (set, frozenset)):
        raise ValueError("Retained publications require an explicit identity set")
    if not isinstance(unfinished_ids, (set, frozenset)):
        raise ValueError("Unfinished publications require an explicit identity set")
    for identity in retained_ids | unfinished_ids:
        check_cancelled()
        period(identity)

    with temporary_index() as index:
        index.execute("CREATE TABLE previous (id TEXT PRIMARY KEY, fingerprint TEXT)")
        index.execute("CREATE TABLE current (id TEXT PRIMARY KEY)")
        index.execute(
            "CREATE TABLE selected (year INTEGER, month INTEGER, id TEXT PRIMARY KEY, payload TEXT)"
        )
        for value in previous:
            check_cancelled()
            if not isinstance(value, Publication):
                raise ValueError("Expected validated MSRC publication")
            period(value.publication_id)
            try:
                index.execute(
                    "INSERT INTO previous VALUES(?,?)",
                    (value.publication_id, fingerprint(value)),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Duplicate MSRC publication identity") from exc
        for value in current:
            check_cancelled()
            if not isinstance(value, Publication):
                raise ValueError("Expected validated MSRC publication")
            identity = value.publication_id
            selected_period = period(identity)
            try:
                index.execute("INSERT INTO current VALUES(?)", (identity,))
            except sqlite3.IntegrityError as exc:
                raise ValueError("Duplicate MSRC publication identity") from exc
            if (
                start is not None
                and selected_period < start
                and identity not in retained_ids
                and identity not in unfinished_ids
            ):
                continue
            old = index.execute(
                "SELECT fingerprint FROM previous WHERE id=?", (identity,)
            ).fetchone()
            if (
                identity not in unfinished_ids
                and old is not None
                and old[0] == fingerprint(value)
            ):
                continue
            saved = json.dumps(
                dict(
                    url=value.url,
                    initial=value.initial_release.isoformat(),
                    current=value.current_release.isoformat(),
                    fields=value.source_fields,
                ),
                ensure_ascii=False,
                allow_nan=False,
            )
            index.execute(
                "INSERT INTO selected VALUES(?,?,?,?)",
                (*selected_period, identity, saved),
            )
        for identity in unfinished_ids:
            check_cancelled()
            if (
                index.execute(
                    "SELECT 1 FROM current WHERE id=?", (identity,)
                ).fetchone()
                is None
            ):
                raise ValueError(
                    "Unfinished MSRC publication is absent from current index"
                )
        check_cancelled()
        # No item leaves this function until both entire indexes have validated.
        for identity, payload in index.execute(
            "SELECT id,payload FROM selected ORDER BY year,month,id"
        ):
            check_cancelled()
            saved = json.loads(payload)
            yield Publication(
                identity,
                saved["url"],
                datetime.fromisoformat(saved["initial"]),
                datetime.fromisoformat(saved["current"]),
                saved["fields"],
            )
