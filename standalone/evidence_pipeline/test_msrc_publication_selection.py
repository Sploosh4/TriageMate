"""Generated publication changes do not invent an implicit historical scope."""

from dataclasses import replace
import pytest
from standalone.evidence_pipeline.collection.msrc_publication_selection import (
    select_changed,
)
from .test_msrc_publications import parse, entry, CONTEXT


def publication(identity):
    return parse({"@odata.context": CONTEXT, "value": [entry(identity)]})[0]


def select(current, previous=(), start="2099-Mar", retained=frozenset()):
    return tuple(
        select_changed(current, previous, starting_month=start, retained_ids=retained)
    )


def test_new_and_revised_records_include_retained_older_scopes_only():
    old = publication("2099-Jan")
    updated = replace(
        old,
        source_fields={**old.source_fields, "DocumentTitle": "Revised synthetic title"},
    )
    current = [updated, publication("2099-Mar"), publication("2099-Apr")]
    assert [x.publication_id for x in select(current, [old])] == [
        "2099-Mar",
        "2099-Apr",
    ]
    assert [
        x.publication_id for x in select(current, [old], retained={"2099-Jan"})
    ] == ["2099-Jan", "2099-Mar", "2099-Apr"]
    assert select([old], [old], retained={"2099-Jan"}) == ()


def test_explicit_all_history_and_supplements_preserve_native_ids():
    values = [
        publication("2099-May-B"),
        publication("2099-FEB"),
        publication("2099-May"),
    ]
    assert [x.publication_id for x in select(values, start=None)] == [
        "2099-FEB",
        "2099-May",
        "2099-May-B",
    ]
    assert select([], values, start=None) == ()  # no deletion or absent-evidence claim


@pytest.mark.parametrize(
    "start", ["2099", "2099-03", "2099-May-B", "2099-Mar/../Apr", True]
)
def test_invalid_collection_period_is_rejected(start):
    with pytest.raises(ValueError):
        select([], start=start)


def test_late_invalid_index_cannot_return_partial_selection():
    def broken():
        yield publication("2099-Apr")
        raise ValueError("late malformed index")

    with pytest.raises(ValueError, match="late malformed"):
        select(broken())
    with pytest.raises(ValueError, match="Duplicate"):
        select([publication("2099-Apr"), publication("2099-Apr")])
    with pytest.raises(ValueError):
        select([], retained={"invalid"})


@pytest.mark.parametrize("phase", ["before", "previous", "current", "output"])
def test_cancellation_closes_scratch_index(monkeypatch, phase):
    from contextlib import contextmanager
    import sqlite3
    from standalone.evidence_pipeline.collection import (
        msrc_publication_selection as module,
    )
    from .temporary_index import temporary_index

    connections = []
    stopped = phase == "before"

    @contextmanager
    def tracked_index():
        with temporary_index() as connection:
            connections.append(connection)
            yield connection

    def values(stage):
        nonlocal stopped
        if phase == stage:
            stopped = True
        yield publication("2099-Apr")
        yield publication("2099-May")

    monkeypatch.setattr(module, "temporary_index", tracked_index)
    iterator = select_changed(
        values("current"),
        values("previous") if phase == "previous" else (),
        starting_month=None,
        retained_ids=frozenset(),
        cancelled=lambda: stopped,
    )
    if phase == "output":
        assert next(iterator).publication_id == "2099-Apr"
        stopped = True
    with pytest.raises(ValueError, match="selection cancelled"):
        next(iterator)
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


def test_unchanged_unfinished_children_remain_selected_without_losing_scope():
    older = publication("2099-Jan")
    current = publication("2099-Apr")
    values = [older, current]
    assert (
        list(
            select_changed(
                values, values, starting_month="2099-Mar", retained_ids=frozenset()
            )
        )
        == []
    )
    assert list(
        select_changed(
            values,
            values,
            starting_month="2099-Mar",
            retained_ids=frozenset(),
            unfinished_ids={"2099-Jan"},
        )
    ) == [older]
    assert list(
        select_changed(
            values,
            values,
            starting_month="2099-Mar",
            retained_ids=frozenset(),
            unfinished_ids={"2099-Apr"},
        )
    ) == [current]


def test_missing_unfinished_child_cannot_silently_complete_or_yield_partial_work():
    iterator = select_changed(
        [publication("2099-Apr")],
        (),
        starting_month=None,
        retained_ids=frozenset(),
        unfinished_ids={"2099-Jan"},
    )
    with pytest.raises(ValueError, match="absent from current index"):
        next(iterator)


@pytest.mark.parametrize("unfinished", [["2099-Jan"], {"not-a-publication"}])
def test_invalid_unfinished_scope_rejected(unfinished):
    with pytest.raises(ValueError):
        list(
            select_changed(
                [],
                (),
                starting_month=None,
                retained_ids=frozenset(),
                unfinished_ids=unfinished,
            )
        )
