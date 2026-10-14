"""Strict restart state for the local dispatcher; active runs stay active on load."""

from dataclasses import asdict, fields
from datetime import datetime

from .dispatch import (
    Definition,
    Dispatcher,
    InputState,
    Job,
    Notice,
    OverdueNotice,
    identity,
)
from .lifecycle import Mode
from .scheduling import Daily, Interval, utc


def wire(value):
    if isinstance(value, datetime):
        return utc(value).isoformat()
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [wire(item) for item in value]
    return value


def encode(dispatcher):
    definitions = []
    for item in dispatcher.definitions.values():
        definitions.append(
            dict(
                input_id=item.input_id,
                dependencies=list(item.dependencies),
                schedule=dict(
                    kind="daily" if isinstance(item.schedule, Daily) else "interval",
                    **asdict(item.schedule),
                ),
                **(
                    {"overdue_after_seconds": item.overdue_after_seconds}
                    if item.overdue_after_seconds is not None
                    else {}
                ),
                **(
                    {"worker_contract": item.worker_contract}
                    if item.worker_contract is not None
                    else {}
                ),
            )
        )
    control = dispatcher.control
    return wire(
        dict(
            version=1,
            clock=dispatcher.clock,
            concurrency=dispatcher.concurrency,
            definitions=definitions,
            inputs={
                key: {
                    name: value
                    for name, value in asdict(state).items()
                    if name
                    not in {
                        "monitor_since",
                        "last_success_at",
                        "overdue_episode",
                        "overdue_reference_at",
                        "overdue_threshold_seconds",
                    }
                    or dispatcher.definitions[key].overdue_after_seconds is not None
                }
                for key, state in dispatcher.inputs.items()
            },
            control=dict(
                desired=control.desired.value,
                grace_seconds=control.grace_seconds,
                deadline=control.deadline,
                active=sorted(control.active),
                cancel_requested=sorted(control.cancel_requested),
            ),
            notices=[asdict(item) for item in dispatcher._notices],
        )
    )


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("Unexpected operational checkpoint fields")
    return value


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Invalid operational checkpoint timestamp")
    return utc(datetime.fromisoformat(value))


def integer(value):
    if type(value) is not int or value < 0:
        raise ValueError("Invalid operational checkpoint count")
    return value


def decode(document):
    keys(
        document,
        [
            "version",
            "clock",
            "concurrency",
            "definitions",
            "inputs",
            "control",
            "notices",
        ],
    )
    if type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("Unsupported operational checkpoint version")
    clock = timestamp(document["clock"])
    definitions = document["definitions"]
    if not isinstance(definitions, list) or len(definitions) > 256:
        raise ValueError("Operational checkpoint exceeds schedule bound")
    parsed = []
    for item in definitions:
        keys(
            item,
            ["input_id", "dependencies", "schedule"]
            + (
                ["overdue_after_seconds"]
                if isinstance(item, dict) and "overdue_after_seconds" in item
                else []
            )
            + (
                ["worker_contract"]
                if isinstance(item, dict) and "worker_contract" in item
                else []
            ),
        )
        schedule = item["schedule"]
        if not isinstance(schedule, dict):
            raise ValueError("Invalid operational schedule")
        if schedule.get("kind") == "daily":
            keys(schedule, ["kind", "hour", "minute"])
            cadence = Daily(schedule["hour"], schedule["minute"])
        elif schedule.get("kind") == "interval":
            keys(schedule, ["kind", "seconds", "anchor", "offset_seconds"])
            cadence = Interval(
                schedule["seconds"],
                timestamp(schedule["anchor"]),
                schedule["offset_seconds"],
            )
        else:
            raise ValueError("Unknown operational schedule kind")
        if not isinstance(item["dependencies"], list):
            raise ValueError("Invalid prerequisite list")
        parsed.append(
            Definition(
                item["input_id"],
                cadence,
                tuple(item["dependencies"]),
                item.get("worker_contract"),
                item.get("overdue_after_seconds"),
            )
        )
    control = keys(
        document["control"],
        ["desired", "grace_seconds", "deadline", "active", "cancel_requested"],
    )
    result = Dispatcher(
        parsed,
        now=clock,
        concurrency=document["concurrency"],
        grace_seconds=control["grace_seconds"],
    )
    result.control.desired = Mode(control["desired"])
    result.control.deadline = (
        None if control["deadline"] is None else timestamp(control["deadline"])
    )
    for name in ("active", "cancel_requested"):
        values = control[name]
        if (
            not isinstance(values, list)
            or any(not isinstance(item, str) for item in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("Invalid operational worker identities")
        setattr(result.control, name, {identity(item) for item in values})
    if not result.control.cancel_requested <= result.control.active:
        raise ValueError("Cancellation references an unknown worker")
    if result.control.desired == Mode.RUNNING and result.control.deadline is not None:
        raise ValueError("Running control cannot retain a drain deadline")
    inputs = keys(document["inputs"], result.definitions)
    active = set()
    for key, raw in inputs.items():
        health = {
            "monitor_since",
            "last_success_at",
            "overdue_episode",
            "overdue_reference_at",
            "overdue_threshold_seconds",
        }
        expected = [
            item.name
            for item in fields(InputState)
            if item.name not in health
            or result.definitions[key].overdue_after_seconds is not None
        ]
        keys(raw, expected)
        state = InputState(timestamp(raw["cursor"]))
        for name in ("monitor_since", "last_success_at", "overdue_reference_at"):
            value = raw.get(name)
            setattr(state, name, None if value is None else timestamp(value))
            if getattr(state, name) is not None and getattr(state, name) > clock:
                raise ValueError("Collection monitoring time is in the future")
        state.overdue_episode = (
            None
            if raw.get("overdue_episode") is None
            else identity(raw["overdue_episode"])
        )
        threshold = raw.get("overdue_threshold_seconds")
        state.overdue_threshold_seconds = (
            None if threshold is None else integer(threshold)
        )
        if (state.overdue_episode is None) != (threshold is None) or (
            threshold is not None and threshold < 1
        ):
            raise ValueError("Overdue episode and original threshold disagree")
        if (state.overdue_episode is None) != (state.overdue_reference_at is None):
            raise ValueError("Overdue episode and reference disagree")
        if state.overdue_episode is not None and state.monitor_since is None:
            raise ValueError("Overdue episode lacks a monitoring start")
        if state.cursor > clock:
            raise ValueError("Schedule cursor is in the future")
        state.pending = None if raw["pending"] is None else timestamp(raw["pending"])
        if state.pending is not None and state.pending > state.cursor:
            raise ValueError("Pending occurrence is in the future")
        for name in ("active_skips", "overlap_count", "missed_count"):
            setattr(state, name, integer(raw[name]))
        if type(raw["latest_success"]) is not bool:
            raise ValueError("Invalid prior collection outcome")
        state.latest_success = raw["latest_success"]
        state.latest_snapshot = (
            None if raw["latest_snapshot"] is None else identity(raw["latest_snapshot"])
        )
        if state.latest_success != (state.latest_snapshot is not None):
            raise ValueError("Collection success and snapshot identity disagree")
        state.overlap_run = (
            None if raw["overlap_run"] is None else identity(raw["overlap_run"])
        )
        if (state.overlap_run is None) != (state.overlap_count == 0) or (
            state.overlap_run is not None and state.overlap_count < 2
        ):
            raise ValueError("Invalid overlap episode")
        job = raw["active"]
        if job is not None:
            keys(job, [item.name for item in fields(Job)])
            bindings = job["prerequisite_snapshots"]
            if not isinstance(bindings, list) or any(
                not isinstance(pair, list) or len(pair) != 2 for pair in bindings
            ):
                raise ValueError("Invalid prerequisite snapshot bindings")
            bindings = tuple(
                (identity(parent), identity(snapshot)) for parent, snapshot in bindings
            )
            if (
                tuple(parent for parent, _ in bindings)
                != result.definitions[key].dependencies
            ):
                raise ValueError("Worker prerequisite identities disagree")
            state.active = Job(
                identity(job["run_id"]),
                identity(job["input_id"]),
                timestamp(job["scheduled_at"]),
                timestamp(job["started_at"]),
                bindings,
            )
            if (
                state.active.input_id != key
                or state.active.run_id in active
                or not state.active.scheduled_at <= state.active.started_at <= clock
                or state.pending is not None
            ):
                raise ValueError("Invalid active collection state")
            active.add(state.active.run_id)
        result.inputs[key] = state
    if (result.control.deadline is not None) != (
        result.control.desired != Mode.RUNNING and bool(active)
    ):
        raise ValueError("Drain deadline disagrees with active worker state")
    if active != result.control.active:
        raise ValueError("Active worker inventory disagrees with checkpoint")
    if not isinstance(document["notices"], list):
        raise ValueError("Invalid pending operational notices")
    for item in document["notices"]:
        if isinstance(item, dict) and item.get("kind") in {
            "overdue_opened",
            "overdue_resolved",
        }:
            keys(item, [field.name for field in fields(OverdueNotice)])
            observed, reference = timestamp(item["at"]), timestamp(item["reference_at"])
            if (
                item["input_id"] not in inputs
                or integer(item["threshold_seconds"]) < 1
                or not reference <= observed <= clock
            ):
                raise ValueError("Invalid overdue collection notice")
            if result.definitions[item["input_id"]].overdue_after_seconds is None or (
                item["kind"] == "overdue_opened"
                and (observed - reference).total_seconds() < item["threshold_seconds"]
            ):
                raise ValueError(
                    "Overdue notice does not match an elapsed monitoring policy"
                )
            result._notices.append(
                OverdueNotice(
                    item["kind"],
                    item["input_id"],
                    identity(item["episode_id"]),
                    reference,
                    item["threshold_seconds"],
                    observed,
                )
            )
            continue
        keys(item, [field.name for field in fields(Notice)])
        if (
            item["kind"]
            not in {"overlap_opened", "overlap_updated", "overlap_resolved"}
            or item["input_id"] not in inputs
            or integer(item["skipped_count"]) < 2
        ):
            raise ValueError("Invalid operational notice")
        observed = timestamp(item["at"])
        if observed > clock:
            raise ValueError("Operational notice is in the future")
        result._notices.append(
            Notice(
                item["kind"],
                item["input_id"],
                identity(item["original_run_id"]),
                item["skipped_count"],
                observed,
            )
        )
    return result
